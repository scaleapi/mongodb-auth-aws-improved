/**
 * the MONGODB-AWS provider doesn't provide for any way to dynamically input AWS temporary credentials
 * the only types of temporary credentials it can refresh are EC2 and ECS credentials, neither of are useful to us.
 * This issue only pops up when attempting to grow the connection pool after the initial credentials have expired.
 *
 * To get around this, patch the mongodb-aws auth provider internals to use a AWS.Credentials instance of our choice
 * so that when it attempts to create new connections, it can get the proper credentials.
 */
import { Credentials } from 'aws-sdk';
import { MongoError, MongoClient } from 'mongodb';
import crypto from 'crypto';
// @ts-ignore
import { maxWireVersion } from 'mongodb/lib/core/utils';
// @ts-ignore
import MongoDBAWS from 'mongodb/lib/core/auth/mongodb_aws';
import aws4 from 'aws4';

const ASCII_N = 110;

let originalAuth: Function | undefined = undefined;
const connectionToCredentialsMap = new WeakMap();

export default function patchMongoAws(client: MongoClient, awsCredentials: Credentials) {
  if (!originalAuth) {
    originalAuth = MongoDBAWS.prototype.auth;
    // this is largely duplicated from mongodb/lib/core/auth/mongodb_aws, except the credentials used
    // is the Credentials object we provide
    MongoDBAWS.prototype.auth = async function auth(authContext: any, callback: Function) {
      const connection = authContext.connection;
      const credentials = authContext.credentials;

      if (maxWireVersion(connection) < 9) {
        callback(new MongoError('MONGODB-AWS authentication requires MongoDB version 4.4 or later'));
        return;
      }

      try {
        await awsCredentials.getPromise();
      } catch (e) {
        return callback(e);
      }

      const username = awsCredentials.accessKeyId;
      const password = awsCredentials.secretAccessKey;
      const db = credentials.source;
      const token = awsCredentials.sessionToken;
      const bson = this.bson;

      crypto.randomBytes(32, (err, nonce) => {
        if (err) {
          callback(err);
          return;
        }

        const saslStart = {
          saslStart: 1,
          mechanism: 'MONGODB-AWS',
          payload: bson.serialize({ r: nonce, p: ASCII_N }),
        };

        connection.command(`${db}.$cmd`, saslStart, (err: Error | null, result: any) => {
          if (err) return callback(err);

          const res = result.result;
          const serverResponse = bson.deserialize(res.payload.buffer);
          const host = serverResponse.h;
          const serverNonce = serverResponse.s.buffer;
          if (serverNonce.length !== 64) {
            callback(
              new MongoError(`Invalid server nonce length ${serverNonce.length}, expected 64`),
            );
            return;
          }

          if (serverNonce.compare(nonce, 0, nonce.length, 0, nonce.length) !== 0) {
            callback(new MongoError('Server nonce does not begin with client nonce'));
            return;
          }

          if (host.length < 1 || host.length > 255 || host.indexOf('..') !== -1) {
            callback(new MongoError(`Server returned an invalid host: "${host}"`));
            return;
          }

          const body = 'Action=GetCallerIdentity&Version=2011-06-15';
          const options = aws4.sign(
            {
              method: 'POST',
              host,
              region: deriveRegion(serverResponse.h),
              service: 'sts',
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': body.length,
                'X-MongoDB-Server-Nonce': serverNonce.toString('base64'),
                'X-MongoDB-GS2-CB-Flag': 'n',
              },
              path: '/',
              body,
            },
            {
              accessKeyId: username,
              secretAccessKey: password,
              token,
            },
          );

          const authorization = options.headers.Authorization;
          const date = options.headers['X-Amz-Date'];
          const payload: any = { a: authorization, d: date };
          if (token) {
            payload.t = token;
          }

          const saslContinue = {
            saslContinue: 1,
            conversationId: 1,
            payload: bson.serialize(payload),
          };

          connection.command(`${db}.$cmd`, saslContinue, (err: Error | null) => {
            if (err) return callback(err);
            callback();
          });
        });
      });
    };
  }
}

function deriveRegion(host: string) {
  const parts = host.split('.');
  if (parts.length === 1 || parts[1] === 'amazonaws') {
    return 'us-east-1';
  }

  return parts[1];
}
