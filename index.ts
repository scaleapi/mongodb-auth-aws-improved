/**
 * the MONGODB-AWS provider doesn't provide for any way to dynamically input AWS temporary credentials
 * the only types of temporary credentials it can refresh are EC2 and ECS credentials, neither of are useful to us.
 * This issue only pops up when attempting to grow the connection pool after the initial credentials have expired.
 *
 * To get around this, patch the mongodb-aws auth provider internals to use a AWS.Credentials instance of our choice
 * so that when it attempts to create new connections, it can get the proper credentials.
 */
import type { Credentials as CredentialsV2 } from 'aws-sdk';
import type { CredentialProvider as CredentialProviderV3 } from '@aws-sdk/types';
import { MongoError } from 'mongodb';
import crypto from 'crypto';

let MongoDBAWS: any,
  maxWireVersion: any,
  ns = (x: any) => x,
  BSON: any,
  mongoClientVersion = 3;

try {
  ({ MongoDBAWS } = require('mongodb/lib/cmap/auth/mongodb_aws'));
  ({ maxWireVersion, ns } = require('mongodb/lib/utils'));
  BSON = require('mongodb/lib/bson');
  mongoClientVersion = 4;
} catch (e) {
  // mongodb client is version 3
  MongoDBAWS = require('mongodb/lib/core/auth/mongodb_aws');
  ({ maxWireVersion } = require('mongodb/lib/core/utils'));
}

import aws4 from 'aws4';

const ASCII_N = 110;

const bsonOptions =
  mongoClientVersion === 4
    ? {
        promoteLongs: true,
        promoteValues: true,
        promoteBuffers: false,
        bsonRegExp: false,
      }
    : undefined;

function commandArgs(_ns: string, saslStart: any) {
  return [ns(_ns), saslStart].concat(mongoClientVersion === 4 ? [undefined] : []);
}

interface IAwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

let originalAuth: Function | undefined = undefined;
const fakeCredentialMap = new Map<string, () => Promise<IAwsCredentials>>();

/**
 * Returns a set of meaningless random credentials.
 * Patches the mongo library so that, when it encounters these credentials, it uses the associated AWS.Credentials object for authentication.
 */
export function getMongoAwsAuth(awsCredentialsOrProvider: CredentialsV2 | CredentialProviderV3) {
  patchMongoAws();
  const fakeUsername = crypto.randomBytes(8).toString('base64');
  fakeCredentialMap.set(fakeUsername, () => getCredentials(awsCredentialsOrProvider));
  // 3.x expects auth.user, 4.x expects auth.username
  return { user: fakeUsername, username: fakeUsername, password: fakeUsername };
}

function isCredentials(awsCredentialsOrProvider: CredentialsV2 | CredentialProviderV3): awsCredentialsOrProvider is CredentialsV2 {
  return !!(awsCredentialsOrProvider as CredentialsV2).getPromise;
}

async function getCredentials(awsCredentialsOrProvider: CredentialsV2 | CredentialProviderV3): Promise<IAwsCredentials> {
  if (isCredentials(awsCredentialsOrProvider)) {
    await awsCredentialsOrProvider.getPromise();
    return awsCredentialsOrProvider;
  } else {
    return awsCredentialsOrProvider();
  }
}

function patchMongoAws() {
  if (!originalAuth) {
    originalAuth = MongoDBAWS.prototype.auth;

    /**
     * This section of code is heavily inspired by code from node-mongodb-native, developed by MongoDB, Inc:
     * 
     * https://github.com/mongodb/node-mongodb-native/blob/v3.7.3/lib/core/auth/mongodb_aws.js
     */
    MongoDBAWS.prototype.auth = async function auth(authContext: any, callback: Function) {
      const connection = authContext.connection;
      const credentials = authContext.credentials;

      const awsCredentialsOrProvider = fakeCredentialMap.get(credentials.password);
      if (!awsCredentialsOrProvider) {
        return originalAuth!.call(this, authContext, callback);
      }

      if (maxWireVersion(connection) < 9) {
        callback(new MongoError('MONGODB-AWS authentication requires MongoDB version 4.4 or later'));
        return;
      }

      let awsCredentials: IAwsCredentials;
      try {
        awsCredentials = await getCredentials(awsCredentialsOrProvider);
      } catch (e) {
        return callback(e);
      }

      const db = credentials.source;
      const bson = BSON || this.bson;

      crypto.randomBytes(32, (err, nonce) => {
        if (err) {
          callback(err);
          return;
        }

        const saslStart = {
          saslStart: 1,
          mechanism: 'MONGODB-AWS',
          payload: bson.serialize({ r: nonce, p: ASCII_N }, bsonOptions),
        };

        // eslint-disable-next-line @typescript-eslint/no-shadow
        connection.command(...commandArgs(`${db}.$cmd`, saslStart), (err: any, result: any) => {
          if (err) return callback(err);

          const res = mongoClientVersion === 4 ? result : result.result;
          const serverResponse = bson.deserialize(res.payload.buffer, bsonOptions);
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
            awsCredentials,
          );

          const authorization = options.headers?.Authorization;
          const date = options.headers?.['X-Amz-Date'];
          const payload: any = { a: authorization, d: date };
          if (awsCredentials.sessionToken) {
            payload.t = awsCredentials.sessionToken;
          }

          const saslContinue = {
            saslContinue: 1,
            conversationId: 1,
            payload: bson.serialize(payload),
          };

          // eslint-disable-next-line @typescript-eslint/no-shadow
          connection.command(...commandArgs(`${db}.$cmd`, saslContinue), (err: Error | null) => {
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
