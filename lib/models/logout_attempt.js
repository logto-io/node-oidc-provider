import { hash, randomBytes } from 'node:crypto';

import instance from '../helpers/weak_cache.js';
import epochTime from '../helpers/epoch_time.js';

const ttl = 5 * 60;

export default (provider) => class LogoutAttempt extends instance(provider).BaseModel {
  static get IN_PAYLOAD() {
    return [...super.IN_PAYLOAD, 'sessionId', 'clientId', 'state', 'postLogoutRedirectUri'];
  }

  static async issue(sessionId, details) {
    const secret = randomBytes(24).toString('hex');
    await new this({ ...details, sessionId, jti: hash('sha256', secret) }).save(ttl);
    return secret;
  }

  static async lookup(sessionId, secret) {
    if (typeof secret !== 'string' || secret.length !== 48 || !/^[0-9a-f]+$/.test(secret)) {
      return undefined;
    }

    const attempt = await this.find(hash('sha256', secret));
    if (attempt?.sessionId === sessionId && attempt.exp > epochTime()) {
      return attempt;
    }
    return undefined;
  }
};
