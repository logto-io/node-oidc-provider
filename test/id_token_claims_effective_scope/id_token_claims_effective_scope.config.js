import getConfig from '../default.config.js';
import { Account } from '../models.js';

const config = getConfig();

config.rotateRefreshToken = false;

/**
 * LOGTO PATCH(id-token-claims-effective-scope): records every call the account claims
 * callback receives so the tests can assert on the query-level behavior, not just the final
 * ID token payload. The config and test files share this array as an ESM module singleton.
 */
export const claimsCalls = [];

config.findAccount = async (ctx, sub, token) => {
  const account = await Account.findAccount(ctx, sub, token);

  if (!account) {
    return account;
  }

  return {
    accountId: account.accountId,
    claims(use, scope, claims, rejected) {
      claimsCalls.push({ use, scope });
      return account.claims(use, scope, claims, rejected);
    },
  };
};

export default {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
