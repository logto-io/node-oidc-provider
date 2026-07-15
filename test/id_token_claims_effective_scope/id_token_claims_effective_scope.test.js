import { parse as parseUrl } from 'node:url';

import { expect } from 'chai';

import bootstrap, { skipConsent } from '../test_helper.js';

import { claimsCalls } from './id_token_claims_effective_scope.config.js';

const route = '/token';
const fullScope = 'openid email offline_access';

/**
 * LOGTO PATCH(id-token-claims-effective-scope): the account claims callback must receive the
 * effective scope of the current token request — the `scope` parameter when the client
 * down-scopes on refresh, the token's own scope otherwise. These tests fail loudly if the
 * patch is lost: upstream passes the refresh token's full stored scope regardless of the
 * request.
 */
describe('id token claims effective scope', () => {
  before(bootstrap(import.meta.url));

  beforeEach(function () { return this.login({ scope: fullScope }); });
  afterEach(function () { return this.logout(); });
  skipConsent();

  beforeEach(function (done) {
    this.agent.get('/auth')
      .query({
        client_id: 'client',
        scope: fullScope,
        prompt: 'consent',
        response_type: 'code',
        redirect_uri: 'https://client.example.com/cb',
        nonce: 'foobarnonce',
      })
      .expect(303)
      .end((err, authResponse) => {
        if (err) {
          return done(err);
        }

        const { query: { code } } = parseUrl(authResponse.headers.location, true);

        return this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            code,
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb',
          })
          .expect(200)
          .expect((response) => {
            expect(response.body).to.have.property('refresh_token');
            this.rt = response.body.refresh_token;
          })
          .end(done);
      });
  });

  it('queries account claims with the full code scope on the initial issuance', () => {
    expect(claimsCalls.at(-1)).to.deep.equal({ use: 'id_token', scope: fullScope });
  });

  it('queries account claims with the down-scoped request scope on refresh', function () {
    const seen = claimsCalls.length;

    return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        refresh_token: this.rt,
        grant_type: 'refresh_token',
        scope: 'openid',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(claimsCalls.slice(seen)).to.deep.equal([{ use: 'id_token', scope: 'openid' }]);
      });
  });

  it('queries account claims with the full token scope when the request does not down-scope', function () {
    const seen = claimsCalls.length;

    return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        refresh_token: this.rt,
        grant_type: 'refresh_token',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(claimsCalls.slice(seen)).to.deep.equal([{ use: 'id_token', scope: fullScope }]);
      });
  });
});
