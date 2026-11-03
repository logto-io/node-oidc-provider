import { parse as parseUrl } from 'node:url';

import { expect } from 'chai';

import bootstrap, { skipConsent } from '../test_helper.js';

const route = '/token';
const grantedScope = 'openid offline_access';

/**
 * LOGTO PATCH(scope-space-normalization): request `scope` values padded with extra spaces
 * (OpenAI Codex refreshes with `scope=" offline_access"`) are normalized in `Params`. Without
 * the patch the empty token produced by the extra space is treated as a requested scope the
 * refresh token does not carry, and every such refresh fails with `invalid_scope`.
 */
describe('scope space normalization', () => {
  before(bootstrap(import.meta.url));

  beforeEach(function () { return this.login({ scope: grantedScope }); });
  afterEach(function () { return this.logout(); });
  skipConsent();

  beforeEach(function (done) {
    this.agent.get('/auth')
      .query({
        client_id: 'client',
        scope: grantedScope,
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

  function refresh(scope) {
    return this.agent.post(route)
      .auth('client', 'secret')
      .type('form')
      .send({ refresh_token: this.rt, grant_type: 'refresh_token', scope });
  }

  it('accepts a refresh scope with a leading space', function () {
    return refresh.call(this, ' offline_access')
      .expect(200)
      .expect(({ body }) => {
        expect(body).to.have.property('access_token');
        expect(body).to.have.property('scope', 'offline_access');
      });
  });

  it('accepts a refresh scope with a double space', function () {
    return refresh.call(this, 'openid  offline_access')
      .expect(200)
      .expect(({ body }) => {
        expect(body).to.have.property('id_token');
        expect(body).to.have.property('scope', grantedScope);
      });
  });

  it('treats a whitespace-only refresh scope as absent and falls back to the refresh token scope', function () {
    return refresh.call(this, '   ')
      .expect(200)
      .expect(({ body }) => {
        expect(body).to.have.property('id_token');
        expect(body).to.have.property('scope', grantedScope);
      });
  });

  it('still rejects a padded scope the refresh token was not granted', function () {
    return refresh.call(this, ' email')
      .expect(400)
      .expect(({ body }) => {
        expect(body).to.have.property('error', 'invalid_scope');
        expect(body).to.have.property('scope', 'email');
      });
  });

  it('does not normalize tab separators', function () {
    return refresh.call(this, 'openid\toffline_access')
      .expect(400)
      .expect(({ body }) => {
        expect(body).to.have.property('error', 'invalid_scope');
        expect(body).to.have.property('scope', 'openid\toffline_access');
      });
  });
});
