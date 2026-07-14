import { expect } from 'chai';
import base64url from 'base64url';

import bootstrap from '../test_helper.js';
import { buildTokenResponse } from '../../lib/helpers/grant_common.js';
import ResourceServer from '../../lib/helpers/resource_server.js';

/**
 * LOGTO PATCH(scope-always-present): token, introspection, and JWT access token payloads carry
 * the `scope` property whenever the token has one, including the empty string upstream would
 * omit. These tests fail loudly if the patch is lost.
 */

function decodePayload(jwt) {
  return JSON.parse(base64url.decode(jwt.split('.')[1]));
}

describe('scope always present', () => {
  before(bootstrap(import.meta.url));
  before(function () { return this.login({ accountId: 'accountId' }); });

  describe('token endpoint response', () => {
    it('keeps the access token scope even when the source token has none', () => {
      const at = { expiration: 3600, tokenType: 'Bearer', scope: '' };
      const response = buildTokenResponse(at, 'token-value', { source: {} });

      expect(response).to.have.property('scope', '');
    });
  });

  describe('introspection response', () => {
    it('includes an empty scope', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: '',
      });

      const token = await at.save();
      return this.agent.post('/token/introspection')
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('scope', '');
        });
    });
  });

  describe('jwt access token payload', () => {
    it('includes an empty scope claim', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: '',
        resourceServer: new ResourceServer('urn:example:rs', {
          accessTokenFormat: 'jwt',
          audience: 'urn:example:rs',
        }),
      });

      const token = await at.save();

      expect(decodePayload(token)).to.have.property('scope', '');
    });
  });
});
