import * as url from 'node:url';

import sinon from 'sinon';
import { expect } from 'chai';
import {
  SignJWT, exportJWK, calculateJwkThumbprint, generateKeyPair,
} from 'jose';

import nanoid from '../../lib/helpers/nanoid.js';
import bootstrap, { skipConsent } from '../test_helper.js';

/**
 * Replay detection of DPoP proofs at the token endpoint. The main dpop suite covers proof
 * binding at the token endpoint and replay detection at the userinfo endpoint; these tests pin
 * the token-endpoint replay behavior for the client_credentials and refresh_token grants —
 * centralized in `helpers/validate_dpop.js` since v9.11.2 (`1d764c83`) — along with the
 * `features.dPoP.allowReplay` escape hatch.
 */

async function DPoP(keypair, htu, htm) {
  return new SignJWT({ htu, htm })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: await exportJWK(keypair.publicKey) })
    .setJti(nanoid())
    .setIssuedAt()
    .sign(keypair.privateKey);
}

describe('token endpoint DPoP proof replay detection', () => {
  before(bootstrap(import.meta.url));
  before(function () { return this.login({ scope: 'openid offline_access' }); });
  skipConsent();
  before(async function () {
    this.keypair = await generateKeyPair('ES256', { extractable: true });
    this.thumbprint = await calculateJwkThumbprint(await exportJWK(this.keypair.publicKey));
  });

  describe('client_credentials', () => {
    it('rejects a proof that was already used', async function () {
      const proof = await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST');

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', proof)
        .type('form')
        .expect(200);

      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', proof)
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'DPoP proof JWT Replay detected');
    });

    describe('with features.dPoP.allowReplay enabled', () => {
      before(function () {
        this.orig = i(this.provider).features.dPoP.allowReplay;
        i(this.provider).features.dPoP.allowReplay = true;
      });

      after(function () {
        i(this.provider).features.dPoP.allowReplay = this.orig;
      });

      it('accepts a proof that was already used and still binds the token', async function () {
        const proof = await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST');

        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({ grant_type: 'client_credentials' })
          .set('DPoP', proof)
          .type('form')
          .expect(200);

        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({ grant_type: 'client_credentials' })
          .set('DPoP', proof)
          .type('form')
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { ClientCredentials } } } = spy.args[0][0];
        expect(ClientCredentials).to.have.property('jkt', this.thumbprint);
      });
    });
  });

  describe('refresh_token', () => {
    beforeEach(async function () {
      // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
      const auth = this.auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { code } } = url.parse(location, true);
          this.code = code;
        });

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'authorization_code',
          code_verifier: this.auth.code_verifier,
          code: this.code,
          redirect_uri: 'https://client.example.com/cb',
        })
        .type('form')
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
        .expect(200)
        .expect(({ body }) => {
          this.rt = body.refresh_token;
        });
    });

    it('rejects a proof that was already used', async function () {
      const proof = await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST');

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'refresh_token',
          refresh_token: this.rt,
        })
        .set('DPoP', proof)
        .type('form')
        .expect(200);

      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'refresh_token',
          refresh_token: this.rt,
        })
        .set('DPoP', proof)
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'DPoP proof JWT Replay detected');
    });
  });
});
