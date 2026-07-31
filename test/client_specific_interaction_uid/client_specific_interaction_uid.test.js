import { strict as assert } from 'node:assert';

import { expect } from 'chai';
import { createSandbox } from 'sinon';

import bootstrap from '../test_helper.js';
import { getInteractionUid, setInteractionUid } from '../../lib/helpers/interaction_cookie_handler.js';

const sinon = createSandbox();

/**
 * LOGTO PATCH(client-specific-interaction-uid): the interaction cookie holds a JSON mapping of
 * client IDs to interaction UIDs instead of a single UID, so concurrent sign-ins from different
 * clients can each resolve their own interaction. These tests fail loudly if the patch is lost.
 */

function getInteractionCookieValue(response) {
  const header = response.headers['set-cookie'].find((value) => value.startsWith('_interaction='));
  expect(header).to.exist;
  return header.split(';')[0].slice('_interaction='.length);
}

function decodeMapping(value) {
  return JSON.parse(decodeURIComponent(value));
}

function getInteractionCookieMapping(response) {
  return decodeMapping(getInteractionCookieValue(response));
}

describe('client-specific interaction UIDs', () => {
  before(bootstrap(import.meta.url));
  afterEach(sinon.restore);

  beforeEach(function () { return this.logout(); });

  it('stores the interaction UID keyed by client ID in the interaction cookie', async function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
    });

    const response = await this.agent.get('/auth').query(auth).expect(303);
    const uid = response.headers.location.split('/interaction/')[1];

    const mapping = getInteractionCookieMapping(response);
    expect(mapping).to.deep.equal({ client: uid, _legacy: uid });
  });

  it('merges concurrent interactions from different clients into one cookie mapping', async function () {
    const first = await this.agent.get('/auth')
      .query(new this.AuthorizationRequest({ response_type: 'code', scope: 'openid' }))
      .expect(303);
    const uid1 = first.headers.location.split('/interaction/')[1];

    /**
     * The response scopes the cookie to its own interaction path; re-save it at the root path
     * so the next authorization request sends it, the way a mounted deployment configures it.
     */
    this.agent._saveCookies.bind(this.agent)({
      request: { url: this.provider.issuer },
      headers: { 'set-cookie': [`_interaction=${getInteractionCookieValue(first)}; path=/; httponly`] },
    });

    const second = await this.agent.get('/auth')
      .query(new this.AuthorizationRequest({ client_id: 'client-2', response_type: 'code', scope: 'openid' }))
      .expect(303);
    const uid2 = second.headers.location.split('/interaction/')[1];

    const mapping = getInteractionCookieMapping(second);
    expect(mapping).to.deep.equal({ client: uid1, 'client-2': uid2, _legacy: uid2 });
  });

  it('bounds an oversized existing cookie mapping on the next write', async function () {
    const staleClientIds = Array.from({ length: 12 }, (_, i) => `https://client-${i}.example.com/.well-known/${'x'.repeat(160)}.json`);
    const staleMapping = Object.fromEntries(staleClientIds.map((clientId, i) => [clientId, `stale-uid-${i}`]));
    const staleValue = encodeURIComponent(JSON.stringify({ ...staleMapping, _legacy: 'stale-uid-11' }));

    this.agent._saveCookies.bind(this.agent)({
      request: { url: this.provider.issuer },
      headers: { 'set-cookie': [`_interaction=${staleValue}; path=/; httponly`] },
    });

    const response = await this.agent.get('/auth')
      .query(new this.AuthorizationRequest({ response_type: 'code', scope: 'openid' }))
      .expect(303);
    const uid = response.headers.location.split('/interaction/')[1];

    const value = getInteractionCookieValue(response);
    expect(value.length).to.be.at.most(3072);

    const mapping = decodeMapping(value);
    expect(mapping.client).to.equal(uid);
    expect(mapping._legacy).to.equal(uid);
    expect(Object.keys(mapping).filter((key) => key !== '_legacy')).to.have.lengthOf.at.most(10);
    expect(mapping).to.not.have.property(staleClientIds[0]);
    expect(mapping).to.have.property(staleClientIds[11], 'stale-uid-11');
  });

  it('resolves the interaction for the client identified by the Logto-App-Id header', async function () {
    const response = await this.agent.get('/auth')
      .query(new this.AuthorizationRequest({ response_type: 'code', scope: 'openid' }))
      .expect(303);

    await this.agent.get(response.headers.location)
      .set('Logto-App-Id', 'client')
      .expect(200)
      .expect(/Sign-in/);
  });

  it('resolves the interaction for the client identified by the app_id query parameter', async function () {
    const response = await this.agent.get('/auth')
      .query(new this.AuthorizationRequest({ response_type: 'code', scope: 'openid' }))
      .expect(303);

    await this.agent.get(response.headers.location)
      .query({ app_id: 'client' })
      .expect(200)
      .expect(/Sign-in/);
  });

  it('rejects resolving the interaction on behalf of a different client', async function () {
    const response = await this.agent.get('/auth')
      .query(new this.AuthorizationRequest({ response_type: 'code', scope: 'openid' }))
      .expect(303);

    sinon.spy(this.provider, 'interactionDetails');

    await this.agent.get(response.headers.location)
      .set('Logto-App-Id', 'client-2')
      .expect(400);

    return assert.rejects(this.provider.interactionDetails.getCall(0).returnValue, (err) => {
      expect(err.name).to.eql('SessionNotFound');
      expect(err.error_description).to.eql('interaction client_id mismatch');
      return true;
    });
  });

  it('accepts a legacy plain-string cookie value', async function () {
    const response = await this.agent.get('/auth')
      .query(new this.AuthorizationRequest({ response_type: 'code', scope: 'openid' }))
      .expect(303);
    const uid = response.headers.location.split('/interaction/')[1];

    this.agent._saveCookies.bind(this.agent)({
      request: { url: this.provider.issuer },
      headers: { 'set-cookie': [`_interaction=${uid}; path=${response.headers.location}; httponly`] },
    });

    await this.agent.get(response.headers.location)
      .set('Logto-App-Id', 'client')
      .expect(200)
      .expect(/Sign-in/);
  });

  it('reads the raw-JSON cookie format written before the value was percent-encoded', () => {
    const raw = JSON.stringify({ client: 'uid-a', _legacy: 'uid-b' });
    expect(getInteractionUid(raw, 'client')).to.equal('uid-a');
    expect(getInteractionUid(raw, 'other')).to.equal('uid-b');
  });

  describe('bounded client map', () => {
    it('evicts the least recently written client beyond the entry bound', () => {
      let value;
      for (let i = 0; i < 11; i += 1) {
        value = setInteractionUid(value, `client-${i}`, `uid-${i}`);
      }

      const mapping = decodeMapping(value);
      expect(Object.keys(mapping).filter((key) => key !== '_legacy')).to.have.lengthOf(10);
      expect(mapping).to.not.have.property('client-0');
      expect(mapping).to.have.property('client-1', 'uid-1');
      expect(mapping).to.have.property('client-10', 'uid-10');
      expect(getInteractionUid(value, null)).to.equal('uid-10');
    });

    it('re-writing a client refreshes its eviction order', () => {
      let value;
      for (let i = 0; i < 10; i += 1) {
        value = setInteractionUid(value, `client-${i}`, `uid-${i}`);
      }
      value = setInteractionUid(value, 'client-0', 'uid-0-again');
      value = setInteractionUid(value, 'client-10', 'uid-10');

      const mapping = decodeMapping(value);
      expect(mapping).to.have.property('client-0', 'uid-0-again');
      expect(mapping).to.not.have.property('client-1');
      expect(mapping).to.have.property('client-10', 'uid-10');
    });

    it('keeps the encoded value within the size bound for CIMD-length client IDs', () => {
      /**
       * Ten of these entries encode to ~3.8 KB, well over the 3072-byte bound, so the size
       * bound evicts entries before the entry-count bound is ever reached.
       */
      const clientIdFor = (i) => `https://client-${i}.example.com/.well-known/${'x'.repeat(300)}.json`;

      let value;
      for (let i = 0; i < 10; i += 1) {
        value = setInteractionUid(value, clientIdFor(i), `uid-${i}`);
      }

      expect(value.length).to.be.at.most(3072);
      expect(getInteractionUid(value, clientIdFor(9))).to.equal('uid-9');

      const mapping = decodeMapping(value);
      expect(mapping).to.not.have.property(clientIdFor(0));
      expect(mapping).to.not.have.property(clientIdFor(1));
    });

    it('falls back to a legacy-only mapping when a single entry alone exceeds the size bound', () => {
      const hugeClientId = `https://client.example.com/${'x'.repeat(4000)}`;
      const value = setInteractionUid(undefined, hugeClientId, 'uid');

      expect(value.length).to.be.at.most(3072);
      expect(getInteractionUid(value, hugeClientId)).to.equal('uid');
      expect(decodeMapping(value)).to.deep.equal({ _legacy: 'uid' });
    });
  });
});
