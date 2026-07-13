import { strict as assert } from 'node:assert';

import { expect } from 'chai';
import { createSandbox } from 'sinon';

import bootstrap from '../test_helper.js';
import { getInteractionUid } from '../../lib/helpers/interaction_cookie_handler.js';

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

function getInteractionCookieMapping(response) {
  return JSON.parse(decodeURIComponent(getInteractionCookieValue(response)));
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
});
