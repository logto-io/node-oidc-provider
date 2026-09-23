import { expect } from 'chai';

import bootstrap, { mock } from '../test_helper.js';
import nanoid from '../../lib/helpers/nanoid.js';

const REGISTERED_CLIENT_ID = 'client';
const REGISTERED_REDIRECT_URI = 'https://client.example.com/cb';

function clientIdUrl(host) {
  return `https://${host}/client`;
}

function redirectUri(host) {
  return `https://${host}/cb`;
}

function mockDocument(host) {
  mock(`https://${host}`)
    .intercept({ path: '/client' })
    .reply(200, JSON.stringify({
      client_id: clientIdUrl(host),
      redirect_uris: [redirectUri(host)],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      scope: 'openid profile email offline_access',
    }), {
      headers: { 'content-type': 'application/json' },
    });
}

describe('CIMD offline_access consent prompt', () => {
  before(bootstrap(import.meta.url));

  beforeEach(function () {
    return this.login({ scope: 'openid offline_access' });
  });

  afterEach(function () {
    return this.logout();
  });

  // Pre-granted, so a consent interaction can only come from the added prompt.
  async function grantCimdClient(ctx, host, scope = 'openid offline_access') {
    const clientId = clientIdUrl(host);
    const grant = new ctx.provider.Grant({ clientId, accountId: ctx.loggedInAccountId });
    grant.addOIDCScope(scope);
    const grantId = await grant.save();
    ctx.getSession().authorizations[clientId] = { sid: nanoid(), grantId };
  }

  function authorize(ctx, query) {
    return ctx.agent.get('/auth')
      .query({ response_type: 'code', scope: 'openid offline_access', ...query })
      .expect(303);
  }

  function authorizeCimd(ctx, host, query = {}) {
    return authorize(ctx, {
      client_id: clientIdUrl(host),
      redirect_uri: redirectUri(host),
      ...query,
    });
  }

  // The pathname keeps the mount prefix when the suite runs mounted.
  function interactionOf(ctx, response) {
    const { pathname } = new URL(response.headers.location, ctx.provider.issuer);
    expect(pathname).to.match(/\/interaction\/[^/]+$/);

    return {
      pathname,
      interaction: ctx.TestAdapter.for('Interaction').syncFind(pathname.split('/').pop()),
    };
  }

  function codeOf(ctx, response, redirect_uri) {
    const location = new URL(response.headers.location);
    expect(location.origin + location.pathname).to.equal(redirect_uri);
    expect(location.searchParams.get('error')).to.equal(null);
    const code = location.searchParams.get('code');
    expect(code).to.be.a('string');

    return {
      code,
      record: ctx.TestAdapter.for('AuthorizationCode').syncFind(ctx.getTokenJti(code)),
    };
  }

  it('forces consent and issues a refresh token when a CIMD client omits prompt', async function () {
    const host = 'consent-added.example.com';
    mockDocument(host);
    await grantCimdClient(this, host);

    const { pathname, interaction } = interactionOf(this, await authorizeCimd(this, host));
    expect(interaction.params.prompt).to.equal('consent');
    expect(interaction.params.scope.split(' ')).to.include('offline_access');
    expect(interaction.prompt.name).to.equal('consent');
    expect(interaction.prompt.reasons).to.deep.equal(['consent_prompt']);

    const submitted = await this.agent.post(pathname)
      .send({ prompt: 'consent' })
      .type('form')
      .expect(303);
    const { code, record } = codeOf(
      this,
      await this.agent.get(new URL(submitted.headers.location).pathname).expect(303),
      redirectUri(host),
    );
    expect(record.scope.split(' ')).to.include('offline_access');

    const { body: tokens } = await this.agent.post('/token')
      .send({
        client_id: clientIdUrl(host),
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri(host),
      })
      .type('form')
      .expect(200);
    expect(tokens).to.have.property('refresh_token');
  });

  it('adds consent next to the prompt values a CIMD client sends', async function () {
    const host = 'consent-login.example.com';
    mockDocument(host);

    const { interaction } = interactionOf(
      this,
      await authorizeCimd(this, host, { prompt: 'login' }),
    );
    expect(interaction.params.prompt).to.equal('login consent');
    expect(interaction.params.scope.split(' ')).to.include('offline_access');
  });

  it('adds consent to a CIMD pushed authorization request', async function () {
    const host = 'consent-par.example.com';
    mockDocument(host);
    await grantCimdClient(this, host);

    const { body: { request_uri } } = await this.agent.post('/request')
      .send({
        client_id: clientIdUrl(host),
        redirect_uri: redirectUri(host),
        response_type: 'code',
        scope: 'openid offline_access',
      })
      .type('form')
      .expect(201);

    const { interaction } = interactionOf(this, await this.agent.get('/auth')
      .query({ client_id: clientIdUrl(host), request_uri })
      .expect(303));
    expect(interaction.params.prompt).to.equal('consent');
    expect(interaction.params.scope.split(' ')).to.include('offline_access');
    expect(interaction.prompt.reasons).to.deep.equal(['consent_prompt']);
  });

  it('leaves prompt=none untouched and drops offline_access as upstream does', async function () {
    const host = 'consent-none.example.com';
    mockDocument(host);
    await grantCimdClient(this, host);

    const { record } = codeOf(
      this,
      await authorizeCimd(this, host, { prompt: 'none' }),
      redirectUri(host),
    );
    expect(record.scope.split(' ')).not.to.include('offline_access');
  });

  it('does not add consent when a CIMD client does not request offline_access', async function () {
    const host = 'consent-online.example.com';
    mockDocument(host);
    await grantCimdClient(this, host, 'openid');

    const { record } = codeOf(
      this,
      await authorizeCimd(this, host, { scope: 'openid' }),
      redirectUri(host),
    );
    expect(record.scope).to.equal('openid');
  });

  it('does not add consent for a registered client, which still loses offline_access', async function () {
    const { code, record } = codeOf(
      this,
      await authorize(this, {
        client_id: REGISTERED_CLIENT_ID,
        redirect_uri: REGISTERED_REDIRECT_URI,
      }),
      REGISTERED_REDIRECT_URI,
    );
    expect(record.scope.split(' ')).not.to.include('offline_access');

    const { body: tokens } = await this.agent.post('/token')
      .auth(REGISTERED_CLIENT_ID, 'secret')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REGISTERED_REDIRECT_URI,
      })
      .type('form')
      .expect(200);
    expect(tokens).not.to.have.property('refresh_token');
  });
});
