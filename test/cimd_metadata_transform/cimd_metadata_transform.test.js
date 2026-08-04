import { expect } from 'chai';

import bootstrap, { mock } from '../test_helper.js';
import { resolveClientByMetadataDocument } from '../../lib/helpers/client_id_metadata_document.js';

function clientIdUrl(host) {
  return `https://${host}/client`;
}

function metadataDocument(host, extra = {}) {
  return {
    client_id: clientIdUrl(host),
    redirect_uris: [`https://${host}/cb`],
    token_endpoint_auth_method: 'none',
    scope: 'openid profile email',
    client_name: 'Remote App',
    ...extra,
  };
}

function mockDocument(host, body, headers = {}) {
  mock(`https://${host}`)
    .intercept({ path: '/client' })
    .reply(200, JSON.stringify(body), {
      headers: { 'content-type': 'application/json', ...headers },
    });
}

describe('CIMD metadata transform', () => {
  before(bootstrap(import.meta.url));

  /**
   * The hook lives on the shared provider instance, so each test swaps it in only for the
   * duration of its own resolutions.
   */
  async function withTransform(provider, transform, fn) {
    const { features } = i(provider);
    const orig = features.clientIdMetadataDocument.transformClientMetadata;
    features.clientIdMetadataDocument.transformClientMetadata = transform;
    try {
      return await fn();
    } finally {
      features.clientIdMetadataDocument.transformClientMetadata = orig;
    }
  }

  function rejection(promise) {
    return promise.then(
      () => { throw new Error('expected the resolution to reject'); },
      (err) => err,
    );
  }

  it('applies the transform to a freshly fetched document', async function () {
    const host = 'transform-fetch.example.com';
    mockDocument(host, metadataDocument(host));

    const client = await withTransform(this.provider, async (_ctx, metadata) => ({
      ...metadata,
      scope: 'openid',
      grant_types: ['authorization_code'],
    }), () => resolveClientByMetadataDocument(this.provider, clientIdUrl(host)));

    expect(client.scope).to.equal('openid');
    expect(client.grantTypes).to.deep.equal(['authorization_code']);
    expect(client.metadata().client_name).to.equal('Remote App');
  });

  it('runs on every resolution, including cache hits, with the current host behavior', async function () {
    const host = 'transform-cache.example.com';
    mockDocument(host, metadataDocument(host), { 'cache-control': 'max-age=3600' });

    const first = await withTransform(this.provider, async (_ctx, metadata) => ({
      ...metadata,
      scope: 'openid',
    }), () => resolveClientByMetadataDocument(this.provider, clientIdUrl(host)));
    expect(first.scope).to.equal('openid');

    // No new mock: this resolution is served from cache, yet the swapped transform applies.
    const second = await withTransform(this.provider, async (_ctx, metadata) => ({
      ...metadata,
      scope: 'openid email',
    }), () => resolveClientByMetadataDocument(this.provider, clientIdUrl(host)));
    expect(second.scope).to.equal('openid email');
  });

  it('keeps the cached document raw even when the transform mutates its input', async function () {
    const host = 'transform-mutate.example.com';
    mockDocument(host, metadataDocument(host), { 'cache-control': 'max-age=3600' });

    const seen = [];
    const mutatingTransform = async (_ctx, metadata) => {
      seen.push({ scope: metadata.scope, client_name: metadata.client_name });
      metadata.scope = 'openid';
      delete metadata.client_name;
      return metadata;
    };

    await withTransform(this.provider, mutatingTransform, () => resolveClientByMetadataDocument(this.provider, clientIdUrl(host)));
    await withTransform(this.provider, mutatingTransform, () => resolveClientByMetadataDocument(this.provider, clientIdUrl(host)));

    expect(seen).to.deep.equal([
      { scope: 'openid profile email', client_name: 'Remote App' },
      { scope: 'openid profile email', client_name: 'Remote App' },
    ]);
  });

  it('validates the raw document before the transform can touch it', async function () {
    const host = 'transform-launder.example.com';
    mockDocument(host, metadataDocument(host, { client_secret: 'oops' }));

    const err = await rejection(withTransform(this.provider, async (_ctx, metadata) => {
      const { client_secret: ignored, ...rest } = metadata;
      return rest;
    }, () => resolveClientByMetadataDocument(this.provider, clientIdUrl(host))));

    expect(err.message).to.equal('invalid_client_metadata');
    expect(err.error_description).to.contain('client_secret');
  });

  it('runs the transformed metadata through client schema validation', async function () {
    const host = 'transform-invalid.example.com';
    mockDocument(host, metadataDocument(host));

    const err = await rejection(withTransform(this.provider, async (_ctx, metadata) => ({
      ...metadata,
      redirect_uris: 'not-an-array',
    }), () => resolveClientByMetadataDocument(this.provider, clientIdUrl(host))));

    expect(err.message).to.equal('invalid_redirect_uri');
  });

  it('propagates transform errors untouched instead of mapping them to invalid_client', async function () {
    const host = 'transform-error.example.com';
    mockDocument(host, metadataDocument(host));

    const failure = new Error('host transform failure');
    const err = await rejection(withTransform(this.provider, async () => {
      throw failure;
    }, () => resolveClientByMetadataDocument(this.provider, clientIdUrl(host))));

    expect(err).to.equal(failure);
  });

  it('rejects a transform that does not return the metadata object', async function () {
    const host = 'transform-void.example.com';
    mockDocument(host, metadataDocument(host));

    const err = await rejection(withTransform(
      this.provider,
      async () => undefined,
      () => resolveClientByMetadataDocument(this.provider, clientIdUrl(host)),
    ));

    expect(err).to.be.instanceOf(TypeError);
  });

  it('defaults to identity', async function () {
    const host = 'transform-default.example.com';
    mockDocument(host, metadataDocument(host));

    const client = await resolveClientByMetadataDocument(this.provider, clientIdUrl(host));

    expect(client.scope).to.equal('openid profile email');
    expect(client.metadata().client_name).to.equal('Remote App');
  });

  it('feeds the transformed scope into the native authorization scope check', async function () {
    const host = 'transform-e2e.example.com';
    mockDocument(host, metadataDocument(host));

    await withTransform(this.provider, async (_ctx, metadata) => ({
      ...metadata,
      scope: 'openid',
    }), () => this.agent.get('/auth')
      .query({
        client_id: clientIdUrl(host),
        redirect_uri: `https://${host}/cb`,
        response_type: 'code',
        scope: 'openid profile',
      })
      .expect(303)
      .expect((response) => {
        const location = new URL(response.headers.location);
        expect(location.origin + location.pathname).to.equal(`https://${host}/cb`);
        expect(location.searchParams.get('error')).to.equal('invalid_scope');
      }));
  });

  it('surfaces transform failures as a server error, not a client error', async function () {
    const host = 'transform-e2e-error.example.com';
    mockDocument(host, metadataDocument(host));

    await withTransform(this.provider, async () => {
      throw new Error('host transform failure');
    }, () => this.agent.get('/auth')
      .query({
        client_id: clientIdUrl(host),
        redirect_uri: `https://${host}/cb`,
        response_type: 'code',
        scope: 'openid',
      })
      .expect(500)
      .expect((response) => {
        expect(response.text).to.contain('server_error');
      }));
  });
});
