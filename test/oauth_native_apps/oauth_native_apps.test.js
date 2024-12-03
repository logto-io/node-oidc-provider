import { strict as assert } from 'node:assert';

import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('OAuth 2.0 for Native Apps Best Current Practice features', () => {
  before(bootstrap(import.meta.url));

  describe('changed native client validations', () => {
    describe('Private-use URI Scheme Redirection', () => {
      it('allows custom uri scheme uris with localhost', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['com.example.app://localhost/op/callback', 'com.example.app:/op/callback'],
        });
      });

      // Updated test to reflect the forked version of oidc-provider
      it('allows custom schemes without dots with reverse domain name scheme recommendation', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['myapp:/op/callback'],
        });
      });
    });

    describe('Claimed HTTPS URI Redirection', () => {
      it('allows claimed https uris', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['https://claimed.example.com/op/callback'],
        });
      });

      // Updated test to reflect the forked version of oidc-provider
      it('allows https if using loopback uris', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['https://localhost/op/callback'],
        });
      });
    });

    describe('Loopback Interface Redirection', () => {
      it('catches invalid urls being passed in', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://127.0.0.1:2355/op/callback'],
        }).then((client) => {
          expect(client.redirectUriAllowed('http:')).to.be.false;
          expect(client.redirectUriAllowed('http://127.0.0.')).to.be.false;
          expect(client.redirectUriAllowed('http://127.0.0.1::')).to.be.false;
        });
      });

      it('allows http protocol localhost loopback uris (when registered with a random port)', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://localhost:2355/op/callback'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://localhost:2355/op/callback');
          expect(client.redirectUriAllowed('http://localhost/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:8888/op/callback')).to.be.true;
        });
      });

      it('allows http protocol localhost loopback uris (when registered without a port)', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://localhost/op/callback'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://localhost/op/callback');
          expect(client.redirectUriAllowed('http://localhost/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:8888/op/callback')).to.be.true;
        });
      });

      it('allows http protocol IPv4 loopback uris (when registered with a random port)', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://127.0.0.1:2355/op/callback'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://127.0.0.1:2355/op/callback');
          expect(client.redirectUriAllowed('http://127.0.0.1/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:8888/op/callback')).to.be.true;
        });
      });

      it('allows http protocol IPv4 loopback uris (when registered without a port)', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://127.0.0.1/op/callback'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://127.0.0.1/op/callback');
          expect(client.redirectUriAllowed('http://127.0.0.1/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:8888/op/callback')).to.be.true;
        });
      });

      it('allows http protocol IPv6 loopback uris (when registered with a random port)', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://[::1]:2355/op/callback'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://[::1]:2355/op/callback');
          expect(client.redirectUriAllowed('http://[::1]/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:8888/op/callback')).to.be.true;
        });
      });

      it('allows http protocol IPv6 loopback uris (when registered without a port)', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://[::1]/op/callback'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://[::1]/op/callback');
          expect(client.redirectUriAllowed('http://[::1]/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:8888/op/callback')).to.be.true;
        });
      });

      // Updated test to reflect the forked version of oidc-provider
      it('allows http protocol uris not using loopback uris', function () {
        return i(this.provider).clientAdd({
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://rp.example.com/op/callback'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://rp.example.com/op/callback');
          expect(client.redirectUriAllowed('http://rp.example.com/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://rp.example.com:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://rp.example.com:443/op/callback')).to.be.false;
        });
      });
    });
  });
});
