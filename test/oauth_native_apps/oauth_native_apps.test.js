import { expect } from 'chai';

import bootstrap from '../test_helper.js';
import addClient from '../../lib/helpers/add_client.js';

describe('OAuth 2.0 for Native Apps Best Current Practice features', () => {
  before(bootstrap(import.meta.url));

  describe('changed native client validations', () => {
    describe('Loopback Interface Redirection', () => {
      it('catches invalid urls being passed in', function () {
        return addClient(this.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://127.0.0.1:2355/op/callback'],
          post_logout_redirect_uris: ['http://127.0.0.1:2355/op/logout'],
        }).then((client) => {
          expect(client.redirectUriAllowed('http:')).to.be.false;
          expect(client.redirectUriAllowed('http://127.0.0.')).to.be.false;
          expect(client.redirectUriAllowed('http://127.0.0.1::')).to.be.false;
          expect(client.postLogoutRedirectUriAllowed('http:')).to.be.false;
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.')).to.be.false;
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1::')).to.be.false;
        });
      });

      it('allows http protocol localhost loopback uris (when registered with a random port)', function () {
        return addClient(this.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://localhost:2355/op/callback'],
          post_logout_redirect_uris: ['http://localhost:2355/op/logout'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://localhost:2355/op/callback');
          expect(client.redirectUriAllowed('http://localhost/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:8888/op/callback')).to.be.true;

          expect(client.postLogoutRedirectUris).to.contain('http://localhost:2355/op/logout');
          expect(client.postLogoutRedirectUriAllowed('http://localhost/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://localhost:80/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://localhost:443/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://localhost:2355/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://localhost:8888/op/logout')).to.be.true;
        });
      });

      it('allows http protocol localhost loopback uris (when registered without a port)', function () {
        return addClient(this.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://localhost/op/callback'],
          post_logout_redirect_uris: ['http://localhost/op/logout'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://localhost/op/callback');
          expect(client.redirectUriAllowed('http://localhost/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://localhost:8888/op/callback')).to.be.true;

          expect(client.postLogoutRedirectUris).to.contain('http://localhost/op/logout');
          expect(client.postLogoutRedirectUriAllowed('http://localhost/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://localhost:80/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://localhost:443/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://localhost:2355/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://localhost:8888/op/logout')).to.be.true;
        });
      });

      it('allows http protocol IPv4 loopback uris (when registered with a random port)', function () {
        return addClient(this.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://127.0.0.1:2355/op/callback'],
          post_logout_redirect_uris: ['http://127.0.0.1:2355/op/logout'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://127.0.0.1:2355/op/callback');
          expect(client.redirectUriAllowed('http://127.0.0.1/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:8888/op/callback')).to.be.true;

          expect(client.postLogoutRedirectUris).to.contain('http://127.0.0.1:2355/op/logout');
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1:80/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1:443/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1:2355/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1:8888/op/logout')).to.be.true;
        });
      });

      it('allows http protocol IPv4 loopback uris (when registered without a port)', function () {
        return addClient(this.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://127.0.0.1/op/callback'],
          post_logout_redirect_uris: ['http://127.0.0.1/op/logout'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://127.0.0.1/op/callback');
          expect(client.redirectUriAllowed('http://127.0.0.1/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://127.0.0.1:8888/op/callback')).to.be.true;

          expect(client.postLogoutRedirectUris).to.contain('http://127.0.0.1/op/logout');
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1:80/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1:443/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1:2355/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://127.0.0.1:8888/op/logout')).to.be.true;
        });
      });

      it('allows http protocol IPv6 loopback uris (when registered with a random port)', function () {
        return addClient(this.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://[::1]:2355/op/callback'],
          post_logout_redirect_uris: ['http://[::1]:2355/op/logout'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://[::1]:2355/op/callback');
          expect(client.redirectUriAllowed('http://[::1]/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:8888/op/callback')).to.be.true;

          expect(client.postLogoutRedirectUris).to.contain('http://[::1]:2355/op/logout');
          expect(client.postLogoutRedirectUriAllowed('http://[::1]/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://[::1]:80/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://[::1]:443/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://[::1]:2355/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://[::1]:8888/op/logout')).to.be.true;
        });
      });

      it('allows http protocol IPv6 loopback uris (when registered without a port)', function () {
        return addClient(this.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://[::1]/op/callback'],
          post_logout_redirect_uris: ['http://[::1]/op/logout'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://[::1]/op/callback');
          expect(client.redirectUriAllowed('http://[::1]/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:80/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:443/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:2355/op/callback')).to.be.true;
          expect(client.redirectUriAllowed('http://[::1]:8888/op/callback')).to.be.true;

          expect(client.postLogoutRedirectUris).to.contain('http://[::1]/op/logout');
          expect(client.postLogoutRedirectUriAllowed('http://[::1]/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://[::1]:80/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://[::1]:443/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://[::1]:2355/op/logout')).to.be.true;
          expect(client.postLogoutRedirectUriAllowed('http://[::1]:8888/op/logout')).to.be.true;
        });
      });

      // LOGTO PATCH(redirect-uri-relaxation): non-loopback http uris are allowed for native clients
      it('allows http protocol redirect_uris not using loopback uris', function () {
        return addClient(this.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://rp.example.com/op/callback'],
        }).then((client) => {
          expect(client.redirectUris).to.contain('http://rp.example.com/op/callback');
          expect(client.redirectUriAllowed('http://rp.example.com/op/callback')).to.be.true;
        });
      });

      // LOGTO PATCH(redirect-uri-relaxation): non-loopback http uris are allowed for native clients
      it('allows http protocol post_logout_redirect_uris not using loopback uris', function () {
        return addClient(this.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://[::1]/op/callback'],
          post_logout_redirect_uris: ['http://rp.example.com/op/logout'],
        }).then((client) => {
          expect(client.postLogoutRedirectUris).to.contain('http://rp.example.com/op/logout');
          expect(client.postLogoutRedirectUriAllowed('http://rp.example.com/op/logout')).to.be.true;
        });
      });
    });
  });
});
