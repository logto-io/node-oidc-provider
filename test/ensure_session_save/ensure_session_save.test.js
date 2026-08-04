import { expect } from 'chai';

import bootstrap from '../test_helper.js';
import nanoid from '../../lib/helpers/nanoid.js';

/**
 * LOGTO PATCH(ensure-session-save-persisted-only): the device user-code routes are the only ones
 * whose error handler writes to the session (an xsrf secret) after `sessionMiddleware` already
 * ran. When such a request carries no persisted session, `ensureSessionSave` used to call
 * `persist()` on it and turn the intended error response into a 500. These tests fail loudly if
 * the guard is lost.
 */

describe('ensure session save', () => {
  before(bootstrap(import.meta.url));

  describe('without a persisted session', () => {
    it('renders the user code form instead of failing on device resume', function () {
      return this.agent.get(`/device/${nanoid()}`)
        .expect(400)
        .expect(({ text }) => {
          expect(text).to.include('op.deviceInputForm');
        });
    });

    it('renders the user code form instead of failing on a user code submission', function () {
      return this.agent.post('/device')
        .send({ user_code: 'AAA-BBB-CCC' })
        .type('form')
        .expect(400)
        .expect(({ text }) => {
          expect(text).to.include('op.deviceInputForm');
        });
    });

    it('renders the user code form instead of failing on an empty submission', function () {
      return this.agent.post('/device')
        .send({})
        .type('form')
        .expect(400)
        .expect(({ text }) => {
          expect(text).to.include('op.deviceInputForm');
        });
    });

    it('does not emit a server_error', async function () {
      const emitted = [];
      const listener = (ctx, err) => emitted.push(err);
      this.provider.on('server_error', listener);

      try {
        await this.agent.get(`/device/${nanoid()}`).expect(400);
      } finally {
        this.provider.removeListener('server_error', listener);
      }

      expect(emitted).to.be.empty;
    });
  });

  describe('with a persisted session', () => {
    it('still persists a session touched by the error handler', async function () {
      const session = new this.provider.Session({ jti: nanoid() });
      await session.save(60);

      const { jti } = session;
      const expiresAt = new Date(Date.now() + 60_000).toGMTString();
      this.agent._saveCookies.bind(this.agent)({
        request: { url: this.provider.issuer },
        headers: { 'set-cookie': [`_session=${jti}; path=/; expires=${expiresAt}; httponly`] },
      });

      await this.agent.get(`/device/${nanoid()}`).expect(400);

      const persisted = await this.provider.Session.find(jti);
      expect(persisted).to.be.ok;
      expect(persisted.state).to.have.property('secret');
    });
  });
});
