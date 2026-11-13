import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { purgeExpiredSessions } from '../src/housekeeping.ts';
import { sessions } from '../src/db/schema.ts';
import { ADMIN, bearer, login, setup, type TestCtx } from './helpers.ts';

describe('auth', () => {
  let ctx: TestCtx;
  before(async () => (ctx = await setup()));
  after(async () => ctx.close());

  it('health is public', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/v1/health' });
    assert.equal(res.statusCode, 200);
    assert.equal(res.json().database, 'ok');
  });

  it('login returns token, cookie and effective permissions', async () => {
    const res = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: ADMIN });
    assert.equal(res.statusCode, 200);
    const body = res.json();
    assert.match(body.token, /^ocs_/);
    assert.deepEqual(body.user.permissions, ['*']);
    const cookie = res.cookies.find((c) => c.name === 'opencm_session');
    assert.ok(cookie);
    assert.equal(cookie.httpOnly, true);
    assert.equal(cookie.sameSite, 'Strict');
  });

  it('rejects wrong password and unknown user with the same error', async () => {
    const wrong = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: ADMIN.username, password: 'nope' } });
    const unknown = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: 'ghost', password: 'nope' } });
    assert.equal(wrong.statusCode, 401);
    assert.equal(unknown.statusCode, 401);
    assert.deepEqual(wrong.json(), unknown.json());
  });

  it('keeps prototype-poisoning protection in the JSON parser', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      headers: { 'content-type': 'application/json' },
      payload: '{"username":"a","password":"b","__proto__":{"isAdmin":true}}',
    });
    assert.equal(res.statusCode, 400);
  });

  it('validates the login body', async () => {
    const res = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: '' } });
    assert.equal(res.statusCode, 400);
    assert.equal(res.json().error.code, 'validation_error');
  });

  it('me works with bearer and cookie, 401 without', async () => {
    assert.equal((await ctx.app.inject({ method: 'GET', url: '/api/v1/auth/me' })).statusCode, 401);
    const viaBearer = await ctx.app.inject({ method: 'GET', url: '/api/v1/auth/me', headers: bearer(ctx.adminToken) });
    assert.equal(viaBearer.json().username, ADMIN.username);
    const viaCookie = await ctx.app.inject({ method: 'GET', url: '/api/v1/auth/me', cookies: { opencm_session: ctx.adminToken } });
    assert.equal(viaCookie.statusCode, 200);
    const garbage = await ctx.app.inject({ method: 'GET', url: '/api/v1/auth/me', headers: bearer('ocs_invalid') });
    assert.equal(garbage.statusCode, 401);
  });

  it('logout invalidates the session', async () => {
    const token = await login(ctx.app, ADMIN.username, ADMIN.password);
    const out = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/logout', headers: bearer(token) });
    assert.equal(out.statusCode, 204);
    const me = await ctx.app.inject({ method: 'GET', url: '/api/v1/auth/me', headers: bearer(token) });
    assert.equal(me.statusCode, 401);
  });

  it('expired sessions are rejected and purged', async () => {
    const token = await login(ctx.app, ADMIN.username, ADMIN.password);
    await ctx.handle.db.update(sessions).set({ expiresAt: new Date(Date.now() - 1000) });
    const me = await ctx.app.inject({ method: 'GET', url: '/api/v1/auth/me', headers: bearer(token) });
    assert.equal(me.statusCode, 401);
    assert.ok((await purgeExpiredSessions(ctx.handle.db)) >= 1);
    ctx.adminToken = await login(ctx.app, ADMIN.username, ADMIN.password);
  });

  it('serves the OpenAPI docs', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/docs/json' });
    assert.equal(res.statusCode, 200);
    assert.equal(res.json().info.title, 'OpenCM API');
  });
});

describe('login rate limit', () => {
  let ctx: TestCtx;
  before(async () => (ctx = await setup({ LOGIN_RATE_LIMIT_PER_MIN: '3' })));
  after(async () => ctx.close());

  it('returns 429 after the configured number of attempts', async () => {
    // setup() already used one attempt
    const codes: number[] = [];
    for (let i = 0; i < 3; i++) {
      const res = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: 'x', password: 'y' } });
      codes.push(res.statusCode);
    }
    assert.deepEqual(codes, [401, 401, 429]);
  });
});
