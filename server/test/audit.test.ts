import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { sql } from 'drizzle-orm';
import { bearer, setup, type TestCtx } from './helpers.ts';

describe('audit log', () => {
  let ctx: TestCtx;
  before(async () => (ctx = await setup()));
  after(async () => ctx.close());

  const list = async (query = '') =>
    (await ctx.app.inject({ method: 'GET', url: `/api/v1/audit-log${query}`, headers: bearer(ctx.adminToken) })).json();

  it('records bootstrap, login and write actions with actor', async () => {
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v1/users',
      headers: bearer(ctx.adminToken),
      payload: { username: 'audited', password: 'audited-password-1' },
    });
    const { items } = await list();
    const actions = items.map((e: { action: string }) => e.action);
    assert.ok(actions.includes('user.bootstrap'));
    assert.ok(actions.includes('auth.login'));
    const create = items.find((e: { action: string }) => e.action === 'user.create');
    assert.equal(create.actorName, 'admin');
    assert.equal(create.targetId, created.json().id);
    assert.equal(create.details.password, undefined, 'password must never be audited');
  });

  it('never stores passwords in update details', async () => {
    const u = (await list('?action=user.create')).items[0];
    await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v1/users/${u.targetId}`,
      headers: bearer(ctx.adminToken),
      payload: { password: 'new-secret-password' },
    });
    const upd = (await list('?action=user.update')).items[0];
    assert.equal(upd.details.passwordChanged, true);
    assert.equal(JSON.stringify(upd).includes('new-secret-password'), false);
  });

  it('records failed logins', async () => {
    await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: 'mallory', password: 'x' } });
    const { items, total } = await list('?action=auth.login_failed');
    assert.equal(total, 1);
    assert.equal(items[0].details.username, 'mallory');
  });

  it('is append-only at database level', async () => {
    // drizzle wraps the driver error; the trigger message is in `cause`
    const appendOnly = (err: unknown) => /append-only/.test(String((err as { cause?: unknown }).cause ?? err));
    await assert.rejects(ctx.handle.db.execute(sql`UPDATE audit_log SET action = 'tampered'`), appendOnly);
    await assert.rejects(ctx.handle.db.execute(sql`DELETE FROM audit_log`), appendOnly);
    await assert.rejects(ctx.handle.db.execute(sql`TRUNCATE audit_log`), appendOnly);
    assert.ok((await list()).total > 0);
  });
});
