import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { bearer, login, setup, userWithGrants, type TestCtx } from './helpers.ts';

describe('RBAC: users, roles, groups', () => {
  let ctx: TestCtx;
  before(async () => (ctx = await setup()));
  after(async () => ctx.close());

  const api = (method: 'GET' | 'POST' | 'PATCH' | 'DELETE', url: string, token: string, payload?: object) =>
    ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(token), ...(payload && { payload }) });

  it('lists system roles', async () => {
    const res = await api('GET', '/roles', ctx.adminToken);
    const names = res.json().items.map((r: { name: string }) => r.name);
    assert.deepEqual(names, ['Administrator', 'Auditor', 'Helpdesk']);
  });

  it('system roles are immutable', async () => {
    const admin = (await api('GET', '/roles', ctx.adminToken)).json().items[0];
    assert.equal((await api('PATCH', `/roles/${admin.id}`, ctx.adminToken, { permissions: [] })).statusCode, 409);
    assert.equal((await api('DELETE', `/roles/${admin.id}`, ctx.adminToken)).statusCode, 409);
  });

  it('PATCH only changes the given fields (regression: zod defaults in partial schemas)', async () => {
    const r = await api('POST', '/roles', ctx.adminToken, { name: 'keep-me', description: 'desc', permissions: ['devices:read'] });
    const patched = await api('PATCH', `/roles/${r.json().id}`, ctx.adminToken, { name: 'renamed' });
    assert.equal(patched.json().name, 'renamed');
    assert.equal(patched.json().description, 'desc');
    assert.deepEqual(patched.json().permissions, ['devices:read']);
  });

  it('rejects unknown permissions', async () => {
    const res = await api('POST', '/roles', ctx.adminToken, { name: 'bad', permissions: ['users:fly'] });
    assert.equal(res.statusCode, 400);
  });

  it('enforces permissions per route', async () => {
    const { token } = await userWithGrants(ctx, 'reader', ['users:read']);
    assert.equal((await api('GET', '/users', token)).statusCode, 200);
    const create = await api('POST', '/users', token, { username: 'x', password: 'long-enough-pw' });
    assert.equal(create.statusCode, 403);
    assert.equal(create.json().error.code, 'forbidden');
    assert.equal((await api('GET', '/audit-log', token)).statusCode, 403);
    const me = (await api('GET', '/auth/me', token)).json();
    assert.deepEqual(me.permissions, ['users:read']);
  });

  it('user CRUD with search and pagination', async () => {
    const created = await api('POST', '/users', ctx.adminToken, {
      username: 'max.muster',
      displayName: 'Max Muster',
      email: 'max@example.org',
      password: 'max-password-123',
    });
    assert.equal(created.statusCode, 201);
    const id = created.json().id;
    assert.equal(created.json().passwordHash, undefined);

    const dup = await api('POST', '/users', ctx.adminToken, { username: 'max.muster', password: 'max-password-123' });
    assert.equal(dup.statusCode, 409);

    const list = (await api('GET', '/users?search=muster', ctx.adminToken)).json();
    assert.equal(list.total, 1);
    const page = (await api('GET', '/users?limit=1&offset=0', ctx.adminToken)).json();
    assert.equal(page.items.length, 1);
    assert.ok(page.total >= 2);

    const patched = await api('PATCH', `/users/${id}`, ctx.adminToken, { displayName: 'Max M.' });
    assert.equal(patched.json().displayName, 'Max M.');

    assert.equal((await api('DELETE', `/users/${id}`, ctx.adminToken)).statusCode, 204);
    assert.equal((await api('GET', `/users/${id}`, ctx.adminToken)).statusCode, 404);
  });

  it('rejects too short passwords and bad ids', async () => {
    assert.equal((await api('POST', '/users', ctx.adminToken, { username: 'shorty', password: 'short' })).statusCode, 400);
    assert.equal((await api('GET', '/users/not-a-uuid', ctx.adminToken)).statusCode, 400);
  });

  it('deactivation ends sessions and blocks login', async () => {
    const { userId, token } = await userWithGrants(ctx, 'temp', ['devices:read']);
    await api('PATCH', `/users/${userId}`, ctx.adminToken, { isActive: false });
    assert.equal((await api('GET', '/auth/me', token)).statusCode, 401);
    await assert.rejects(login(ctx.app, 'temp', 'user-password-123'));
  });

  it('users cannot delete/deactivate themselves or change their own roles', async () => {
    const me = (await api('GET', '/auth/me', ctx.adminToken)).json();
    assert.equal((await api('DELETE', `/users/${me.id}`, ctx.adminToken)).statusCode, 409);
    assert.equal((await api('PATCH', `/users/${me.id}`, ctx.adminToken, { isActive: false })).statusCode, 409);
    assert.equal((await api('PATCH', `/users/${me.id}`, ctx.adminToken, { roleIds: [] })).statusCode, 409);
  });

  it('prevents privilege escalation via roles and assignments', async () => {
    const { token } = await userWithGrants(ctx, 'useradmin', ['users:*', 'roles:*']);
    // cannot create a role with more than own grants
    assert.equal((await api('POST', '/roles', token, { name: 'super', permissions: ['*'] })).statusCode, 403);
    assert.equal((await api('POST', '/roles', token, { name: 'jobber', permissions: ['jobs:execute'] })).statusCode, 403);
    // may create a role within own grants
    assert.equal((await api('POST', '/roles', token, { name: 'ro-users', permissions: ['users:read'] })).statusCode, 201);
    // cannot assign the Administrator role
    const adminRole = (await api('GET', '/roles', token)).json().items.find((r: { name: string }) => r.name === 'Administrator');
    const res = await api('POST', '/users', token, { username: 'evil', password: 'evil-password-123', roleIds: [adminRole.id] });
    assert.equal(res.statusCode, 403);
  });

  it('effective permissions include group roles', async () => {
    const role = (await api('POST', '/roles', ctx.adminToken, { name: 'patcher', permissions: ['patches:read', 'patches:execute'] })).json();
    const user = (await api('POST', '/users', ctx.adminToken, { username: 'member', password: 'member-password-1' })).json();
    const group = await api('POST', '/groups', ctx.adminToken, { name: 'Buchhaltung', roleIds: [role.id], memberIds: [user.id] });
    assert.equal(group.statusCode, 201);
    assert.deepEqual(group.json().members.map((m: { username: string }) => m.username), ['member']);

    const token = await login(ctx.app, 'member', 'member-password-1');
    assert.deepEqual((await api('GET', '/auth/me', token)).json().permissions, ['patches:execute', 'patches:read']);

    await api('PATCH', `/groups/${group.json().id}`, ctx.adminToken, { memberIds: [] });
    assert.deepEqual((await api('GET', '/auth/me', token)).json().permissions, []);
  });

  it('permission catalogue is available to any authenticated user', async () => {
    const { token } = await userWithGrants(ctx, 'nobody', []);
    const res = await api('GET', '/permissions', token);
    assert.equal(res.statusCode, 200);
    assert.ok(res.json().modules.some((m: { module: string }) => m.module === 'scripts'));
  });
});
