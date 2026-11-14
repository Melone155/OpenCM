import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { eq } from 'drizzle-orm';
import type { Directory, DirectoryUser } from '../src/auth/ldap.ts';
import { buildUserFilter, ldapEscape } from '../src/auth/ldap.ts';
import { base32Decode, counterAt, hotp } from '../src/auth/totp.ts';
import { apiTokens, users } from '../src/db/schema.ts';
import { enrollOk, type EnrolledAgent } from './agent-helpers.ts';
import { ADMIN, bearer, login, setup, userWithGrants, type TestCtx } from './helpers.ts';

type Method = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';

function apiFor(ctx: TestCtx) {
  return async (method: Method, url: string, payload?: object, token = ctx.adminToken) => {
    const res = await ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(token), ...(payload && { payload }) });
    return { status: res.statusCode, body: res.body ? (res.headers['content-type']?.includes('json') ? res.json() : res.body) : null, headers: res.headers };
  };
}

async function approvedScript(api: ReturnType<typeof apiFor>, name: string, interpreter = 'python') {
  const s = await api('POST', '/scripts', { name, interpreter, content: 'print(1)' });
  await api('POST', `/scripts/${s.body.id}/versions/1/approve`);
  return s.body.id as string;
}

// ====================================================================== scopes

describe('M4: permission scopes (device groups)', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;
  let win: EnrolledAgent;
  let lin: EnrolledAgent;
  let helpdesk: string;
  let groupA: string;
  let groupB: string;
  let jobId: string;

  before(async () => {
    ctx = await setup();
    api = apiFor(ctx);
    win = await enrollOk(ctx, { hostname: 'BUCH-PC-01', os: 'windows' });
    lin = await enrollOk(ctx, { hostname: 'IT-SRV-01', os: 'linux' });
    groupA = (await api('POST', '/device-groups', { kind: 'static', name: 'Buchhaltung', deviceIds: [win.deviceId] })).body.id;
    groupB = (await api('POST', '/device-groups', { kind: 'static', name: 'IT', deviceIds: [lin.deviceId] })).body.id;
    const role = await api('POST', '/roles', {
      name: 'Helpdesk Buchhaltung',
      permissions: ['devices:read', 'inventory:read', 'jobs:read', 'jobs:execute', 'scripts:execute', 'vulnerabilities:read'],
    });
    await api('POST', '/users', {
      username: 'hd-buch',
      password: 'helpdesk-password-1',
      roleAssignments: [{ roleId: role.body.id, scopeDeviceGroupIds: [groupA] }],
    });
    helpdesk = await login(ctx.app, 'hd-buch', 'helpdesk-password-1');
    const scriptId = await approvedScript(api, 'scoped-script');
    jobId = (await api('POST', '/jobs', { name: 'both groups', trigger: 'manual', targets: { groupIds: [groupA, groupB] }, steps: [{ scriptId }] })).body.id;
  });
  after(async () => ctx.close());

  it('lists and shows only devices within the scope; others are 404', async () => {
    const list = await api('GET', '/devices', undefined, helpdesk);
    assert.deepEqual(list.body.items.map((d: { hostname: string }) => d.hostname), ['BUCH-PC-01']);
    assert.equal(list.body.total, 1);
    assert.equal((await api('GET', `/devices/${win.deviceId}`, undefined, helpdesk)).status, 200);
    assert.equal((await api('GET', `/devices/${lin.deviceId}`, undefined, helpdesk)).status, 404, 'existence not revealed');
    assert.equal((await api('GET', `/devices/${lin.deviceId}/software`, undefined, helpdesk)).status, 404);
    assert.equal((await api('GET', `/devices/${lin.deviceId}/vulnerabilities`, undefined, helpdesk)).status, 404);
    assert.equal((await api('GET', `/devices/${win.deviceId}/history`, undefined, helpdesk)).status, 200);
  });

  it('scoped rights never unlock global endpoints', async () => {
    for (const url of ['/users', '/audit-log', '/jobs', '/device-groups', '/enrollment-tokens', '/roles']) {
      assert.equal((await api('GET', url, undefined, helpdesk)).status, 403, url);
    }
    assert.equal((await api('POST', `/devices/${win.deviceId}/revoke`, undefined, helpdesk)).status, 403, 'devices:update not granted');
    const me = (await api('GET', '/auth/me', undefined, helpdesk)).body;
    assert.deepEqual(me.permissions, []);
    assert.deepEqual(me.scoped[0].deviceGroupIds, [groupA]);
  });

  it('runs jobs only on targets within the scope', async () => {
    const run = await api('POST', `/jobs/${jobId}/run`, {}, helpdesk);
    assert.equal(run.status, 201, JSON.stringify(run.body));
    assert.equal(run.body.counts.total, 1);
    const tasks = (await api('GET', `/runs/${run.body.id}/tasks`, undefined, helpdesk)).body.items;
    assert.deepEqual(tasks.map((t: { hostname: string }) => t.hostname), ['BUCH-PC-01']);
    assert.equal((await api('POST', `/jobs/${jobId}/run`, { deviceIds: [lin.deviceId] }, helpdesk)).status, 403);
  });

  it('ad-hoc runs: no "all devices", nothing outside the scope', async () => {
    const scriptId = await approvedScript(api, 'adhoc-scoped');
    assert.equal((await api('POST', `/scripts/${scriptId}/run`, { targets: { allDevices: true } }, helpdesk)).status, 403);
    assert.equal((await api('POST', `/scripts/${scriptId}/run`, { targets: { groupIds: [groupB] } }, helpdesk)).status, 409);
    assert.equal((await api('POST', `/scripts/${scriptId}/run`, { targets: { deviceIds: [lin.deviceId] } }, helpdesk)).status, 403);
    const ok = await api('POST', `/scripts/${scriptId}/run`, { targets: { groupIds: [groupA, groupB] } }, helpdesk);
    assert.equal(ok.status, 201);
    assert.equal(ok.body.counts.total, 1);
    // test runs: only on own devices
    assert.equal((await api('POST', `/scripts/${scriptId}/versions/1/test`, { deviceId: lin.deviceId }, helpdesk)).status, 404);
    assert.equal((await api('POST', `/scripts/${scriptId}/versions/1/test`, { deviceId: win.deviceId }, helpdesk)).status, 201);
  });

  it('runs of others are visible only through tasks in scope, filtered', async () => {
    const adminRun = await api('POST', `/jobs/${jobId}/run`);
    assert.equal(adminRun.body.counts.total, 2);
    const visible = (await api('GET', '/runs', undefined, helpdesk)).body.items.map((r: { id: string }) => r.id);
    assert.ok(visible.includes(adminRun.body.id));
    const tasks = (await api('GET', `/runs/${adminRun.body.id}/tasks`, undefined, helpdesk)).body.items;
    assert.deepEqual(tasks.map((t: { hostname: string }) => t.hostname), ['BUCH-PC-01'], 'tasks outside the scope are hidden');
    const allTasks = (await api('GET', `/runs/${adminRun.body.id}/tasks`)).body.items;
    const foreign = allTasks.find((t: { hostname: string }) => t.hostname === 'IT-SRV-01');
    assert.equal((await api('GET', `/tasks/${foreign.id}`, undefined, helpdesk)).status, 404);
    assert.equal((await api('POST', `/runs/${adminRun.body.id}/cancel`, undefined, helpdesk)).status, 403, "cannot cancel someone else's run");
    const mine = allTasks.find((t: { hostname: string }) => t.hostname === 'BUCH-PC-01');
    assert.equal((await api('POST', `/tasks/${mine.id}/cancel`, undefined, helpdesk)).status, 200, 'but a task on an own device');

    // a run that touches only foreign devices is invisible
    const itRun = await api('POST', `/jobs/${jobId}/run`, { deviceIds: [lin.deviceId] });
    assert.equal((await api('GET', `/runs/${itRun.body.id}`, undefined, helpdesk)).status, 404);
  });

  it('scopes via group role assignments; validation of scopes', async () => {
    const role = await api('POST', '/roles', { name: 'IT-Leser', permissions: ['devices:read'] });
    const g = await api('POST', '/groups', { name: 'IT-Team', roleAssignments: [{ roleId: role.body.id, scopeDeviceGroupIds: [groupB] }] });
    assert.equal(g.status, 201);
    assert.deepEqual(g.body.roles[0].scopeDeviceGroupIds, [groupB]);
    await api('POST', '/users', { username: 'it-user', password: 'it-user-password-1', groupIds: [g.body.id] });
    const tok = await login(ctx.app, 'it-user', 'it-user-password-1');
    assert.deepEqual((await api('GET', '/devices', undefined, tok)).body.items.map((d: { hostname: string }) => d.hostname), ['IT-SRV-01']);

    const bad = await api('POST', '/users', { username: 'x1', password: 'x-password-12', roleAssignments: [{ roleId: role.body.id, scopeDeviceGroupIds: ['6f9619ff-8b86-d011-b42d-00cf4fc964ff'] }] });
    assert.equal(bad.status, 400);
    const empty = await api('POST', '/users', { username: 'x2', password: 'x-password-12', roleAssignments: [{ roleId: role.body.id, scopeDeviceGroupIds: [] }] });
    assert.equal(empty.status, 400);
  });

  it('dynamic groups as scope follow the filter', async () => {
    const dyn = await api('POST', '/device-groups', { kind: 'dynamic', name: 'Alle Linux', filter: { rules: [{ field: 'os', op: 'eq', value: 'linux' }] } });
    const role = await api('POST', '/roles', { name: 'Linux-Leser', permissions: ['devices:read'] });
    await api('POST', '/users', { username: 'lx', password: 'lx-password-123', roleAssignments: [{ roleId: role.body.id, scopeDeviceGroupIds: [dyn.body.id] }] });
    const tok = await login(ctx.app, 'lx', 'lx-password-123');
    assert.deepEqual((await api('GET', '/devices', undefined, tok)).body.items.map((d: { hostname: string }) => d.hostname), ['IT-SRV-01']);
    await enrollOk(ctx, { hostname: 'NEW-LINUX', os: 'linux' });
    assert.equal((await api('GET', '/devices', undefined, tok)).body.total, 2, 'new matching device is in scope automatically');
  });
});

// ====================================================================== four-eyes

describe('M4: security settings', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;
  before(async () => {
    ctx = await setup();
    api = apiFor(ctx);
  });
  after(async () => ctx.close());

  it('are configurable at runtime (settings:update, audited)', async () => {
    const viewer = (await userWithGrants(ctx, 'settings-viewer', ['settings:read'])).token;
    assert.equal((await api('GET', '/settings/security', undefined, viewer)).body.mfaRequired, false);
    assert.equal((await api('PATCH', '/settings/security', { mfaRequired: false }, viewer)).status, 403);
    const s = await api('PATCH', '/settings/security', { mfaRequired: false, fourEyes: { enabled: true } });
    assert.equal(s.status, 200);
    assert.equal('fourEyes' in s.body, false, 'the removed four-eyes setting is ignored');
    const audit = (await api('GET', '/audit-log?action=settings.security_update')).body.items[0];
    assert.equal(audit.details.after.mfaRequired, false);
  });
});

// ====================================================================== MFA

describe('M4: MFA (TOTP)', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;
  let secret: string;
  const code = (offset = 0) => hotp(base32Decode(secret), counterAt(new Date()) + offset);

  before(async () => {
    ctx = await setup();
    api = apiFor(ctx);
  });
  after(async () => ctx.close());

  it('enrols with a confirmation code and returns recovery codes; secret is encrypted', async () => {
    const s = await api('POST', '/auth/mfa/setup');
    secret = s.body.secret;
    assert.match(s.body.otpauthUri, /^otpauth:\/\/totp\/OpenCM%3Aadmin\?secret=[A-Z2-7]+&issuer=OpenCM/);
    assert.equal((await api('POST', '/auth/mfa/enable', { code: '000000' })).status, 400);
    const en = await api('POST', '/auth/mfa/enable', { code: code() });
    assert.equal(en.status, 200);
    assert.equal(en.body.recoveryCodes.length, 10);
    const [u] = await ctx.handle.db.select().from(users).where(eq(users.username, 'admin'));
    assert.match(u!.mfaSecretEnc!, /^v1:/);
    assert.ok(!u!.mfaSecretEnc!.includes(secret));
    assert.equal(u!.mfaRecoveryHashes.length, 10);
    (globalThis as { __recovery?: string[] }).__recovery = en.body.recoveryCodes;
  });

  it('login requires the code; codes cannot be replayed; recovery codes work once', async () => {
    const noCode = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: ADMIN });
    assert.equal(noCode.statusCode, 401);
    assert.equal(noCode.json().error.code, 'mfa_required');
    const c = code(1); // enabling consumed the current step
    const ok = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { ...ADMIN, otp: c } });
    assert.equal(ok.statusCode, 200, ok.body);
    const replay = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { ...ADMIN, otp: c } });
    assert.equal(replay.json().error.code, 'invalid_otp');

    const rc = (globalThis as { __recovery?: string[] }).__recovery![0]!;
    const viaRecovery = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { ...ADMIN, otp: rc.toUpperCase() } });
    assert.equal(viaRecovery.statusCode, 200);
    const again = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { ...ADMIN, otp: rc } });
    assert.equal(again.statusCode, 401);
    assert.equal((await api('GET', '/auth/mfa')).body.recoveryCodesLeft, 9);
  });

  it('mandatory MFA: new users can only set up MFA first', async () => {
    await api('PATCH', '/settings/security', { mfaRequired: true });
    await userWithGrants(ctx, 'newbie', ['devices:read']).catch(() => {});
    const res = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: 'newbie', password: 'user-password-123' } });
    assert.equal(res.json().mfaSetupRequired, true);
    const tok = res.json().token;
    const blocked = await api('GET', '/devices', undefined, tok);
    assert.equal(blocked.status, 403);
    assert.equal(blocked.body.error.code, 'mfa_setup_required');
    assert.equal((await api('GET', '/auth/me', undefined, tok)).body.mfaSetupRequired, true);
    const s = (await api('POST', '/auth/mfa/setup', undefined, tok)).body;
    await api('POST', '/auth/mfa/enable', { code: hotp(base32Decode(s.secret), counterAt(new Date())) }, tok);
    assert.equal((await api('GET', '/devices', undefined, tok)).status, 200, 'session usable after setup');
    assert.equal((await api('POST', '/auth/mfa/disable', { code: hotp(base32Decode(s.secret), counterAt(new Date()) + 1) }, tok)).status, 409, 'cannot disable while mandatory');
    await api('PATCH', '/settings/security', { mfaRequired: false });
  });

  it('admins can reset MFA (ends sessions); users can disable with a code', async () => {
    const [newbie] = await ctx.handle.db.select().from(users).where(eq(users.username, 'newbie'));
    assert.equal((await api('POST', `/users/${newbie!.id}/mfa/reset`)).status, 204);
    const [after] = await ctx.handle.db.select().from(users).where(eq(users.id, newbie!.id));
    assert.equal(after!.mfaEnabled, false);
    assert.equal(after!.mfaSecretEnc, null);
    assert.equal((await api('POST', '/auth/mfa/disable', { code: code(-1) })).status, 400, 'old step already used');
    assert.equal((await api('POST', '/auth/mfa/disable', { code: code(2) })).status, 400, 'outside window');
  });
});

// ====================================================================== API tokens

describe('M4: API tokens', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;
  before(async () => {
    ctx = await setup();
    api = apiFor(ctx);
    await enrollOk(ctx, { hostname: 'T1', os: 'linux' });
  });
  after(async () => ctx.close());

  it('creates restricted tokens: effective rights = token ∩ owner', async () => {
    const t = await api('POST', '/api-tokens', { name: 'Monitoring', permissions: ['devices:read'], expiresInDays: 30 });
    assert.equal(t.status, 201);
    assert.match(t.body.token, /^oct_/);
    assert.equal((await api('GET', '/devices', undefined, t.body.token)).status, 200);
    assert.equal((await api('GET', '/users', undefined, t.body.token)).status, 403);
    assert.equal((await api('POST', '/api-tokens', { name: 'chain' }, t.body.token)).status, 403, 'tokens cannot mint tokens');
    const me = (await api('GET', '/auth/me', undefined, t.body.token)).body;
    assert.equal(me.via, 'token');
    assert.deepEqual(me.permissions, ['devices:read']);

    const list = (await api('GET', '/api-tokens')).body.items;
    assert.equal(list[0].name, 'Monitoring');
    assert.equal(list[0].tokenHash, undefined);
    assert.ok(list[0].lastUsedAt);

    const audit = (await api('GET', '/audit-log?action=api_token.create')).body.items[0];
    assert.equal(audit.details.name, 'Monitoring');
  });

  it('cannot exceed own rights; lifetime limited; scope of the owner applies', async () => {
    const reader = await userWithGrants(ctx, 'reader', ['devices:read']);
    assert.equal((await api('POST', '/api-tokens', { name: 'x', permissions: ['users:read'] }, reader.token)).status, 403);
    assert.equal((await api('POST', '/api-tokens', { name: 'x', expiresInDays: 5000 })).status, 400);
    const inherit = await api('POST', '/api-tokens', { name: 'inherit' }, reader.token);
    assert.deepEqual((await api('GET', '/auth/me', undefined, inherit.body.token)).body.permissions, ['devices:read']);
  });

  it('expired and revoked tokens stop working immediately; actions are attributed', async () => {
    const t = (await api('POST', '/api-tokens', { name: 'short' })).body;
    const created = await api('POST', '/device-groups', { kind: 'static', name: 'via-token', deviceIds: [] }, t.token);
    assert.equal(created.status, 201);
    const audit = (await api('GET', '/audit-log?action=device_group.create')).body.items[0];
    assert.equal(audit.actorType, 'api_token');
    assert.match(audit.actorName, /Token „short“/);

    await ctx.handle.db.update(apiTokens).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(apiTokens.id, t.id));
    assert.equal((await api('GET', '/devices', undefined, t.token)).status, 401);

    const t2 = (await api('POST', '/api-tokens', { name: 'revoke-me' })).body;
    assert.equal((await api('DELETE', `/api-tokens/${t2.id}`)).status, 204);
    assert.equal((await api('GET', '/devices', undefined, t2.token)).status, 401);
  });
});

// ====================================================================== LDAP

class FakeDirectory implements Directory {
  accounts = new Map<string, { password: string; user: DirectoryUser }>();
  calls: string[] = [];
  async authenticate(username: string, password: string) {
    this.calls.push(username);
    const a = this.accounts.get(username.toLowerCase());
    return a && password && a.password === password ? a.user : null;
  }
  async test(username?: string) {
    return { ok: true, message: 'Bind successful', user: username ? (this.accounts.get(username)?.user ?? null) : null };
  }
}

const ADMINS_DN = 'CN=OpenCM-Admins,OU=Groups,DC=corp,DC=example';

describe('M4: LDAP / Active Directory', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;
  const dir = new FakeDirectory();

  before(async () => {
    dir.accounts.set('jdoe', { password: 'Winter2026!', user: { dn: 'CN=John Doe,OU=Users,DC=corp,DC=example', username: 'jdoe', displayName: 'John Doe', email: 'jdoe@corp.example', groups: [ADMINS_DN.toLowerCase()] } });
    dir.accounts.set('ext', { password: 'Ext2026!', user: { dn: 'CN=Ext,OU=Users,DC=corp,DC=example', username: 'ext', displayName: 'Extern', email: null, groups: ['CN=Other,DC=corp,DC=example'] } });
    ctx = await setup({}, { directory: dir });
    api = apiFor(ctx);
    const role = await api('POST', '/roles', { name: 'AD-Helpdesk', permissions: ['devices:read'] });
    await api('POST', '/groups', { name: 'AD Admins', ldapGroup: ADMINS_DN, roleIds: [role.body.id] });
  });
  after(async () => ctx.close());

  it('escapes filter values (RFC 4515)', () => {
    assert.equal(ldapEscape('a*)(uid=*'), 'a\\2a\\29\\28uid=\\2a');
    assert.equal(ldapEscape('back\\slash\0'), 'back\\5cslash\\00');
    assert.equal(buildUserFilter('(&(objectClass=user)(sAMAccountName={username}))', '*)(|(cn=*'), '(&(objectClass=user)(sAMAccountName=\\2a\\29\\28|\\28cn=\\2a))');
  });

  it('logs in directory users, creates them and syncs mapped groups', async () => {
    const res = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: 'jdoe', password: 'Winter2026!' } });
    assert.equal(res.statusCode, 200, res.body);
    assert.deepEqual(res.json().user.permissions, ['devices:read']);
    assert.equal(res.json().user.authSource, 'ldap');
    const [u] = await ctx.handle.db.select().from(users).where(eq(users.username, 'jdoe'));
    assert.equal(u!.passwordHash, null);
    assert.equal(u!.displayName, 'John Doe');
    const audit = (await api('GET', '/audit-log?action=auth.login')).body.items[0];
    assert.equal(audit.details.method, 'ldap');
  });

  it('rejects wrong passwords and users without mapped group', async () => {
    const wrong = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: 'jdoe', password: 'nope' } });
    assert.equal(wrong.statusCode, 401);
    const ext = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: 'ext', password: 'Ext2026!' } });
    assert.equal(ext.statusCode, 401);
    assert.equal(ext.json().error.code, 'not_authorized');
    assert.equal((await ctx.handle.db.select().from(users).where(eq(users.username, 'ext'))).length, 0, 'no account created');
  });

  it('membership changes in AD are applied at the next login', async () => {
    dir.accounts.get('jdoe')!.user.groups = [];
    const res = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: 'jdoe', password: 'Winter2026!' } });
    assert.equal(res.statusCode, 401, 'no longer in a mapped group');
    dir.accounts.get('jdoe')!.user.groups = [ADMINS_DN];
  });

  it('local accounts stay local; directory users have no local password', async () => {
    dir.calls = [];
    const res = await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: ADMIN });
    assert.equal(res.statusCode, 200);
    assert.equal(dir.calls.length, 0, 'local admin never goes to the directory');
    const [u] = await ctx.handle.db.select().from(users).where(eq(users.username, 'jdoe'));
    assert.equal((await api('PATCH', `/users/${u!.id}`, { password: 'some-new-password' })).status, 409);
    const t = await api('POST', '/settings/ldap/test', { username: 'jdoe' });
    assert.equal(t.body.ok, true);
    assert.equal(t.body.user.displayName, 'John Doe');
  });
});

// ====================================================================== audit export

describe('M4: audit export', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;
  before(async () => {
    ctx = await setup();
    api = apiFor(ctx);
  });
  after(async () => ctx.close());

  it('exports CSV (BOM, ; separated, formula-safe) and JSON; export itself is audited', async () => {
    await ctx.app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username: '=HYPERLINK("x")', password: 'x' } });
    const csv = await ctx.app.inject({ method: 'GET', url: '/api/v1/audit-log/export?format=csv', headers: bearer(ctx.adminToken) });
    assert.equal(csv.statusCode, 200);
    assert.match(String(csv.headers['content-type']), /text\/csv/);
    assert.match(String(csv.headers['content-disposition']), /opencm-audit-.*\.csv/);
    assert.ok(csv.body.startsWith('\uFEFFid;at;actorType'));
    assert.ok(csv.body.includes(`"'=HYPERLINK(""x"")"`), 'formula neutralised');
    assert.ok(!/;"=HYPERLINK/.test(csv.body));

    const json = await api('GET', '/audit-log/export?format=json&action=auth.login_failed');
    assert.equal(json.body.items.length, 1);
    const log = (await api('GET', '/audit-log?action=audit.export')).body;
    assert.equal(log.total, 2);
    const reader = await userWithGrants(ctx, 'noaudit', ['devices:read']);
    assert.equal((await api('GET', '/audit-log/export', undefined, reader.token)).status, 403);
  });
});
