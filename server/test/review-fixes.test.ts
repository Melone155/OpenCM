// Regression tests for the findings of the internal security review (REV-001 … REV-005).
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { agentRequest, createEnrollmentToken, enroll, enrollOk, startAgentServer, type AgentServerHandle } from './agent-helpers.ts';
import { ADMIN, bearer, login, setup, userWithGrants, type TestCtx } from './helpers.ts';

type Method = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
const apiFor = (ctx: TestCtx) => async (method: Method, url: string, payload?: object, token = ctx.adminToken) => {
  const res = await ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(token), ...(payload && { payload }) });
  return { status: res.statusCode, body: res.body && res.headers['content-type']?.includes('json') ? res.json() : res.body };
};

describe('REV-001/002: user management cannot escalate privileges', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;
  let mgr: { userId: string; token: string };
  let viewer: { userId: string; token: string };
  let adminId: string;

  before(async () => {
    ctx = await setup();
    api = apiFor(ctx);
    mgr = await userWithGrants(ctx, 'usermgr', ['users:read', 'users:update', 'users:delete', 'groups:read', 'devices:read']);
    viewer = await userWithGrants(ctx, 'viewer', ['devices:read']);
    adminId = (await api('GET', '/auth/me')).body.id;
  });
  after(async () => ctx.close());

  it('REV-001: users:update cannot set the password of a user with more rights', async () => {
    const r = await api('PATCH', `/users/${adminId}`, { password: 'attacker-chosen-pw-1' }, mgr.token);
    assert.equal(r.status, 403);
    await assert.rejects(login(ctx.app, ADMIN.username, 'attacker-chosen-pw-1'));
    assert.equal((await api('GET', '/auth/me')).status, 200, 'admin session untouched');
  });

  it('REV-001: … nor deactivate or delete such a user', async () => {
    assert.equal((await api('PATCH', `/users/${adminId}`, { isActive: false }, mgr.token)).status, 403);
    assert.equal((await api('DELETE', `/users/${adminId}`, undefined, mgr.token)).status, 403);
    assert.equal((await api('GET', `/users/${adminId}`)).body.isActive, true);
  });

  it('REV-001: harmless fields and users with fewer rights can still be managed', async () => {
    assert.equal((await api('PATCH', `/users/${adminId}`, { displayName: 'Chef' }, mgr.token)).status, 200);
    assert.equal((await api('PATCH', `/users/${viewer.userId}`, { password: 'new-viewer-password-1' }, mgr.token)).status, 200);
    await login(ctx.app, 'viewer', 'new-viewer-password-1');
    // own password change stays possible
    assert.equal((await api('PATCH', `/users/${mgr.userId}`, { password: 'own-new-password-123' }, mgr.token)).status, 200);
  });

  it('REV-001: group membership cannot be used to obtain roles the actor does not hold', async () => {
    const adminRole = (await api('GET', '/roles')).body.items.find((r: { name: string }) => r.name === 'Administrator');
    const g = await api('POST', '/groups', { name: 'Admins', roleIds: [adminRole.id] });
    assert.equal(g.status, 201);
    const self = await api('PATCH', `/users/${mgr.userId}`, { groupIds: [g.body.id] }, mgr.token);
    assert.equal(self.status, 403);
    const other = await api('PATCH', `/users/${viewer.userId}`, { groupIds: [g.body.id] }, mgr.token);
    assert.equal(other.status, 403);
    assert.deepEqual((await api('GET', '/auth/me', undefined, mgr.token)).body.permissions.includes('*'), false);
  });

  it('REV-002: users:update cannot reset the MFA of a user with more rights', async () => {
    assert.equal((await api('POST', `/users/${adminId}/mfa/reset`, undefined, mgr.token)).status, 403);
    assert.equal((await api('GET', '/auth/me')).status, 200, 'admin session not ended');
    assert.equal((await api('POST', `/users/${viewer.userId}/mfa/reset`, undefined, mgr.token)).status, 204);
  });
});

describe('REV-003: rerun respects the four-eyes principle', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;

  before(async () => {
    ctx = await setup({ FOUR_EYES_ENABLED: 'true', FOUR_EYES_DEVICE_THRESHOLD: '2' });
    api = apiFor(ctx);
  });
  after(async () => ctx.close());

  it('a mass rerun needs approval by a second person; small reruns run directly', async () => {
    const devs = [await enrollOk(ctx, { hostname: 'A1', os: 'linux' }), await enrollOk(ctx, { hostname: 'A2', os: 'linux' }), await enrollOk(ctx, { hostname: 'A3', os: 'linux' })];
    const approver = (await userWithGrants(ctx, 'approver', ['jobs:read', 'jobs:approve'])).token;
    const s = await api('POST', '/scripts', { name: 'mass', interpreter: 'bash', content: 'echo 1' });
    await api('POST', `/scripts/${s.body.id}/versions/1/approve`);
    const steps = [{ scriptId: s.body.id }];

    const mass = (await api('POST', '/jobs', { name: 'mass-job', trigger: 'manual', targets: { deviceIds: devs.map((d) => d.deviceId) }, steps })).body;
    const req = await api('POST', `/jobs/${mass.id}/run`);
    const first = await api('POST', `/approvals/${req.body.approvalId}/approve`, {}, approver);
    const runId = first.body.result.runId;

    const again = await api('POST', `/runs/${runId}/rerun`, { onlyFailed: false });
    assert.equal(again.status, 202);
    assert.equal(again.body.approvalRequired, true);
    assert.equal(again.body.devices, 3);
    assert.equal((await api('GET', `/jobs/${mass.id}/runs`)).body.total, 1, 'nothing executed yet');
    assert.equal((await api('POST', `/approvals/${again.body.approvalId}/approve`, {})).status, 403, 'not your own request');
    const ok = await api('POST', `/approvals/${again.body.approvalId}/approve`, {}, approver);
    assert.equal(ok.body.status, 'approved');
    const rerun = await api('GET', `/runs/${ok.body.result.runId}`);
    assert.equal(rerun.body.trigger, 'rerun');
    assert.equal(rerun.body.counts.total, 3);

    const small = (await api('POST', '/jobs', { name: 'small-job', trigger: 'manual', targets: { deviceIds: [devs[0]!.deviceId] }, steps })).body;
    const run = await api('POST', `/jobs/${small.id}/run`);
    assert.equal(run.status, 201);
    assert.equal((await api('POST', `/runs/${run.body.id}/rerun`, { onlyFailed: false })).status, 201);
  });
});

describe('REV-004/005: enrollment cannot take over or reactivate a device', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;
  let agentSrv: AgentServerHandle;

  before(async () => {
    ctx = await setup();
    api = apiFor(ctx);
    agentSrv = await startAgentServer(ctx);
  });
  after(async () => {
    await agentSrv.close();
    await ctx.close();
  });

  const heartbeat = (a: { certPem: string; keyPem: string; caPem: string }) => agentRequest(agentSrv.port, '/agent/v1/heartbeat', { agentVersion: '1' }, a);

  it('REV-004: a second enrollment with the machineId of an existing device is rejected', async () => {
    const victim = await enrollOk(ctx, { machineId: 'machine-victim-0001', hostname: 'VICTIM' });
    const t = await createEnrollmentToken(ctx, { name: 'other-rollout', maxUses: 1 });
    const { res } = await enroll(ctx, t.token, { machineId: 'machine-victim-0001', hostname: 'ATTACKER' });
    assert.equal(res.statusCode, 409);
    assert.equal(res.json().error.code, 'device_already_enrolled');
    assert.equal((await heartbeat(victim)).status, 200, 'the real device keeps working');
    assert.equal((await api('GET', `/devices/${victim.deviceId}`)).body.hostname, 'VICTIM');
    const audit = (await api('GET', '/audit-log?action=device.enroll_rejected')).body;
    assert.ok(audit.items.some((e: { targetId: string }) => e.targetId === victim.deviceId));
    // the rejected attempt did not consume the single-use token
    assert.equal((await enroll(ctx, t.token, { machineId: 'machine-other-0002' })).res.statusCode, 200);
  });

  it('REV-005: a revoked device stays revoked', async () => {
    const dev = await enrollOk(ctx, { machineId: 'machine-revoked-0001', hostname: 'REVOKED' });
    assert.equal((await api('POST', `/devices/${dev.deviceId}/revoke`)).status, 200);
    const t = await createEnrollmentToken(ctx, { name: 'again' });
    const { res } = await enroll(ctx, t.token, { machineId: 'machine-revoked-0001' });
    assert.equal(res.statusCode, 409);
    assert.equal((await api('GET', `/devices/${dev.deviceId}`)).body.status, 'revoked');
    assert.equal((await heartbeat(dev)).status, 403);
  });

  it('after an administrator deleted the device the machine enrolls as a new device', async () => {
    const old = await enrollOk(ctx, { machineId: 'machine-reinstall-0001' });
    assert.equal((await api('DELETE', `/devices/${old.deviceId}`)).status, 204);
    const fresh = await enrollOk(ctx, { machineId: 'machine-reinstall-0001' });
    assert.notEqual(fresh.deviceId, old.deviceId);
    assert.equal((await heartbeat(fresh)).status, 200);
  });
});

// ---------------------------------------------------------------- REV-010 / REV-007 / REV-008

describe('REV-010: the task signing key is never regenerated silently', () => {
  it('creates the key only when it does not exist; an unreadable key aborts the start', async () => {
    const { mkdtempSync, readFileSync, writeFileSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { initSigner } = await import('../src/pki/signing.ts');
    const dir = mkdtempSync(join(tmpdir(), 'opencm-signer-'));
    const first = await initSigner(dir);
    assert.equal((await initSigner(dir)).publicKey, first.publicKey, 'existing key is reused');

    writeFileSync(join(dir, 'signing.key'), 'not a key');
    await assert.rejects(initSigner(dir), /signing\.key/);
    assert.equal(readFileSync(join(dir, 'signing.key'), 'utf8'), 'not a key', 'the damaged file is left for the operator, not overwritten');
  });
});

describe('REV-007: drafts can only be test-run by someone who may approve scripts', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;
  before(async () => {
    ctx = await setup();
    api = apiFor(ctx);
  });
  after(async () => ctx.close());

  it('scripts:execute alone runs approved versions only', async () => {
    const author = await userWithGrants(ctx, 'author', ['scripts:read', 'scripts:create', 'scripts:update', 'scripts:execute', 'devices:read']);
    const d = await enrollOk(ctx, { hostname: 'T1', os: 'linux' });
    const s = await api('POST', '/scripts', { name: 'draft-only', interpreter: 'bash', content: 'id' }, author.token);
    assert.equal(s.status, 201);
    const draft = await api('POST', `/scripts/${s.body.id}/versions/1/test`, { deviceId: d.deviceId }, author.token);
    assert.equal(draft.status, 403);
    assert.equal((await api('GET', '/runs', undefined, author.token)).body.total, 0, 'nothing was started');

    // an approver may test the draft, and once approved the author may test it too
    assert.equal((await api('POST', `/scripts/${s.body.id}/versions/1/test`, { deviceId: d.deviceId })).status, 201);
    assert.equal((await api('POST', `/scripts/${s.body.id}/versions/1/approve`)).status, 200);
    assert.equal((await api('POST', `/scripts/${s.body.id}/versions/1/test`, { deviceId: d.deviceId }, author.token)).status, 201);
  });
});

describe('REV-008: the four-eyes threshold cannot be undercut by splitting', () => {
  let ctx: TestCtx;
  let api: ReturnType<typeof apiFor>;
  before(async () => {
    ctx = await setup({ FOUR_EYES_ENABLED: 'true', FOUR_EYES_DEVICE_THRESHOLD: '3' });
    api = apiFor(ctx);
  });
  after(async () => ctx.close());

  it('devices of a user\'s recent runs count towards the threshold', async () => {
    const devs = [];
    for (const h of ['S1', 'S2', 'S3', 'S4']) devs.push(await enrollOk(ctx, { hostname: h, os: 'linux' }));
    const approver = (await userWithGrants(ctx, 'approver', ['jobs:read', 'jobs:approve'])).token;
    const s = await api('POST', '/scripts', { name: 'split', interpreter: 'bash', content: 'echo 1' });
    await api('POST', `/scripts/${s.body.id}/versions/1/approve`);
    const run = (deviceId: string) => api('POST', `/scripts/${s.body.id}/run`, { targets: { deviceIds: [deviceId] } });

    assert.equal((await run(devs[0]!.deviceId)).status, 201);
    assert.equal((await run(devs[0]!.deviceId)).status, 201, 'the same device again does not add up');
    assert.equal((await run(devs[1]!.deviceId)).status, 201);
    const third = await run(devs[2]!.deviceId);
    assert.equal(third.status, 202, 'third distinct device within the window reaches the threshold of 3');
    assert.equal(third.body.approvalRequired, true);

    // test runs are counted as well and have no approval path: refused
    const t = await api('POST', `/scripts/${s.body.id}/versions/1/test`, { deviceId: devs[3]!.deviceId });
    assert.equal(t.status, 409);
    assert.equal(t.body.error.code, 'four_eyes_limit');

    // approved runs do not count against the requester afterwards
    assert.equal((await api('POST', `/approvals/${third.body.approvalId}/approve`, {}, approver)).body.status, 'approved');
    assert.equal((await run(devs[0]!.deviceId)).status, 201);
  });

  it('script self-approval is off by default', async () => {
    const { loadConfig } = await import('../src/config.ts');
    assert.equal(loadConfig({}).SCRIPT_SELF_APPROVAL, false);
    assert.equal(loadConfig({}).FOUR_EYES_WINDOW_MINUTES, 60);
  });
});
