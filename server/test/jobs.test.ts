import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { eq, sql } from 'drizzle-orm';
import { jobs, scriptVersions, tasks } from '../src/db/schema.ts';
import { schedulerTick, type TaskPayload } from '../src/jobs/engine.ts';
import { updateMessage } from '../src/pki/signing.ts';
import { agentCall, enrollOk, sampleInventory, startAgentServer, type AgentServerHandle, type EnrolledAgent } from './agent-helpers.ts';
import { bearer, setup, userWithGrants, type TestCtx } from './helpers.ts';

type Method = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';

describe('M2: scripts, jobs, signed tasks', () => {
  let ctx: TestCtx;
  let srv: AgentServerHandle;
  let win: EnrolledAgent;
  let lin: EnrolledAgent;
  let mac: EnrolledAgent;

  before(async () => {
    ctx = await setup();
    srv = await startAgentServer(ctx);
    win = await enrollOk(ctx, { hostname: 'WIN-01', os: 'windows' });
    lin = await enrollOk(ctx, { hostname: 'LNX-01', os: 'linux' });
    mac = await enrollOk(ctx, { hostname: 'MAC-01', os: 'macos' });
  });
  after(async () => {
    await srv.close();
    await ctx.close();
  });

  const api = async (method: Method, url: string, payload?: object, token = ctx.adminToken) => {
    const res = await ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(token), ...(payload && { payload }) });
    return { status: res.statusCode, body: res.body ? res.json() : null };
  };
  const agent = (a: EnrolledAgent) => ({
    post: (path: string, body: unknown) => agentCall('POST', srv.port, `/agent/v1${path}`, body, a),
    get: (path: string) => agentCall('GET', srv.port, `/agent/v1${path}`, undefined, a),
  });

  const verifyEnvelope = (env: { payload: string; signature: string }): TaskPayload => {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(ctx.signer.publicKey, 'base64').toString('base64url') }, format: 'jwk' });
    const bytes = Buffer.from(env.payload, 'base64');
    assert.ok(verify(null, bytes, key, Buffer.from(env.signature, 'base64')), 'envelope signature must verify with the enrolment key');
    return JSON.parse(bytes.toString('utf8'));
  };

  let counter = 0;
  async function approvedScript(interpreter: string, content: string, parameters: object[] = []) {
    const s = await api('POST', '/scripts', { name: `script-${++counter}-${interpreter}`, interpreter, content, parameters });
    assert.equal(s.status, 201, JSON.stringify(s.body));
    const a = await api('POST', `/scripts/${s.body.id}/versions/1/approve`);
    assert.equal(a.status, 200);
    return s.body as { id: string; name: string };
  }

  async function createJob(body: Record<string, unknown>) {
    const res = await api('POST', '/jobs', { name: `job-${++counter}`, trigger: 'manual', ...body });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    return res.body as { id: string };
  }

  async function nextTask(a: EnrolledAgent, wait = 0) {
    const res = await agent(a).get(`/tasks/next?wait=${wait}`);
    if (res.status === 204) return null;
    assert.equal(res.status, 200, JSON.stringify(res.body));
    return verifyEnvelope(res.body);
  }

  // ------------------------------------------------------------ scripts

  it('creates scripts with versions; approved content is immutable', async () => {
    const s = await api('POST', '/scripts', {
      name: 'Disk cleanup',
      interpreter: 'powershell',
      content: 'Write-Output "v1"',
      parameters: [{ name: 'Days', type: 'number', required: true }],
    });
    assert.equal(s.status, 201);
    assert.equal(s.body.latestVersion, 1);
    assert.equal(s.body.approvedVersion, null);
    assert.equal(s.body.versions[0].status, 'draft');

    const v2 = await api('POST', `/scripts/${s.body.id}/versions`, { content: 'Write-Output "v2"', parameters: [], changeNote: 'simpler' });
    assert.equal(v2.body.version, 2);
    assert.equal(v2.body.sha256, createHash('sha256').update('Write-Output "v2"').digest('hex'));

    assert.equal((await api('POST', `/scripts/${s.body.id}/versions/1/approve`)).body.status, 'approved');
    assert.equal((await api('POST', `/scripts/${s.body.id}/versions/1/approve`)).status, 409);
    assert.equal((await api('GET', `/scripts/${s.body.id}`)).body.approvedVersion, 1);

    // DB trigger forbids changing content of any version
    const tamper = ctx.handle.db.update(scriptVersions).set({ content: 'evil' }).where(eq(scriptVersions.scriptId, s.body.id));
    await assert.rejects(tamper, (e: { cause?: unknown }) => /immutable/.test(String(e.cause ?? e)));

    const list = await api('GET', '/scripts?search=cleanup');
    assert.equal(list.body.items.length, 1);
    assert.equal(list.body.items[0].latestVersion, 2);
  });

  it('validates parameter definitions and interpreters', async () => {
    assert.equal((await api('POST', '/scripts', { name: 'bad1', interpreter: 'perl', content: 'x' })).status, 400);
    const dup = await api('POST', '/scripts', { name: 'bad2', interpreter: 'bash', content: 'x', parameters: [{ name: 'A', type: 'string' }, { name: 'a', type: 'string' }] });
    assert.equal(dup.status, 400);
    const badDefault = await api('POST', '/scripts', { name: 'bad3', interpreter: 'bash', content: 'x', parameters: [{ name: 'N', type: 'number', default: 'x' }] });
    assert.equal(badDefault.status, 400);
    const interp = await api('GET', '/interpreters');
    assert.deepEqual(interp.body.items.map((i: { name: string }) => i.name), ['powershell', 'cmd', 'bash', 'zsh', 'python']);
  });

  it('jobs only accept approved versions and valid parameters', async () => {
    const s = await api('POST', '/scripts', { name: 'draft-only', interpreter: 'bash', content: 'echo hi', parameters: [{ name: 'Mode', type: 'string', required: true }] });
    const draft = await api('POST', '/jobs', { name: 'j', trigger: 'manual', targets: { deviceIds: [lin.deviceId] }, steps: [{ scriptId: s.body.id }] });
    assert.equal(draft.status, 400);
    assert.equal(draft.body.error.code, 'script_not_approved');
    await api('POST', `/scripts/${s.body.id}/versions/1/approve`);
    const missing = await api('POST', '/jobs', { name: 'j', trigger: 'manual', targets: { deviceIds: [lin.deviceId] }, steps: [{ scriptId: s.body.id }] });
    assert.equal(missing.body.error.code, 'invalid_parameters');
    const wrongType = await api('POST', '/jobs', { name: 'j', trigger: 'manual', targets: { deviceIds: [lin.deviceId] }, steps: [{ scriptId: s.body.id, params: { Mode: 5 } }] });
    assert.equal(wrongType.body.error.code, 'invalid_parameters');
    const noTarget = await api('POST', '/jobs', { name: 'j', trigger: 'manual', targets: {}, steps: [{ scriptId: s.body.id, params: { Mode: 'x' } }] });
    assert.equal(noTarget.status, 400);
    const badCron = await api('POST', '/jobs', { name: 'j', trigger: 'cron', cron: '99 * * * *', targets: { allDevices: true }, steps: [{ scriptId: s.body.id, params: { Mode: 'x' } }] });
    assert.equal(badCron.status, 400);
    const badTz = await api('POST', '/jobs', { name: 'j', trigger: 'cron', cron: '0 3 * * *', timezone: 'Mars/Base', targets: { allDevices: true }, steps: [{ scriptId: s.body.id, params: { Mode: 'x' } }] });
    assert.equal(badTz.status, 400);
    const past = await api('POST', '/jobs', { name: 'j', trigger: 'once', runAt: '2000-01-01T00:00:00Z', targets: { allDevices: true }, steps: [{ scriptId: s.body.id, params: { Mode: 'x' } }] });
    assert.equal(past.status, 400);
  });

  // ------------------------------------------------------------ end-to-end execution

  it('runs a job: skip incompatible OS, long-poll, signed payload, live output, result', async () => {
    const s = await approvedScript('powershell', 'Write-Output "Hello $env:OPENCM_PARAM_NAME"', [{ name: 'Name', type: 'string', required: false, default: 'World' }]);
    const group = await api('POST', '/device-groups', { kind: 'static', name: 'Mixed', deviceIds: [win.deviceId, lin.deviceId] });
    assert.equal(group.status, 201);
    assert.equal(group.body.memberCount, 2);
    const job = await createJob({ targets: { groupIds: [group.body.id] }, steps: [{ scriptId: s.id, params: { Name: 'OpenCM' } }] });

    const run = await api('POST', `/jobs/${job.id}/run`);
    assert.equal(run.status, 201);
    assert.equal(run.body.counts.total, 2);
    assert.equal(run.body.counts.skipped, 1, 'powershell is skipped on linux');
    assert.equal(run.body.counts.pending, 1);
    assert.equal(run.body.steps[0].content, undefined, 'script content is not leaked in run summaries');

    assert.equal(await nextTask(lin), null, 'linux agent gets nothing');
    const payload = await nextTask(win);
    assert.ok(payload);
    assert.equal(payload.deviceId, win.deviceId);
    assert.equal(payload.steps[0]!.interpreter, 'powershell');
    assert.deepEqual(payload.steps[0]!.params, { Name: 'OpenCM' });
    assert.equal(payload.steps[0]!.sha256, createHash('sha256').update(payload.steps[0]!.content).digest('hex'));
    assert.ok(new Date(payload.expiresAt) > new Date());
    assert.equal(await nextTask(win), null, 'a task is only dispatched once');

    const tasksRes = await api('GET', `/runs/${run.body.id}/tasks`);
    const winTask = tasksRes.body.items.find((t: { hostname: string }) => t.hostname === 'WIN-01');
    assert.equal(winTask.status, 'dispatched');
    assert.match(tasksRes.body.items.find((t: { hostname: string }) => t.hostname === 'LNX-01').error, /not available on linux/);

    const w = agent(win);
    assert.deepEqual((await w.post(`/tasks/${payload.taskId}/start`, {})).body, { cancel: false });
    assert.equal((await w.post(`/tasks/${payload.taskId}/output`, { chunks: [{ stream: 'stdout', data: 'Hello ' }] })).status, 200);
    let out = await api('GET', `/tasks/${payload.taskId}/output`);
    assert.equal(out.body.status, 'running');
    assert.equal(out.body.done, false);
    const cursor = out.body.nextCursor;
    await w.post(`/tasks/${payload.taskId}/output`, { chunks: [{ stream: 'stdout', data: 'OpenCM\n' }, { stream: 'stderr', data: 'warn\n' }] });
    out = await api('GET', `/tasks/${payload.taskId}/output?after=${cursor}`);
    assert.deepEqual(out.body.items.map((i: { stream: string; data: string }) => `${i.stream}:${i.data}`), ['stdout:OpenCM\n', 'stderr:warn\n']);

    const res = await w.post(`/tasks/${payload.taskId}/result`, { status: 'succeeded', exitCode: 0, steps: [{ position: 0, status: 'succeeded', exitCode: 0, durationMs: 120 }] });
    assert.equal(res.status, 204);
    assert.equal((await w.post(`/tasks/${payload.taskId}/result`, { status: 'succeeded', exitCode: 0 })).status, 409, 'results are final');

    const task = await api('GET', `/tasks/${payload.taskId}`);
    assert.equal(task.body.status, 'succeeded');
    assert.equal(task.body.stepResults[0].durationMs, 120);
    const finalRun = await api('GET', `/runs/${run.body.id}`);
    assert.equal(finalRun.body.status, 'completed');
    assert.ok(finalRun.body.finishedAt);
    assert.equal((await api('GET', `/tasks/${payload.taskId}/output`)).body.done, true);
  });

  it('agents cannot touch tasks of other devices', async () => {
    const s = await approvedScript('bash', 'echo x');
    const job = await createJob({ targets: { deviceIds: [lin.deviceId] }, steps: [{ scriptId: s.id }] });
    await api('POST', `/jobs/${job.id}/run`);
    const p = await nextTask(lin);
    assert.ok(p);
    assert.equal((await agent(mac).post(`/tasks/${p.taskId}/output`, { chunks: [{ stream: 'stdout', data: 'pwn' }] })).status, 404);
    assert.equal((await agent(mac).post(`/tasks/${p.taskId}/result`, { status: 'succeeded', exitCode: 0 })).status, 404);
    await agent(lin).post(`/tasks/${p.taskId}/result`, { status: 'succeeded', exitCode: 0 });
  });

  it('long-poll waits and then delivers a task created meanwhile', async () => {
    const s = await approvedScript('zsh', 'echo poll');
    const job = await createJob({ targets: { deviceIds: [mac.deviceId] }, steps: [{ scriptId: s.id }] });
    const t0 = Date.now();
    const pending = nextTask(mac, 5);
    setTimeout(() => void api('POST', `/jobs/${job.id}/run`), 300);
    const p = await pending;
    assert.ok(p, 'task delivered during long poll');
    assert.ok(Date.now() - t0 < 4000, 'delivered promptly');
    await agent(mac).post(`/tasks/${p.taskId}/result`, { status: 'succeeded', exitCode: 0 });

    const t1 = Date.now();
    assert.equal(await nextTask(mac, 1), null);
    assert.ok(Date.now() - t1 >= 900, 'empty long poll waits');
  });

  it('retries failed tasks after the delay', async () => {
    const s = await approvedScript('bash', 'exit 1');
    const job = await createJob({ targets: { deviceIds: [lin.deviceId] }, steps: [{ scriptId: s.id }], options: { maxRetries: 1, retryDelaySeconds: 600 } });
    await api('POST', `/jobs/${job.id}/run`);
    const p1 = await nextTask(lin);
    assert.equal(p1!.attempt, 1);
    await agent(lin).post(`/tasks/${p1!.taskId}/result`, { status: 'failed', exitCode: 1, steps: [{ position: 0, status: 'failed', exitCode: 1, durationMs: 5 }] });
    let t = await api('GET', `/tasks/${p1!.taskId}`);
    assert.equal(t.body.status, 'pending');
    assert.equal(t.body.attempt, 2);
    assert.equal(await nextTask(lin), null, 'not before retry delay');
    await ctx.handle.db.update(tasks).set({ notBefore: new Date(Date.now() - 1000) }).where(eq(tasks.id, p1!.taskId));
    const p2 = await nextTask(lin);
    assert.equal(p2!.attempt, 2);
    await agent(lin).post(`/tasks/${p2!.taskId}/result`, { status: 'failed', exitCode: 2 });
    t = await api('GET', `/tasks/${p1!.taskId}`);
    assert.equal(t.body.status, 'failed');
    assert.equal(t.body.exitCode, 2);
    const out = await api('GET', `/tasks/${p1!.taskId}/output`);
    assert.ok(out.body.items.some((i: { stream: string; data: string }) => i.stream === 'system' && /retrying/.test(i.data)));
  });

  it('scheduler times out vanished agents', async () => {
    const s = await approvedScript('bash', 'sleep 999');
    const job = await createJob({ targets: { deviceIds: [lin.deviceId] }, steps: [{ scriptId: s.id }], options: { timeoutSeconds: 60 } });
    await api('POST', `/jobs/${job.id}/run`);
    const p = await nextTask(lin);
    const r1 = await schedulerTick(ctx.handle.db, ctx.config, new Date(Date.now() + 30_000));
    assert.equal(r1.timedOut, 0);
    const r2 = await schedulerTick(ctx.handle.db, ctx.config, new Date(Date.now() + (60 + ctx.config.TASK_TIMEOUT_GRACE_SECONDS + 5) * 1000));
    assert.equal(r2.timedOut, 1);
    assert.equal((await api('GET', `/tasks/${p!.taskId}`)).body.status, 'timeout');
    assert.equal((await agent(lin).post(`/tasks/${p!.taskId}/result`, { status: 'succeeded', exitCode: 0 })).status, 409);
  });

  it('cancels pending and running tasks; agent learns about it via output response', async () => {
    const s = await approvedScript('python', 'import time; time.sleep(60)');
    const job = await createJob({ targets: { deviceIds: [win.deviceId, lin.deviceId] }, steps: [{ scriptId: s.id }] });
    const run = await api('POST', `/jobs/${job.id}/run`);
    const p = await nextTask(win);
    await agent(win).post(`/tasks/${p!.taskId}/start`, {});
    const c = await api('POST', `/runs/${run.body.id}/cancel`);
    assert.equal(c.body.status, 'cancelled');
    const ts = (await api('GET', `/runs/${run.body.id}/tasks`)).body.items;
    assert.equal(ts.find((t: { hostname: string }) => t.hostname === 'LNX-01').status, 'cancelled');
    const running = ts.find((t: { hostname: string }) => t.hostname === 'WIN-01');
    assert.equal(running.cancelRequested, true);
    assert.deepEqual((await agent(win).post(`/tasks/${p!.taskId}/output`, { chunks: [{ stream: 'stdout', data: '.' }] })).body, { cancel: true });
    await agent(win).post(`/tasks/${p!.taskId}/result`, { status: 'cancelled', exitCode: null });
    assert.equal((await api('GET', `/tasks/${p!.taskId}`)).body.status, 'cancelled');
    const done = await api('GET', `/runs/${run.body.id}`);
    assert.equal(done.body.status, 'cancelled');
    assert.ok(done.body.finishedAt);
  });

  it('reruns only failed devices', async () => {
    const s = await approvedScript('python', 'print(1)');
    const job = await createJob({ targets: { deviceIds: [win.deviceId, lin.deviceId] }, steps: [{ scriptId: s.id }] });
    const run = await api('POST', `/jobs/${job.id}/run`);
    const pw = await nextTask(win);
    const pl = await nextTask(lin);
    await agent(win).post(`/tasks/${pw!.taskId}/result`, { status: 'succeeded', exitCode: 0 });
    await agent(lin).post(`/tasks/${pl!.taskId}/result`, { status: 'failed', exitCode: 3 });
    const again = await api('POST', `/runs/${run.body.id}/rerun`, { onlyFailed: true });
    assert.equal(again.status, 201);
    assert.equal(again.body.trigger, 'rerun');
    assert.equal(again.body.counts.total, 1);
    const p = await nextTask(lin);
    assert.equal(p!.runId, again.body.id);
    await agent(lin).post(`/tasks/${p!.taskId}/result`, { status: 'succeeded', exitCode: 0 });
  });

  it('stores script output in a custom field and filters dynamic groups by it', async () => {
    const field = await api('POST', '/custom-fields', { name: 'disk_free_gb', label: 'Freier Speicher (GB)', type: 'number' });
    assert.equal(field.status, 201);
    const s = await approvedScript('bash', 'df ...');
    const job = await createJob({ targets: { deviceIds: [lin.deviceId] }, steps: [{ scriptId: s.id, customFieldId: field.body.id }] });
    await api('POST', `/jobs/${job.id}/run`);
    const p = await nextTask(lin);
    assert.equal(p!.steps[0]!.captureOutput, true);
    await agent(lin).post(`/tasks/${p!.taskId}/result`, {
      status: 'succeeded',
      exitCode: 0,
      steps: [{ position: 0, status: 'succeeded', exitCode: 0, durationMs: 1, stdoutTail: 'measuring...\n  42.5  \n\n' }],
    });
    const values = await api('GET', `/devices/${lin.deviceId}/custom-fields`);
    const v = values.body.items.find((i: { name: string }) => i.name === 'disk_free_gb');
    assert.equal(v.value, '42.5');
    assert.equal(v.source, 'script');

    // manual value with type validation
    assert.equal((await api('PUT', `/devices/${win.deviceId}/custom-fields/${field.body.id}`, { value: 'viel' })).status, 400);
    assert.equal((await api('PUT', `/devices/${win.deviceId}/custom-fields/${field.body.id}`, { value: 7 })).body.value, '7');

    const preview = await api('POST', '/device-groups/preview', { filter: { rules: [{ field: 'custom:disk_free_gb', op: 'lt', value: 10 }] } });
    assert.deepEqual(preview.body.items.map((d: { hostname: string }) => d.hostname), ['WIN-01']);
  });

  it('dynamic groups: OS, software and combined rules', async () => {
    const { ingestInventory } = await import('../src/inventory/ingest.ts');
    const { InventorySchema } = await import('../src/inventory/schema.ts');
    await ingestInventory(ctx.handle.db, lin.deviceId, InventorySchema.parse(sampleInventory({ software: [{ name: 'openssl', version: '3.0.2', source: 'dpkg' }] })));

    const g = await api('POST', '/device-groups', {
      kind: 'dynamic',
      name: 'Linux mit OpenSSL',
      filter: { match: 'all', rules: [{ field: 'os', op: 'eq', value: 'LINUX' }, { field: 'software', op: 'installed', value: 'openssl' }] },
    });
    assert.equal(g.status, 201);
    assert.equal(g.body.memberCount, 1);
    const members = await api('GET', `/device-groups/${g.body.id}/devices`);
    assert.deepEqual(members.body.items.map((d: { hostname: string }) => d.hostname), ['LNX-01']);

    const any = await api('POST', '/device-groups/preview', { filter: { match: 'any', rules: [{ field: 'os', op: 'in', value: ['macos', 'windows'] }] } });
    assert.deepEqual(any.body.items.map((d: { hostname: string }) => d.hostname).sort(), ['MAC-01', 'WIN-01']);

    const bad = await api('POST', '/device-groups', { kind: 'dynamic', name: 'bad', filter: { rules: [{ field: 'hostname', op: 'gt', value: 5 }] } });
    assert.equal(bad.status, 400);
    const injection = await api('POST', '/device-groups/preview', { filter: { rules: [{ field: "hostname'; drop table devices;--", op: 'eq', value: 'x' }] } });
    assert.equal(injection.status, 400);
    assert.equal((await api('PUT', `/device-groups/${g.body.id}/members`, { deviceIds: [] })).status, 409, 'dynamic groups have no manual members');

    // groups targeted by jobs cannot be deleted
    const s = await approvedScript('bash', 'true');
    await createJob({ targets: { groupIds: [g.body.id] }, steps: [{ scriptId: s.id }] });
    assert.equal((await api('DELETE', `/device-groups/${g.body.id}`)).status, 409);
  });

  // ------------------------------------------------------------ schedules & triggers

  it('cron jobs run once per occurrence, even with concurrent ticks', async () => {
    const s = await approvedScript('bash', 'echo cron');
    const job = await api('POST', '/jobs', { name: 'nightly', trigger: 'cron', cron: '0 3 * * *', timezone: 'Europe/Berlin', targets: { deviceIds: [lin.deviceId] }, steps: [{ scriptId: s.id }] });
    assert.equal(job.status, 201);
    const next = new Date(job.body.nextRunAt);
    assert.equal(next.getUTCMinutes(), 0);
    assert.ok([1, 2].includes(next.getUTCHours()), '03:00 Berlin is 01:00 or 02:00 UTC');

    const at = new Date(next.getTime() + 1000);
    const [a, b] = await Promise.all([schedulerTick(ctx.handle.db, ctx.config, at), schedulerTick(ctx.handle.db, ctx.config, at)]);
    assert.equal(a.startedRuns + b.startedRuns, 1);
    const after1 = await api('GET', `/jobs/${job.body.id}`);
    assert.equal(new Date(after1.body.nextRunAt).getTime() - next.getTime(), 86_400_000);
    assert.equal(after1.body.lastRun.trigger, 'cron');
    const p = await nextTask(lin);
    await agent(lin).post(`/tasks/${p!.taskId}/result`, { status: 'succeeded', exitCode: 0 });

    // disabled jobs do not run; PATCH leaves other fields untouched
    const patched = await api('PATCH', `/jobs/${job.body.id}`, { enabled: false });
    assert.equal(patched.status, 200, JSON.stringify(patched.body));
    assert.equal(patched.body.cron, '0 3 * * *');
    assert.equal(patched.body.timezone, 'Europe/Berlin');
    await ctx.handle.db.update(jobs).set({ nextRunAt: new Date(Date.now() - 1000) }).where(eq(jobs.id, job.body.id));
    assert.equal((await schedulerTick(ctx.handle.db, ctx.config)).startedRuns, 0);
  });

  it('agent_start and user_login triggers fire from the heartbeat', async () => {
    const s = await approvedScript('powershell', 'Write-Output login');
    const startJob = await createJob({ trigger: 'agent_start', targets: { deviceIds: [win.deviceId] }, steps: [{ scriptId: s.id }] });
    const loginJob = await createJob({ trigger: 'user_login', targets: { allDevices: true }, steps: [{ scriptId: s.id }] });
    const runsOf = async (id: string) => (await api('GET', `/jobs/${id}/runs`)).body.total as number;

    await agent(win).post('/heartbeat', { agentVersion: '1', agentStarted: true, loggedOnUsers: [] });
    assert.equal(await runsOf(startJob.id), 1);
    await agent(win).post('/heartbeat', { agentVersion: '1' });
    assert.equal(await runsOf(startJob.id), 1, 'only on start');

    await agent(win).post('/heartbeat', { agentVersion: '1', loggedOnUsers: ['CONTOSO\\anna'] });
    assert.equal(await runsOf(loginJob.id), 1);
    await agent(win).post('/heartbeat', { agentVersion: '1', loggedOnUsers: ['CONTOSO\\anna'] });
    assert.equal(await runsOf(loginJob.id), 1, 'same session does not fire again');
    await agent(win).post('/heartbeat', { agentVersion: '1', loggedOnUsers: ['Anna'] });
    assert.equal(await runsOf(loginJob.id), 1, 'quser format (no domain, other case) is the same user');
    await agent(win).post('/heartbeat', { agentVersion: '1', loggedOnUsers: ['CONTOSO\\anna', 'CONTOSO\\ben'] });
    assert.equal(await runsOf(loginJob.id), 2, 'new user fires');

    // drain
    for (let p = await nextTask(win); p; p = await nextTask(win)) await agent(win).post(`/tasks/${p.taskId}/result`, { status: 'succeeded', exitCode: 0 });
  });

  it('maintenance windows hold tasks back', async () => {
    const s = await approvedScript('bash', 'echo later');
    const now = new Date();
    const hh = (h: number) => String(h).padStart(2, '0');
    const start = `${hh((now.getUTCHours() + 2) % 24)}:00`;
    const end = `${hh((now.getUTCHours() + 3) % 24)}:00`;
    const job = await createJob({
      targets: { deviceIds: [lin.deviceId] },
      steps: [{ scriptId: s.id }],
      options: { maintenanceWindow: { days: [0, 1, 2, 3, 4, 5, 6], start, end } },
    });
    await api('POST', `/jobs/${job.id}/run`);
    assert.equal(await nextTask(lin), null, 'outside maintenance window');
    await api('PATCH', `/jobs/${job.id}`, { options: { maintenanceWindow: null } });
    assert.equal(await nextTask(lin), null, 'runs keep the options snapshot they were created with');
    await ctx.handle.db.execute(sql`update job_runs set options = options || '{"maintenanceWindow":null}'::jsonb where job_id = ${job.id}`);
    const p = await nextTask(lin);
    assert.ok(p);
    await agent(lin).post(`/tasks/${p.taskId}/result`, { status: 'succeeded', exitCode: 0 });
  });

  // ------------------------------------------------------------ permissions & test runs

  it('test runs: drafts need scripts:approve, approved versions scripts:execute; jobs need jobs:execute', async () => {
    const tester = await userWithGrants(ctx, 'tester', ['scripts:read', 'scripts:create', 'scripts:update', 'scripts:execute', 'devices:read']);
    const s = await api('POST', '/scripts', { name: 'tester-script', interpreter: 'bash', content: 'echo test' }, tester.token);
    assert.equal(s.status, 201);
    assert.equal((await api('POST', `/scripts/${s.body.id}/versions/1/approve`, {}, tester.token)).status, 403, 'scripts:approve required');
    // REV-007: a draft is unreviewed code – not runnable with scripts:execute alone
    assert.equal((await api('POST', `/scripts/${s.body.id}/versions/1/test`, { deviceId: lin.deviceId }, tester.token)).status, 403);
    assert.equal((await api('POST', `/scripts/${s.body.id}/versions/1/approve`)).status, 200);
    const incompatible = await api('POST', `/scripts/${s.body.id}/versions/1/test`, { deviceId: win.deviceId }, tester.token);
    assert.equal(incompatible.body.error.code, 'incompatible_device');
    const run = await api('POST', `/scripts/${s.body.id}/versions/1/test`, { deviceId: lin.deviceId }, tester.token);
    assert.equal(run.status, 201);
    assert.equal(run.body.trigger, 'test');
    assert.equal((await api('GET', `/runs/${run.body.id}`, undefined, tester.token)).status, 200, 'testers see their runs');
    assert.equal((await api('GET', '/jobs', undefined, tester.token)).status, 403);
    const p = await nextTask(lin);
    assert.equal(p!.runId, run.body.id);
    await agent(lin).post(`/tasks/${p!.taskId}/result`, { status: 'succeeded', exitCode: 0 });

    const viewer = await userWithGrants(ctx, 'jobviewer', ['jobs:read']);
    const anyJob = (await api('GET', '/jobs')).body.items[0];
    assert.equal((await api('POST', `/jobs/${anyJob.id}/run`, {}, viewer.token)).status, 403);
    assert.equal((await api('POST', '/jobs', { name: 'x', trigger: 'manual', targets: { allDevices: true }, steps: [] }, viewer.token)).status, 403);
  });

  it('ad-hoc runs of approved scripts on groups (CLI: scripts run --target group:X)', async () => {
    const s = await approvedScript('python', 'print("adhoc")');
    const g = await api('POST', '/device-groups', { kind: 'static', name: 'AdHoc-Ziel', deviceIds: [lin.deviceId, mac.deviceId] });
    const run = await api('POST', `/scripts/${s.id}/run`, { targets: { groupIds: [g.body.id] } });
    assert.equal(run.status, 201, JSON.stringify(run.body));
    assert.equal(run.body.jobId, null);
    assert.equal(run.body.counts.total, 2);
    assert.match(run.body.name, /^Ad-hoc: /);
    for (const a of [lin, mac]) {
      const p = await nextTask(a);
      assert.equal(p!.runId, run.body.id);
      await agent(a).post(`/tasks/${p!.taskId}/result`, { status: 'succeeded', exitCode: 0 });
    }
    assert.equal((await api('GET', `/runs/${run.body.id}`)).body.status, 'completed');

    const draft = await api('POST', '/scripts', { name: 'adhoc-draft', interpreter: 'bash', content: 'echo' });
    assert.equal((await api('POST', `/scripts/${draft.body.id}/run`, { targets: { allDevices: true } })).status, 400, 'drafts only via test run');
    const noExec = await userWithGrants(ctx, 'noexec', ['scripts:read', 'scripts:execute']);
    assert.equal((await api('POST', `/scripts/${s.id}/run`, { targets: { allDevices: true } }, noExec.token)).status, 403);
  });

  it('scripts used by jobs cannot be deleted; retired versions stop jobs', async () => {
    const s = await approvedScript('bash', 'echo keep');
    const job = await createJob({ targets: { deviceIds: [lin.deviceId] }, steps: [{ scriptId: s.id }] });
    assert.equal((await api('DELETE', `/scripts/${s.id}`)).status, 409);
    await api('POST', `/scripts/${s.id}/versions/1/retire`);
    const run = await api('POST', `/jobs/${job.id}/run`);
    assert.equal(run.status, 409);
    assert.equal(run.body.error.code, 'script_not_approved');
    await api('DELETE', `/jobs/${job.id}`);
    assert.equal((await api('DELETE', `/scripts/${s.id}`)).status, 204);
  });

  it('audits script approval and job runs', async () => {
    const log = await api('GET', '/audit-log?limit=500');
    const actions = new Set(log.body.items.map((e: { action: string }) => e.action));
    for (const a of ['script.create', 'script.version_approve', 'job.create', 'job.run', 'run.cancel', 'script.test_run']) assert.ok(actions.has(a), a);
  });

  // ------------------------------------------------------------ agent self-update

  it('offers signed agent updates and serves the binary over mTLS', async () => {
    mkdirSync(ctx.config.AGENT_DOWNLOAD_DIR, { recursive: true });
    writeFileSync(join(ctx.config.AGENT_DOWNLOAD_DIR, 'opencm-agent-windows-amd64.exe'), 'NEW-AGENT-BINARY');
    writeFileSync(join(ctx.config.AGENT_DOWNLOAD_DIR, 'version.txt'), '0.3.0');
    const hb = await agent(win).post('/heartbeat', { agentVersion: '0.2.0' });
    const u = hb.body.update;
    assert.equal(u.version, '0.3.0');
    assert.equal(u.sha256, createHash('sha256').update('NEW-AGENT-BINARY').digest('hex'));
    assert.ok(ctx.signer.verify(updateMessage('windows', 'amd64', '0.3.0', u.sha256), u.signature));
    assert.equal((await agent(win).post('/heartbeat', { agentVersion: '0.3.0' })).body.update, null, 'up to date');
    assert.equal((await agent(win).post('/heartbeat', { agentVersion: 'dev' })).body.update, null, 'dev builds never auto-update');
    assert.equal((await agent(lin).post('/heartbeat', { agentVersion: '0.2.0' })).body.update, null, 'no linux binary');
    const dl = await agent(win).get('/update/download');
    assert.equal(dl.status, 200);
    assert.equal(dl.raw.toString(), 'NEW-AGENT-BINARY');
    const key = await agent(win).get('/signing-key');
    assert.equal(key.body.publicKey, ctx.signer.publicKey);
  });
});

describe('M2: limits and self-approval policy', () => {
  let ctx: TestCtx;
  let srv: AgentServerHandle;
  before(async () => {
    ctx = await setup({ SCRIPT_SELF_APPROVAL: 'false', TASK_OUTPUT_MAX_BYTES: '1024' });
    srv = await startAgentServer(ctx);
  });
  after(async () => {
    await srv.close();
    await ctx.close();
  });

  it('forbids approving own versions when self-approval is disabled', async () => {
    const s = await ctx.app.inject({ method: 'POST', url: '/api/v1/scripts', headers: bearer(ctx.adminToken), payload: { name: 'own', interpreter: 'bash', content: 'echo' } });
    const res = await ctx.app.inject({ method: 'POST', url: `/api/v1/scripts/${s.json().id}/versions/1/approve`, headers: bearer(ctx.adminToken) });
    assert.equal(res.statusCode, 403);
    const approver = await userWithGrants(ctx, 'approver', ['scripts:read', 'scripts:approve']);
    const ok = await ctx.app.inject({ method: 'POST', url: `/api/v1/scripts/${s.json().id}/versions/1/approve`, headers: bearer(approver.token) });
    assert.equal(ok.statusCode, 200);
  });

  it('truncates task output at TASK_OUTPUT_MAX_BYTES', async () => {
    const a = await enrollOk(ctx, { os: 'linux', hostname: 'L' });
    const s = await ctx.app.inject({ method: 'POST', url: '/api/v1/scripts', headers: bearer(ctx.adminToken), payload: { name: 'noisy', interpreter: 'bash', content: 'yes' } });
    const run = await ctx.app.inject({ method: 'POST', url: `/api/v1/scripts/${s.json().id}/versions/1/test`, headers: bearer(ctx.adminToken), payload: { deviceId: a.deviceId } });
    assert.equal(run.statusCode, 201);
    const next = await agentCall('GET', srv.port, '/agent/v1/tasks/next', undefined, a);
    const taskId = JSON.parse(Buffer.from(next.body.payload, 'base64').toString()).taskId;
    for (let i = 0; i < 3; i++) await agentCall('POST', srv.port, `/agent/v1/tasks/${taskId}/output`, { chunks: [{ stream: 'stdout', data: 'x'.repeat(600) }] }, a);
    const out = await ctx.app.inject({ method: 'GET', url: `/api/v1/tasks/${taskId}/output`, headers: bearer(ctx.adminToken) });
    const stored = out.json().items.filter((i: { stream: string }) => i.stream === 'stdout').reduce((n: number, i: { data: string }) => n + i.data.length, 0);
    assert.equal(stored, 1024);
    assert.ok(out.json().items.some((i: { data: string }) => /truncated/.test(i.data)));
    const t = await ctx.app.inject({ method: 'GET', url: `/api/v1/tasks/${taskId}`, headers: bearer(ctx.adminToken) });
    assert.equal(t.json().outputTruncated, true);
  });
});
