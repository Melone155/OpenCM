import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { buffer } from 'node:stream/consumers';
import { after, before, describe, it } from 'node:test';
import { eq } from 'drizzle-orm';
import { packageFiles, packageVersions } from '../src/db/schema.ts';
import type { TaskPayload } from '../src/jobs/engine.ts';
import { deploymentTick } from '../src/packages/deploy.ts';
import { detectFromInventory } from '../src/packages/detect.ts';
import { globToRegex, packageScript, psq, shq, splitArgs, validateAction, validatePackageVersion, type PackageVersionInput } from '../src/packages/generate.ts';
import { throttle, TokenBucket, type Clock } from '../src/packages/throttle.ts';
import { parsePatchOutput } from '../src/patches/ingest.ts';
import { patchScanTick } from '../src/patches/scan.ts';
import { PATCH_BEGIN, PATCH_END } from '../src/patches/scripts.ts';
import { agentCall, enrollOk, sampleInventory, startAgentServer, type AgentServerHandle, type EnrolledAgent } from './agent-helpers.ts';
import { bearer, setup, userWithGrants, type TestCtx } from './helpers.ts';

type Method = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';

const base: PackageVersionInput = {
  type: 'msi',
  fileSha256: 'a'.repeat(64),
  fileName: 'setup.msi',
  packageRef: null,
  installArgs: '',
  installCommand: '',
  uninstallCommand: '',
  productCode: null,
  detection: [],
  successCodes: [0],
  rebootCodes: [3010, 1641],
};
const pkg = { id: 'p', name: 'Demo', platform: 'windows' as const };

const scanOutput = (lines: string[]) => `noise before\n${PATCH_BEGIN}\n${lines.join('\n')}\n${PATCH_END}\ntrailing\n`;

describe('M5 units: generator, detection, parser, throttling', () => {
  it('quotes values safely for PowerShell and POSIX shells', () => {
    assert.equal(psq("it's"), "'it''s'");
    assert.equal(psq('typo\u2019graphic'), "'typo\u2019\u2019graphic'", 'PowerShell also ends strings at typographic quotes');
    assert.equal(shq("it's"), `'it'\\''s'`);
    assert.deepEqual(splitArgs(`/S /D="C:\\Program Files\\X" 'a b'  --x=1`), ['/S', '/D=C:\\Program Files\\X', 'a b', '--x=1']);
    assert.deepEqual(splitArgs(''), []);
  });

  it('turns globs into anchored regexes with escaped metacharacters', () => {
    const re = new RegExp(globToRegex('Mozilla Firefox (x64*'), 'i');
    assert.ok(re.test('Mozilla Firefox (x64 de)'));
    assert.ok(!re.test('Firefox (x64)'));
    assert.ok(!re.test('Mozilla Firefox x64'));
    assert.equal(globToRegex('a?b.c'), '^a.b\\.c$');
  });

  it('detects packages from the inventory (glob + version operator)', () => {
    const sw = [{ name: 'Notepad++ (64-bit x64)', version: '8.6.4' }];
    assert.equal(detectFromInventory([{ type: 'software', name: 'Notepad++*' }], sw), true);
    assert.equal(detectFromInventory([{ type: 'software', name: 'Notepad++*', version: '8.6', operator: 'gte' }], sw), true);
    assert.equal(detectFromInventory([{ type: 'software', name: 'Notepad++*', version: '8.7' }], sw), false);
    assert.equal(detectFromInventory([{ type: 'software', name: 'Notepad++*', version: '8.7', operator: 'lt' }], sw), true);
    assert.equal(detectFromInventory([{ type: 'software', name: 'Notepad++*', version: '8.6.4', operator: 'eq' }], sw), true);
    assert.equal(detectFromInventory([{ type: 'file', path: 'C:\\x' }], sw), null, 'file rules cannot be checked from the inventory');
  });

  it('validates package definitions', () => {
    assert.deepEqual(validatePackageVersion('windows', base), []);
    assert.ok(validatePackageVersion('linux', base).some((e) => /nur für windows/.test(e)));
    assert.ok(validatePackageVersion('windows', { ...base, fileSha256: null }, { requireFile: true }).some((e) => /Installationsdatei/.test(e)));
    const inj = validatePackageVersion('linux', { ...base, type: 'apt', fileSha256: null, packageRef: 'htop; rm -rf /' });
    assert.ok(inj.some((e) => /unzulässige Zeichen/.test(e)));
    assert.ok(validatePackageVersion('linux', { ...base, type: 'apt', fileSha256: null, packageRef: 'htop', detection: [{ type: 'registry', key: 'HKLM\\X' }] }).length);
    assert.ok(validatePackageVersion('windows', { ...base, productCode: 'not-a-guid' }).length);
    assert.deepEqual(validateAction({ ...base, type: 'exe' }, 'uninstall'), ['Für exe ist ein Deinstallationsbefehl nötig']);
    assert.deepEqual(validateAction({ ...base, type: 'msi' }, 'uninstall'), []);
  });

  it('generates install/uninstall scripts per type with embedded literals', () => {
    const msi = packageScript(pkg, '1.0', { ...base, installArgs: `INSTALLDIR="C:\\it's"`, detection: [{ type: 'software', name: 'Demo*', version: '1.0' }] }, 'install');
    assert.match(msi, /msiexec\.exe/);
    assert.ok(msi.includes(`'INSTALLDIR="C:\\it''s"'`), 'arguments are a single-quoted literal');
    assert.match(msi, /if \(Test-OpenCMDetected\) \{ Write-Output 'OpenCM: bereits installiert/);
    assert.match(msi, /Nach der Installation nicht erkannt/);
    assert.match(msi, /\$OpenCMReboot = @\(3010, 1641\)/);

    const msiX = packageScript(pkg, '1.0', { ...base, productCode: '{12345678-1234-1234-1234-123456789ABC}' }, 'uninstall');
    assert.match(msiX, /'\/x ' \+ '\{12345678-1234-1234-1234-123456789ABC\}'/);
    assert.ok(!msiX.includes('OPENCM_FILE_1'), 'uninstall by product code needs no file');

    const winget = packageScript(pkg, '1', { ...base, type: 'winget', fileSha256: null, packageRef: 'Notepad++.Notepad++', installArgs: '--version 8.6.4' }, 'install');
    assert.match(winget, /install --id 'Notepad\+\+\.Notepad\+\+' --exact --silent/);
    assert.match(winget, /'--version' '8\.6\.4'/);

    const lin = { id: 'l', name: 'htop', platform: 'linux' as const };
    const apt = packageScript(lin, '3', { ...base, type: 'apt', fileSha256: null, packageRef: 'htop', detection: [{ type: 'software', name: 'htop' }] }, 'install');
    assert.match(apt, /apt-get install -y -q {2}-- 'htop'/);
    assert.match(apt, /dpkg-query -W/);
    assert.match(apt, /OPENCM_RE='\^htop\$'/);
    const aptX = packageScript(lin, '3', { ...base, type: 'apt', fileSha256: null, packageRef: 'htop' }, 'uninstall');
    assert.match(aptX, /apt-get remove -y -q -- 'htop'/);

    const mac = { id: 'm', name: 'jq', platform: 'macos' as const };
    const brew = packageScript(mac, '1', { ...base, type: 'brew', fileSha256: null, packageRef: 'jq' }, 'install');
    assert.match(brew, /sudo -u "\$u" -H "\$b" install {2}'jq'/);

    const custom = packageScript(pkg, '1', { ...base, type: 'script', fileSha256: null, installCommand: "Write-Output 'x'; exit 3" }, 'install');
    assert.match(custom, /Invoke-OpenCMChild '/);
    assert.ok(!custom.includes("Write-Output 'x'"), 'custom commands are passed base64-encoded, never spliced into the script');
  });

  it('parses patch scan output of all platforms', () => {
    const win = parsePatchOutput(
      scanOutput(['S\twindows_update', 'R\t1', 'U\tabc-1\t2026-11 Cumulative Update\tKB5040000\tSecurity Updates\tCritical\t1\t\t1', 'U\tdef-2\tDefender\t\tDefinition Updates\t\t0\t\t0']),
    );
    assert.equal(win?.source, 'windows_update');
    assert.equal(win?.rebootPending, true);
    assert.equal(win?.updates.length, 2);
    assert.deepEqual(win?.updates[0], { updateId: 'abc-1', title: '2026-11 Cumulative Update', kb: 'KB5040000', classification: 'Security Updates', severity: 'Critical', security: true, version: '', rebootRequired: true });
    const apt = parsePatchOutput(scanOutput(['S\tapt', 'R\t0', 'U\topenssl\topenssl 3.0.2-0ubuntu1.15\t\tsecurity\t\t1\t3.0.2-0ubuntu1.15\t0']));
    assert.equal(apt?.updates[0]?.version, '3.0.2-0ubuntu1.15');
    assert.equal(parsePatchOutput('no markers'), null);
    assert.equal(parsePatchOutput(scanOutput(['S\tevil', 'U\tx\ty'])), null, 'unknown sources are rejected');
    const two = parsePatchOutput(`${scanOutput(['S\tapt', 'U\told\told'])}${scanOutput(['S\tapt', 'U\tnew\tnew'])}`);
    assert.deepEqual(two?.updates.map((u) => u.updateId), ['new'], 'the last block wins');
  });

  it('token bucket limits throughput (fake clock)', async () => {
    let now = 0;
    let slept = 0;
    const clock: Clock = { now: () => now, sleep: async (ms) => { now += ms; slept += ms; } };
    const b = new TokenBucket(1000, clock);
    await b.take(1000);
    assert.equal(slept, 0, 'initial burst of one second');
    await b.take(500);
    assert.equal(slept, 500);
    await b.take(1000);
    assert.equal(slept, 1500);
    const unlimited = new TokenBucket(0, clock);
    await unlimited.take(10 ** 9);
    assert.equal(slept, 1500);
  });

  it('throttled streams deliver the data unchanged', async () => {
    const data = Buffer.alloc(300_000, 7);
    const out = await buffer(Readable.from([data.subarray(0, 100_000), data.subarray(100_000)]).pipe(throttle([new TokenBucket(0)])));
    assert.ok(out.equals(data));
    const slow = await buffer(Readable.from([data.subarray(0, 4000)]).pipe(throttle([new TokenBucket(1_000_000)])));
    assert.equal(slow.length, 4000);
  });
});

describe('M5: software distribution & patch management', () => {
  let ctx: TestCtx;
  let srv: AgentServerHandle;
  let w1: EnrolledAgent;
  let w2: EnrolledAgent;
  let w3: EnrolledAgent;
  let l1: EnrolledAgent;
  let approver: { token: string; userId: string };

  before(async () => {
    ctx = await setup({ PACKAGE_MAX_BYTES: '200000' });
    srv = await startAgentServer(ctx);
    w1 = await enrollOk(ctx, { hostname: 'W1', os: 'windows' });
    w2 = await enrollOk(ctx, { hostname: 'W2', os: 'windows' });
    w3 = await enrollOk(ctx, { hostname: 'W3', os: 'windows' });
    l1 = await enrollOk(ctx, { hostname: 'L1', os: 'linux' });
    approver = await userWithGrants(ctx, 'sw-approver', ['software:*', 'patches:*', 'devices:read', 'jobs:read']);
  });
  after(async () => {
    await srv.close();
    await ctx.close();
  });

  const api = async (method: Method, url: string, payload?: object, token = ctx.adminToken) => {
    const res = await ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(token), ...(payload && { payload }) });
    return { status: res.statusCode, body: res.body && (res.headers['content-type'] ?? '').includes('json') ? res.json() : res.body, headers: res.headers };
  };
  const upload = (url: string, data: Buffer, token = ctx.adminToken) =>
    ctx.app.inject({ method: 'PUT', url: `/api/v1${url}`, headers: { ...bearer(token), 'content-type': 'application/octet-stream' }, payload: data });
  const agent = (a: EnrolledAgent) => ({
    post: (path: string, body: unknown) => agentCall('POST', srv.port, `/agent/v1${path}`, body, a),
    get: (path: string, headers: Record<string, string> = {}) => agentCall('GET', srv.port, `/agent/v1${path}`, undefined, a, headers),
  });
  const verifyEnvelope = (env: { payload: string; signature: string }): TaskPayload => {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(ctx.signer.publicKey, 'base64').toString('base64url') }, format: 'jwk' });
    const bytes = Buffer.from(env.payload, 'base64');
    assert.ok(verify(null, bytes, key, Buffer.from(env.signature, 'base64')));
    return JSON.parse(bytes.toString('utf8'));
  };
  async function nextTask(a: EnrolledAgent): Promise<TaskPayload | null> {
    const res = await agent(a).get('/tasks/next?wait=0');
    if (res.status === 204) return null;
    assert.equal(res.status, 200, JSON.stringify(res.body));
    return verifyEnvelope(res.body);
  }
  async function finish(a: EnrolledAgent, t: TaskPayload, status: 'succeeded' | 'failed', stdout?: string) {
    assert.equal((await agent(a).post(`/tasks/${t.taskId}/start`, {})).status, 200);
    if (stdout) assert.equal((await agent(a).post(`/tasks/${t.taskId}/output`, { chunks: [{ stream: 'stdout', data: stdout }] })).status, 200);
    const code = status === 'succeeded' ? 0 : 1;
    const r = await agent(a).post(`/tasks/${t.taskId}/result`, { status, exitCode: code, steps: t.steps.map((s) => ({ position: s.position, status, exitCode: code, durationMs: 5 })) });
    assert.equal(r.status, 204, JSON.stringify(r.body));
  }
  async function complete(a: EnrolledAgent, status: 'succeeded' | 'failed' = 'succeeded', stdout?: string) {
    const t = await nextTask(a);
    assert.ok(t, 'a task must be waiting');
    await finish(a, t, status, stdout);
    return t;
  }

  const installer = Buffer.from('MZ fake installer \u0000'.repeat(500));
  const sha = createHash('sha256').update(installer).digest('hex');
  let pkgId = '';
  let versionId = '';

  it('manages packages, uploads, approval and immutability', async () => {
    const p = await api('POST', '/packages', { name: 'Notepad++', publisher: 'Don Ho', platform: 'windows' });
    assert.equal(p.status, 201, JSON.stringify(p.body));
    pkgId = p.body.id;
    assert.equal((await api('POST', '/packages', { name: 'Notepad++', platform: 'windows' })).status, 409);
    assert.equal((await api('POST', '/packages', { name: 'x', platform: 'solaris' })).status, 400);

    const badType = await api('POST', `/packages/${pkgId}/versions`, { version: '1', type: 'apt', packageRef: 'htop' });
    assert.equal(badType.status, 400, 'apt is not a Windows package type');
    const badRef = await api('POST', `/packages/${pkgId}/versions`, { version: '1', type: 'winget', packageRef: 'x & calc.exe' });
    assert.equal(badRef.status, 400);

    const v = await api('POST', `/packages/${pkgId}/versions`, {
      version: '8.6.4',
      type: 'exe',
      installArgs: '/S',
      uninstallCommand: "& \"$env:ProgramFiles\\Notepad++\\uninstall.exe\" /S",
      detection: [{ type: 'software', name: 'Notepad++*', version: '8.6', operator: 'gte' }],
    });
    assert.equal(v.status, 201, JSON.stringify(v.body));
    versionId = v.body.id;
    assert.equal(v.body.status, 'draft');
    assert.equal(v.body.file, null);

    const noFile = await api('POST', `/packages/${pkgId}/versions/${versionId}/approve`, undefined, approver.token);
    assert.equal(noFile.status, 409);
    assert.match(noFile.body.error.message, /Installationsdatei fehlt/);

    const wrongCt = await ctx.app.inject({ method: 'PUT', url: `/api/v1/packages/${pkgId}/versions/${versionId}/file?name=npp.exe`, headers: { ...bearer(ctx.adminToken), 'content-type': 'text/plain' }, payload: 'x' });
    assert.equal(wrongCt.statusCode, 415);
    assert.equal((await upload(`/packages/${pkgId}/versions/${versionId}/file?name=..%2Fevil`, installer)).statusCode, 400);
    const big = await upload(`/packages/${pkgId}/versions/${versionId}/file?name=big.exe`, Buffer.alloc(200_001));
    assert.equal(big.statusCode, 413);

    const up = await upload(`/packages/${pkgId}/versions/${versionId}/file?name=npp.8.6.4.Installer.x64.exe`, installer);
    assert.equal(up.statusCode, 200, up.body);
    assert.equal(up.json().file.sha256, sha);
    assert.equal(up.json().file.sizeBytes, installer.length);
    assert.ok(existsSync(join(ctx.config.PACKAGE_DIR, sha)));

    // a second version with the same file is stored once
    const v2 = await api('POST', `/packages/${pkgId}/versions`, { version: '8.6.5', type: 'exe', installArgs: '/S' });
    assert.equal((await upload(`/packages/${pkgId}/versions/${v2.body.id}/file?name=same.exe`, installer)).statusCode, 200);
    assert.equal((await ctx.handle.db.select().from(packageFiles)).length, 1);

    const preview = await api('GET', `/packages/${pkgId}/versions/${versionId}/script?action=install`);
    assert.equal(preview.status, 200);
    assert.equal(preview.body.interpreter, 'powershell');
    assert.match(preview.body.content, /Start-Process -FilePath \$file -ArgumentList '\/S'/);
    assert.equal(preview.body.files[0].sha256, sha);

    // no second person needed: the creator releases the version
    const ok = await api('POST', `/packages/${pkgId}/versions/${versionId}/approve`);
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(ok.body.status, 'approved');

    assert.equal((await api('PATCH', `/packages/${pkgId}/versions/${versionId}`, { installArgs: '/S /evil' })).status, 409);
    assert.equal((await upload(`/packages/${pkgId}/versions/${versionId}/file?name=x.exe`, Buffer.from('other'))).statusCode, 409);
    await assert.rejects(
      ctx.handle.db.update(packageVersions).set({ installArgs: '/tampered' }).where(eq(packageVersions.id, versionId)),
      (e: { cause?: unknown }) => /immutable/.test(String(e.cause ?? e)),
    );
    assert.equal((await api('DELETE', `/packages/${pkgId}/versions/${versionId}`)).status, 409, 'approved versions are retired, not deleted');

    // deleting the draft keeps the shared file (still referenced by the approved version)
    assert.equal((await api('DELETE', `/packages/${pkgId}/versions/${v2.body.id}`)).status, 204);
    assert.ok(existsSync(join(ctx.config.PACKAGE_DIR, sha)));

    const detail = await api('GET', `/packages/${pkgId}`);
    assert.equal(detail.body.versions.length, 1);
    const list = await api('GET', '/packages?search=notepad');
    assert.equal(list.body.items[0].approvedVersion, '8.6.4');

    const reader = await userWithGrants(ctx, 'sw-reader', ['software:read']);
    assert.equal((await api('GET', '/packages', undefined, reader.token)).status, 200);
    assert.equal((await api('POST', '/packages', { name: 'nope', platform: 'linux' }, reader.token)).status, 403);
  });

  let testGroup = '';
  let pilotGroup = '';

  it('deploys through rings: auto-promotion, pause below quota, manual promotion, completion', async () => {
    testGroup = (await api('POST', '/device-groups', { kind: 'static', name: 'Ring Test', deviceIds: [w1.deviceId] })).body.id;
    pilotGroup = (await api('POST', '/device-groups', { kind: 'static', name: 'Ring Pilot', deviceIds: [w2.deviceId, l1.deviceId] })).body.id;
    const res = await api('POST', '/deployments', {
      kind: 'package',
      packageVersionId: versionId,
      action: 'install',
      rings: [
        { name: 'Test', targets: { groupIds: [testGroup] }, delayHours: 0, minSuccessPercent: 100 },
        { name: 'Pilot', targets: { groupIds: [pilotGroup] }, delayHours: 0, minSuccessPercent: 50 },
        { name: 'Alle', targets: { allDevices: true }, delayHours: 0, minSuccessPercent: 90 },
      ],
    });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    const depId = res.body.id;
    assert.equal(res.body.status, 'running');
    assert.equal(res.body.currentRing, 0);
    assert.equal(res.body.name, 'Notepad++ 8.6.4 installieren');
    assert.deepEqual(res.body.platforms, ['windows']);
    assert.equal(res.body.rings[0].stats.total, 1);

    // ring 0: W1 gets a v2 payload with the installer file
    const t1 = await nextTask(w1);
    assert.ok(t1);
    assert.equal(t1.v, 2);
    assert.deepEqual(t1.steps[0]!.files, [{ sha256: sha, name: 'npp.8.6.4.Installer.x64.exe', sizeBytes: installer.length }]);
    assert.equal(t1.steps[0]!.sha256, createHash('sha256').update(t1.steps[0]!.content).digest('hex'));

    // file download over mTLS: only for the device with the active task
    const dl = await agent(w1).get(`/files/${sha}`);
    assert.equal(dl.status, 200);
    assert.ok(dl.raw.equals(installer));
    assert.equal(dl.headers['x-checksum-sha256'], sha);
    const part = await agent(w1).get(`/files/${sha}`, { range: 'bytes=100-' });
    assert.equal(part.status, 206);
    assert.ok(part.raw.equals(installer.subarray(100)));
    assert.equal(part.headers['content-range'], `bytes 100-${installer.length - 1}/${installer.length}`);
    assert.equal((await agent(w1).get(`/files/${sha}`, { range: `bytes=${installer.length + 5}-` })).status, 416);
    assert.equal((await agent(w2).get(`/files/${sha}`)).status, 404, 'W2 has no task with this file');
    assert.equal((await agent(w1).get(`/files/${'b'.repeat(64)}`)).status, 404);
    assert.equal((await agent(w1).get('/files/not-a-hash')).status, 400);
    assert.notEqual((await agent(w1).get('/files/..%2F..%2Fetc%2Fpasswd')).status, 200);

    await finish(w1, t1, 'succeeded');
    assert.equal((await agent(w1).get(`/files/${sha}`)).status, 404, 'no download after the task finished');

    let tick = await deploymentTick(ctx.handle.db, ctx.config);
    assert.equal(tick.promoted, 1);
    let d = (await api('GET', `/deployments/${depId}`)).body;
    assert.equal(d.currentRing, 1);
    assert.equal(d.rings[0].stats.successPercent, 100);
    assert.equal(d.rings[1].stats.total, 1, 'L1 is excluded: the package is Windows-only');

    // ring 1: W2 fails → quota 0 % < 50 % → paused
    await complete(w2, 'failed');
    tick = await deploymentTick(ctx.handle.db, ctx.config);
    assert.equal(tick.paused, 1);
    d = (await api('GET', `/deployments/${depId}`)).body;
    assert.equal(d.status, 'paused');
    assert.match(d.pausedReason, /Erfolgsquote in Ring „Pilot“ 0 % < 50 %/);
    assert.equal((await deploymentTick(ctx.handle.db, ctx.config)).promoted, 0, 'paused deployments stay put');

    // manual promotion → ring 2 only reaches devices not addressed before (W3)
    const pr = await api('POST', `/deployments/${depId}/promote`, undefined, approver.token);
    assert.equal(pr.status, 200, JSON.stringify(pr.body));
    assert.equal(pr.body.currentRing, 2);
    assert.equal(pr.body.status, 'running');
    assert.equal(pr.body.rings[2].stats.total, 1);
    assert.equal(await nextTask(w1), null, 'W1 already got the package in ring 0');
    assert.equal((await api('POST', `/deployments/${depId}/promote`)).status, 409, 'current ring still running');
    await complete(w3);

    tick = await deploymentTick(ctx.handle.db, ctx.config);
    assert.equal(tick.completed, 1);
    d = (await api('GET', `/deployments/${depId}`)).body;
    assert.equal(d.status, 'completed');
    assert.ok(d.finishedAt);
    assert.equal(d.runs.length, 3);
    assert.equal((await api('POST', `/deployments/${depId}/cancel`)).status, 409);

    const list = await api('GET', '/deployments?kind=package');
    assert.equal(list.body.items[0].id, depId);
    assert.deepEqual(list.body.items[0].progress, { total: 3, succeeded: 2, failed: 1 });

    // compliance from inventory + last deployment result
    const inv = sampleInventory({ software: [{ name: 'Notepad++ (64-bit x64)', version: '8.6.4', publisher: 'Notepad++ Team', source: 'registry' }] });
    assert.equal((await agent(w1).post('/inventory', inv)).status, 204);
    assert.equal((await agent(w2).post('/inventory', sampleInventory({ software: [] }))).status, 204);
    const c = (await api('GET', `/packages/${pkgId}/compliance`)).body;
    const by = (id: string) => c.items.find((i: { deviceId: string }) => i.deviceId === id);
    assert.equal(by(w1.deviceId).installed, true);
    assert.equal(by(w2.deviceId).installed, false);
    assert.equal(by(w2.deviceId).lastDeployment.status, 'failed');
    assert.equal(by(w3.deviceId).installed, null, 'no inventory yet');
    assert.equal(c.items.some((i: { deviceId: string }) => i.deviceId === l1.deviceId), false);
    assert.equal(c.summary.failed, 1);
  });

  it('pause, resume and cancel stop further rings', async () => {
    const res = await api('POST', '/deployments', {
      kind: 'package',
      packageVersionId: versionId,
      action: 'uninstall',
      rings: [
        { name: 'Test', targets: { groupIds: [testGroup] }, delayHours: 24, minSuccessPercent: 0 },
        { name: 'Alle', targets: { allDevices: true } },
      ],
    });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    const id = res.body.id;
    const t = await nextTask(w1);
    assert.ok(t);
    assert.equal(t.v, 1, 'uninstall via command needs no file');
    assert.match(t.steps[0]!.content, /Invoke-OpenCMChild/);
    await finish(w1, t, 'succeeded');
    assert.equal((await deploymentTick(ctx.handle.db, ctx.config)).promoted, 0, 'delay of 24 h not over');

    const paused = await api('POST', `/deployments/${id}/pause`);
    assert.equal(paused.status, 200, JSON.stringify(paused.body));
    assert.equal(paused.body.status, 'paused');
    const later = new Date(Date.now() + 25 * 3600_000);
    assert.equal((await deploymentTick(ctx.handle.db, ctx.config, later)).promoted, 0, 'paused: no promotion even after the delay');
    assert.equal((await api('POST', `/deployments/${id}/pause`)).status, 409);

    assert.equal((await api('POST', `/deployments/${id}/resume`)).body.status, 'running');
    assert.equal((await api('POST', `/deployments/${id}/cancel`)).body.status, 'cancelled');
    assert.equal((await deploymentTick(ctx.handle.db, ctx.config, later)).promoted, 0, 'cancelled: the next ring never starts');
    const d = (await api('GET', `/deployments/${id}`)).body;
    assert.equal(d.runs.length, 1);
    assert.equal(d.rings[1].stats.started, false);
    assert.equal(await nextTask(w2), null);
  });

  it('deployments on all devices start immediately (no second person)', async () => {
    const res = await api('POST', '/deployments', { kind: 'package', packageVersionId: versionId, rings: [{ name: 'Alle', targets: { allDevices: true } }] });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    assert.equal(res.body.status, 'running');
    assert.equal('approvalStatus' in res.body, false);
    assert.ok(await nextTask(w3), 'W3 gets its task right away');
  });

  it('patch scans: manual scan, ingestion, replacement, failures, reports', async () => {
    // drain leftovers from earlier tests
    for (const a of [w1, w2, w3, l1]) for (let t = await nextTask(a); t; t = await nextTask(a)) await finish(a, t, 'succeeded');

    const scan = await api('POST', '/patches/scan', { targets: { deviceIds: [w1.deviceId, l1.deviceId] } });
    assert.equal(scan.status, 202, JSON.stringify(scan.body));
    assert.equal(scan.body.devices, 2);
    assert.equal(scan.body.runIds.length, 2, 'one run per operating system');

    const tw = await nextTask(w1);
    assert.ok(tw);
    assert.match(tw.steps[0]!.content, /Microsoft\.Update\.Session/);
    assert.equal(tw.steps[0]!.interpreter, 'powershell');
    await finish(
      w1,
      tw,
      'succeeded',
      scanOutput(['S\twindows_update', 'R\t1', 'U\tu-1\t2026-11 Cumulative Update for Windows 11\tKB5050001\tSecurity Updates\tCritical\t1\t\t1', 'U\tu-2\tDefender update\t\tDefinition Updates\t\t0\t\t0']),
    );
    const tl = await nextTask(l1);
    assert.ok(tl);
    assert.match(tl.steps[0]!.content, /apt list --upgradable/);
    await finish(l1, tl, 'failed');

    const dp = await api('GET', `/devices/${w1.deviceId}/patches`);
    assert.equal(dp.status, 200);
    assert.equal(dp.body.state.lastScanStatus, 'ok');
    assert.equal(dp.body.state.rebootPending, true);
    assert.equal(dp.body.items.length, 2);
    assert.equal(dp.body.items[0].kb, 'KB5050001', 'security updates first');
    const lp = await api('GET', `/devices/${l1.deviceId}/patches`);
    assert.equal(lp.body.state.lastScanStatus, 'failed');

    const summary = (await api('GET', '/patches/summary')).body;
    assert.equal(summary.withSecurity, 1);
    assert.equal(summary.withCritical, 1);
    assert.equal(summary.scanFailed, 1);
    assert.equal(summary.rebootPending, 1);
    assert.equal(summary.missingTotal, 2);
    assert.equal(summary.topUpdates[0].kb, 'KB5050001');

    const devs = (await api('GET', '/patches/devices?filter=security')).body;
    assert.deepEqual(devs.items.map((d: { hostname: string }) => d.hostname), ['W1']);
    assert.equal((await api('GET', '/patches/devices?filter=never')).body.total, 2, 'W2 and W3 never scanned');
    const ups = (await api('GET', '/patches/updates?security=true')).body;
    assert.equal(ups.items.length, 1);
    assert.equal(ups.items[0].devices, 1);

    const csv = await api('GET', '/patches/export?format=csv');
    assert.equal(csv.status, 200);
    assert.ok(String(csv.body).startsWith('\uFEFFhostname;os;'));
    assert.match(String(csv.body), /"W1";"windows"/);

    // a new scan replaces the list (installed updates disappear)
    await api('POST', '/patches/scan', { targets: { deviceIds: [w1.deviceId] } });
    await complete(w1, 'succeeded', scanOutput(['S\twindows_update', 'R\t0', 'U\tu-2\tDefender update\t\tDefinition Updates\t\t0\t\t0']));
    const after2 = (await api('GET', `/devices/${w1.deviceId}/patches`)).body;
    assert.deepEqual(after2.items.map((u: { updateId: string }) => u.updateId), ['u-2']);
    assert.equal(after2.state.rebootPending, false);

    // output without markers counts as a failed scan
    await api('POST', '/patches/scan', { targets: { deviceIds: [w1.deviceId] } });
    await complete(w1, 'succeeded', 'just text');
    assert.equal((await api('GET', `/devices/${w1.deviceId}/patches`)).body.state.lastScanStatus, 'failed');

    // scope: a user restricted to the pilot group sees only W2/L1
    const scoped = await userWithGrants(ctx, 'patch-scoped', []);
    const role = await api('POST', '/roles', { name: 'patch-readers', permissions: ['patches:read', 'patches:execute'] });
    await api('PATCH', `/users/${scoped.userId}`, { roleAssignments: [{ roleId: role.body.id, scopeDeviceGroupIds: [pilotGroup] }] });
    assert.equal((await api('GET', `/devices/${w1.deviceId}/patches`, undefined, scoped.token)).status, 404);
    assert.equal((await api('GET', '/patches/summary', undefined, scoped.token)).body.devices, 2);
    assert.equal((await api('POST', '/patches/scan', { targets: { deviceIds: [w1.deviceId] } }, scoped.token)).status, 403);
  });

  it('automatic scan picks online devices that are due', async () => {
    for (const a of [w1, w2, w3, l1]) for (let t = await nextTask(a); t; t = await nextTask(a)) await finish(a, t, 'succeeded');
    assert.equal((await patchScanTick(ctx.handle.db, ctx.config)).devices, 0, 'disabled in tests (interval 0)');
    assert.equal((await agent(w3).post('/heartbeat', { agentVersion: '1.0.0' })).status, 200);
    assert.equal((await agent(w1).post('/heartbeat', { agentVersion: '1.0.0' })).status, 200);
    const cfg = { ...ctx.config, PATCH_SCAN_INTERVAL_HOURS: 24 };
    const r = await patchScanTick(ctx.handle.db, cfg);
    assert.equal(r.devices, 1, 'W3 is online and never scanned; W1 was scanned recently; W2/L1 offline');
    assert.ok(await nextTask(w3));
    assert.equal((await patchScanTick(ctx.handle.db, cfg)).devices, 0, 'requested scans are not repeated');
  });

  it('OS update deployments: install + rescan per OS, reboot policy, permissions', async () => {
    const swOnly = await userWithGrants(ctx, 'sw-exec', ['software:execute', 'software:read']);
    const body = {
      kind: 'os_updates',
      patchFilter: { classification: 'security', include: [], reboot: 'if_required' },
      rings: [{ name: 'Alle', targets: { allDevices: true } }],
    };
    assert.equal((await api('POST', '/deployments', body, swOnly.token)).status, 403, 'needs patches:execute');
    assert.equal((await api('POST', '/deployments', { ...body, patchFilter: { include: ['KB1; rm -rf /'] } })).status, 400);
    const res = await api('POST', '/deployments', body);
    assert.equal(res.status, 201, JSON.stringify(res.body));
    assert.deepEqual(res.body.platforms.sort(), ['linux', 'macos', 'windows']);
    assert.equal(res.body.runs.length, 2, 'Windows and Linux devices present');
    assert.equal(res.body.options.stopOnError, false, 'the rescan runs even if the installation fails');
    const t = await nextTask(w2);
    assert.ok(t);
    assert.equal(t.steps.length, 2);
    assert.match(t.steps[0]!.content, /shutdown\.exe" \/r \/t 300/);
    assert.match(t.steps[1]!.content, /OPENCM-PATCHES-BEGIN/);
    const tl = await nextTask(l1);
    assert.ok(tl);
    assert.match(tl.steps[0]!.content, /upgrade -y --security/);
    assert.match(tl.steps[0]!.content, /apt-get install --only-upgrade/);
  });
});
