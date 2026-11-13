import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { eq } from 'drizzle-orm';
import { feedState, vulnCpeMatches, vulnerabilities } from '../src/db/schema.ts';
import { ingestInventory } from '../src/inventory/ingest.ts';
import { InventorySchema } from '../src/inventory/schema.ts';
import { feedTick, requestSync, type FeedDeps } from '../src/vuln/feeds.ts';
import { parseNvdCve } from '../src/vuln/nvd.ts';
import { enrollOk, sampleInventory, type EnrolledAgent } from './agent-helpers.ts';
import { bearer, setup, userWithGrants, type TestCtx } from './helpers.ts';
import { fakeFeeds, NVD_CVES, type FakeFeeds } from './vuln-fixtures.ts';

type Method = 'GET' | 'POST' | 'PATCH' | 'DELETE';
const WEBHOOK_SECRET = 'webhook-secret-0123456789';

describe('M3: vulnerability detection', () => {
  let ctx: TestCtx;
  let feeds: FakeFeeds;
  let deps: FeedDeps;
  let win: EnrolledAgent;
  let lin: EnrolledAgent;
  let clock = new Date('2099-01-10T12:00:00Z');

  const api = async (method: Method, url: string, payload?: object, token = ctx.adminToken) => {
    const res = await ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(token), ...(payload && { payload }) });
    return { status: res.statusCode, body: res.body ? res.json() : null };
  };
  const ingest = (a: EnrolledAgent, software: object[], os = 'windows') =>
    ingestInventory(ctx.handle.db, a.deviceId, InventorySchema.parse(sampleInventory({ software, ...(os === 'linux' && { os: { name: 'Ubuntu', version: '22.04' } }) })));
  const tick = () => feedTick(ctx.handle.db, ctx.config, deps);

  const winSoftware = (firefox = '131.0') => [
    { name: 'Mozilla Firefox (x64 de)', version: firefox, publisher: 'Mozilla', source: 'registry', arch: 'x64' },
    { name: '7-Zip 23.01 (x64)', version: '23.01', publisher: 'Igor Pavlov', source: 'registry', arch: 'x64' },
    { name: 'Notepad++ (64-bit x64)', version: '8.6.2', publisher: 'Notepad++ Team', source: 'registry', arch: 'x64' },
    { name: 'Acme Widget', version: '1.0', publisher: 'ACME Corp.', source: 'registry' },
    { name: 'Unknown Tool 2000', version: '1.0', publisher: 'Nobody', source: 'registry' },
  ];

  before(async () => {
    ctx = await setup({
      NVD_API_URL: 'https://nvd.test/rest/json/cves/2.0',
      KEV_URL: 'https://kev.test/kev.json',
      EPSS_URL: 'https://epss.test/data/v1/epss',
      NVD_MAX_PAGES_PER_RUN: '2',
      VULN_WEBHOOK_URL: 'https://hooks.test/opencm',
      VULN_WEBHOOK_SECRET: WEBHOOK_SECRET,
    });
    feeds = fakeFeeds();
    deps = { fetch: feeds.fetch, sleep: async () => {}, log: () => {}, now: () => clock };
    win = await enrollOk(ctx, { hostname: 'WIN-VULN', os: 'windows' });
    lin = await enrollOk(ctx, { hostname: 'LNX-VULN', os: 'linux' });
    await ingest(win, winSoftware());
    await ingest(lin, [{ name: 'openssl', version: '3.0.2-0ubuntu1.10', publisher: 'Ubuntu Developers', source: 'dpkg', arch: 'amd64' }], 'linux');
  });
  after(async () => ctx.close());

  it('parses NVD records: CVSS preference, CWE, English text, application CPEs only', () => {
    const p = parseNvdCve(NVD_CVES[0]!);
    assert.equal(p.vuln.cvssScore, 9.8);
    assert.equal(p.vuln.cvssSeverity, 'CRITICAL');
    assert.equal(p.vuln.description, 'Firefox memory corruption');
    assert.deepEqual(p.vuln.cwes, ['CWE-787']);
    assert.equal(p.matches[0]!.versionEndExcluding, '132.0');
    const v2 = parseNvdCve(NVD_CVES[7]!);
    assert.equal(v2.vuln.cvssSeverity, 'HIGH', 'v2 severity lives on the metric');
    assert.equal(v2.vuln.cvssVersion, '2.0');
    assert.equal(parseNvdCve(NVD_CVES[5]!).matches.length, 0, 'vulnerable=false and OS CPEs are skipped');
    assert.equal(parseNvdCve(NVD_CVES[3]!).matches[0]!.product, 'notepad++', 'CPE escaping removed');
  });

  it('mirrors NVD resumably (rate limit retry, bounded pages per run), then KEV', async () => {
    const r1 = await tick();
    assert.deepEqual(r1.synced, ['kev', 'nvd', 'epss'], 'EPSS runs after the evaluation');
    let [nvd] = await ctx.handle.db.select().from(feedState).where(eq(feedState.name, 'nvd'));
    assert.equal((nvd!.cursor as { mode: string }).mode, 'full', 'two pages per run → not done yet');
    assert.equal((nvd!.cursor as { startIndex: number }).startIndex, 6);
    assert.equal(nvd!.lastSuccessAt, null);
    assert.ok(feeds.calls.filter((c) => c.includes('nvd.test')).length >= 3, 'retried after 403');

    clock = new Date(clock.getTime() + 60_000);
    const r2 = await tick();
    assert.ok(r2.synced.includes('nvd'));
    [nvd] = await ctx.handle.db.select().from(feedState).where(eq(feedState.name, 'nvd'));
    assert.equal((nvd!.cursor as { mode: string }).mode, 'incremental');
    assert.ok(nvd!.lastSuccessAt);

    const all = await ctx.handle.db.select().from(vulnerabilities);
    assert.equal(all.length, 10, '9 NVD CVEs + 1 KEV stub');
    const stub = all.find((v) => v.cveId === 'CVE-2099-0999')!;
    assert.equal(stub.kev, true);
    assert.equal(stub.description, 'Stub from KEV');
    const ff = all.find((v) => v.cveId === 'CVE-2099-0001')!;
    assert.equal(ff.kev, true);
    assert.equal(ff.description, 'Firefox memory corruption', 'NVD text wins over KEV text');
    assert.equal(ff.kevRansomware, 'Known');
  });

  it('detects findings with the right confidence and skips non-matches', async () => {
    const dev = await api('GET', `/devices/${win.deviceId}/vulnerabilities`);
    const ids = dev.body.items.map((i: { cveId: string }) => i.cveId).sort();
    assert.deepEqual(ids, ['CVE-2099-0001', 'CVE-2099-0002', 'CVE-2099-0004', 'CVE-2099-0007', 'CVE-2099-0008']);
    const byId = Object.fromEntries(dev.body.items.map((i: { cveId: string }) => [i.cveId, i]));
    assert.equal(byId['CVE-2099-0001'].confidence, 'high', 'built-in rule');
    assert.equal(byId['CVE-2099-0008'].confidence, 'medium', 'heuristic (Acme Widget → acme:widget)');
    assert.equal(byId['CVE-2099-0001'].softwareVersion, '131.0');
    assert.equal(dev.body.items[0].cveId, 'CVE-2099-0001', 'KEV first');

    const linux = await api('GET', `/devices/${lin.deviceId}/vulnerabilities`);
    assert.deepEqual(linux.body.items.map((i: { cveId: string; confidence: string }) => `${i.cveId}:${i.confidence}`), ['CVE-2099-0003:low']);
  });

  it('notifies new critical / KEV findings via signed webhook', () => {
    assert.ok(feeds.webhooks.length >= 1);
    const hook = feeds.webhooks[0]!;
    const expected = `sha256=${createHmac('sha256', WEBHOOK_SECRET).update(hook.body).digest('hex')}`;
    assert.equal(hook.headers['x-opencm-signature'], expected);
    const body = JSON.parse(hook.body);
    assert.equal(body.event, 'vulnerability.findings.new');
    assert.deepEqual(body.findings.map((f: { cveId: string }) => f.cveId), ['CVE-2099-0001']);
    assert.equal(body.findings[0].hostname, 'WIN-VULN');
    assert.equal(body.findings[0].kev, true);
  });

  it('summary, list filters, details', async () => {
    const s = await api('GET', '/vulnerabilities/summary');
    assert.equal(s.body.openCves, 6);
    assert.equal(s.body.affectedDevices, 2);
    assert.equal(s.body.kev.cves, 1);
    assert.equal(s.body.kev.overdue, 1, 'due date in the past');
    assert.equal(s.body.bySeverity.CRITICAL.cves, 1);
    assert.equal(s.body.bySeverity.HIGH.cves, 3);
    assert.equal(s.body.mirror.cves, 10);
    assert.ok(s.body.feeds.some((f: { name: string }) => f.name === 'nvd'));

    const list = await api('GET', '/vulnerabilities');
    assert.equal(list.body.total, 6);
    assert.equal(list.body.items[0].cveId, 'CVE-2099-0001');
    assert.equal(list.body.items[0].affectedDevices, 1);
    assert.deepEqual(list.body.items[0].products, ['mozilla:firefox']);
    assert.equal((await api('GET', '/vulnerabilities?severity=high,critical')).body.total, 4);
    assert.equal((await api('GET', '/vulnerabilities?kev=true')).body.total, 1);
    assert.equal((await api('GET', '/vulnerabilities?confidence=low')).body.items[0].cveId, 'CVE-2099-0003');
    assert.equal((await api('GET', '/vulnerabilities?search=notepad')).body.total, 1);
    assert.equal((await api('GET', `/vulnerabilities?deviceId=${lin.deviceId}`)).body.total, 1);
    assert.equal((await api('GET', '/vulnerabilities?severity=bogus')).status, 400);

    const d = await api('GET', '/vulnerabilities/cve-2099-0001');
    assert.equal(d.body.cveId, 'CVE-2099-0001');
    assert.equal(d.body.refs[0].url, 'https://example.org/CVE-2099-0001');
    assert.equal(d.body.affected[0].hostname, 'WIN-VULN');
    assert.equal((await api('GET', '/vulnerabilities/CVE-2099-4242')).status, 404);
    assert.equal((await api('GET', '/vulnerabilities/not-a-cve')).status, 400);
  });

  it('loads EPSS only for CVEs with findings', async () => {
    await requestSync(ctx.handle.db, ['epss'], clock);
    clock = new Date(clock.getTime() + 60_000);
    const r = await tick();
    assert.ok(r.synced.includes('epss'));
    const epssCall = feeds.calls.find((c) => c.includes('epss.test'))!;
    assert.ok(!epssCall.includes('CVE-2099-0009'), 'no request for CVEs without findings');
    const [ff] = await ctx.handle.db.select().from(vulnerabilities).where(eq(vulnerabilities.cveId, 'CVE-2099-0001'));
    assert.ok(ff!.epss! > 0);
    assert.equal(ff!.epssDate, '2099-01-05');
  });

  it('risk acceptance hides a CVE (reason required, audited)', async () => {
    assert.equal((await api('PATCH', '/vulnerabilities/CVE-2099-0008', { accepted: true })).status, 400);
    const acc = await api('PATCH', '/vulnerabilities/CVE-2099-0008', { accepted: true, reason: 'Widget ist vom Netz getrennt' });
    assert.ok(acc.body.acceptedAt);
    assert.equal((await api('GET', '/vulnerabilities')).body.total, 5);
    assert.equal((await api('GET', '/vulnerabilities?includeAccepted=true')).body.total, 6);
    await api('PATCH', '/vulnerabilities/CVE-2099-0008', { accepted: false });
    assert.equal((await api('GET', '/vulnerabilities')).body.total, 6);
    const audit = await api('GET', '/audit-log?action=vulnerability.accept');
    assert.equal(audit.body.items[0].details.reason, 'Widget ist vom Netz getrennt');
  });

  it('updating the software closes findings on the next evaluation', async () => {
    clock = new Date(clock.getTime() + 60_000);
    await ingest(win, winSoftware('132.0'));
    // inventory ingest sets lastInventoryAt = real now; evaluation looks for newer inventories than the last run
    const { devices } = await import('../src/db/schema.ts');
    await ctx.handle.db.update(devices).set({ lastInventoryAt: new Date(clock.getTime() + 1000) }).where(eq(devices.id, win.deviceId));
    clock = new Date(clock.getTime() + 60_000);
    const r = await tick();
    assert.equal(r.evaluated, 1, 'only the device with a new inventory');
    const fixed = await api('GET', `/devices/${win.deviceId}/vulnerabilities?status=fixed`);
    assert.deepEqual(fixed.body.items.map((i: { cveId: string }) => i.cveId), ['CVE-2099-0001']);
    assert.ok(fixed.body.items[0].fixedAt);
    assert.equal((await api('GET', '/vulnerabilities?kev=true')).body.total, 0);
  });

  it('incremental NVD sync applies modifications and removes rejected CVEs', async () => {
    await requestSync(ctx.handle.db, ['nvd'], clock);
    clock = new Date(clock.getTime() + 60_000);
    const r = await tick();
    assert.ok(r.synced.includes('nvd'));
    assert.equal((await ctx.handle.db.select().from(vulnerabilities).where(eq(vulnerabilities.cveId, 'CVE-2099-0007'))).length, 0, 'rejected CVE removed');
    assert.equal((await ctx.handle.db.select().from(vulnCpeMatches).where(eq(vulnCpeMatches.cveId, 'CVE-2099-0007'))).length, 0);
    const ids = (await api('GET', `/devices/${win.deviceId}/vulnerabilities`)).body.items.map((i: { cveId: string }) => i.cveId);
    assert.ok(ids.includes('CVE-2099-0010'), 'new CVE (exact version match) found after full re-evaluation');
    assert.ok(!ids.includes('CVE-2099-0007'));
  });

  it('CPE rules: built-ins protected, user rules override, test endpoint', async () => {
    const rules = (await api('GET', '/cpe-rules')).body.items;
    const builtin = rules.find((r: { namePattern: string }) => r.namePattern === 'Mozilla Firefox*');
    assert.equal(builtin.origin, 'builtin');
    assert.equal((await api('DELETE', `/cpe-rules/${builtin.id}`)).status, 409);
    assert.equal((await api('PATCH', `/cpe-rules/${builtin.id}`, { vendor: 'evil' })).status, 409);
    assert.equal((await api('PATCH', `/cpe-rules/${builtin.id}`, { enabled: true })).status, 200);

    const t = await api('POST', '/cpe-rules/test', { namePattern: 'Acme*' });
    assert.deepEqual(t.body.items.map((i: { name: string }) => i.name), ['Acme Widget']);
    assert.equal((await api('POST', '/cpe-rules', { namePattern: 'x' })).status, 400, 'vendor/product required');

    const ignore = await api('POST', '/cpe-rules', { namePattern: 'Acme Widget*', ignore: true, note: 'Eigenentwicklung' });
    assert.equal(ignore.status, 201);
    // the API stamps the re-evaluation request with wall-clock time; the test runs on a fake 2099 clock
    clock = new Date(clock.getTime() + 1000);
    await requestSync(ctx.handle.db, [], clock);
    clock = new Date(clock.getTime() + 60_000);
    await tick(); // rule change requests a full evaluation
    const ids = (await api('GET', `/devices/${win.deviceId}/vulnerabilities`)).body.items.map((i: { cveId: string }) => i.cveId);
    assert.ok(!ids.includes('CVE-2099-0008'), 'ignored software produces no findings');

    const sw = await api('GET', '/software?mapping=unmapped');
    const unknown = sw.body.items.find((i: { name: string }) => i.name === 'Unknown Tool 2000');
    assert.ok(unknown);
    assert.equal(unknown.deviceCount, 1);
    const mapped = await api('GET', '/software?mapping=mapped&search=firefox');
    assert.equal(mapped.body.items[0].mapping.product, 'firefox');
    assert.equal(mapped.body.items[0].mapping.method, 'rule');
    const ignored = await api('GET', '/software?mapping=ignored');
    assert.deepEqual(ignored.body.items.map((i: { name: string }) => i.name), ['Acme Widget']);
    assert.equal((await api('DELETE', `/cpe-rules/${ignore.body.id}`)).status, 204);
  });

  it('creates remediation jobs from a CVE (optionally runs them)', async () => {
    const tpl = (await api('GET', '/script-templates')).body.items.find((t: { id: string }) => t.id === 'win-winget-upgrade');
    assert.ok(tpl);
    const s = await api('POST', '/scripts', { name: 'winget upgrade', interpreter: tpl.interpreter, content: tpl.content, parameters: tpl.parameters });
    const noApproval = await api('POST', '/vulnerabilities/CVE-2099-0002/remediation', { scriptId: s.body.id, params: { PackageId: '7zip.7zip' } });
    assert.equal(noApproval.body.error.code, 'script_not_approved', 'templates must be approved first');
    await api('POST', `/scripts/${s.body.id}/versions/1/approve`);

    const rem = await api('POST', '/vulnerabilities/CVE-2099-0002/remediation', { scriptId: s.body.id, params: { PackageId: '7zip.7zip' }, runNow: true });
    assert.equal(rem.status, 201, JSON.stringify(rem.body));
    assert.equal(rem.body.devices, 1);
    assert.ok(rem.body.runId);
    const job = await api('GET', `/jobs/${rem.body.jobId}`);
    assert.equal(job.body.name, 'Behebung CVE-2099-0002');
    assert.deepEqual(job.body.targets.deviceIds, [win.deviceId]);
    assert.deepEqual(job.body.steps[0].params, { PackageId: '7zip.7zip' });

    assert.equal((await api('POST', '/vulnerabilities/CVE-2099-0009/remediation', { scriptId: s.body.id, params: { PackageId: 'x' } })).status, 409, 'no affected devices');
    const creator = await userWithGrants(ctx, 'jobcreator', ['jobs:create', 'scripts:read', 'vulnerabilities:read']);
    const denied = await api('POST', '/vulnerabilities/CVE-2099-0002/remediation', { scriptId: s.body.id, params: { PackageId: 'x' }, runNow: true }, creator.token);
    assert.equal(denied.status, 403, 'runNow needs jobs:execute');
  });

  it('feeds: sync request, error handling with back-off, lease prevents parallel runs', async () => {
    const reader = await userWithGrants(ctx, 'vulnreader', ['vulnerabilities:read']);
    assert.equal((await api('POST', '/vulnerability-feeds/sync', {}, reader.token)).status, 403);
    assert.equal((await api('PATCH', '/vulnerabilities/CVE-2099-0002', { accepted: true, reason: 'x' }, reader.token)).status, 403);
    assert.equal((await api('GET', '/vulnerabilities', undefined, reader.token)).status, 200);

    feeds.failKev = true;
    assert.equal((await api('POST', '/vulnerability-feeds/sync', { feeds: ['kev'] })).status, 202);
    await requestSync(ctx.handle.db, ['kev'], clock); // fake clock (see above)
    clock = new Date(clock.getTime() + 60_000);
    await tick();
    let kev = (await api('GET', '/vulnerability-feeds')).body.items.find((f: { name: string }) => f.name === 'kev');
    assert.match(kev.error, /HTTP 503/);
    const before = feeds.calls.filter((c) => c.includes('kev.test')).length;
    clock = new Date(clock.getTime() + 60_000);
    await tick();
    assert.equal(feeds.calls.filter((c) => c.includes('kev.test')).length, before, 'no retry storm within the back-off window');
    feeds.failKev = false;

    await requestSync(ctx.handle.db, ['kev'], clock);
    clock = new Date(clock.getTime() + 60_000);
    const [a, b] = await Promise.all([tick(), tick()]);
    assert.equal([...a.synced, ...b.synced].filter((f) => f === 'kev').length, 1, 'exactly one worker synced');
    kev = (await api('GET', '/vulnerability-feeds')).body.items.find((f: { name: string }) => f.name === 'kev');
    assert.equal(kev.error, null);
    assert.equal(kev.stats.total, 2);
  });
});
