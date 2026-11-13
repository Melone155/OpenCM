import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { eq } from 'drizzle-orm';
import { normalizeMac, parseAssetStatus, parseAssetType, parseDay, parseMoney } from '../src/assets.ts';
import { parseCsv, detectDelimiter } from '../src/csv.ts';
import { metricsTick } from '../src/dashboard.ts';
import { deviceHistory, osvPackages, vulnerabilities, webhookDeliveries } from '../src/db/schema.ts';
import { ingestInventory } from '../src/inventory/ingest.ts';
import { InventorySchema, SecuritySchema } from '../src/inventory/schema.ts';
import { evaluatePosture } from '../src/security/posture.ts';
import { feedTick, requestSync, type FeedDeps } from '../src/vuln/feeds.ts';
import { cveIdsOf, osvEcosystem, osvQueries } from '../src/vuln/osv.ts';
import type { DeliverDeps } from '../src/webhooks/deliver.ts';
import { enrollOk, sampleInventory, type EnrolledAgent } from './agent-helpers.ts';
import { bearer, setup, userWithGrants, type TestCtx } from './helpers.ts';
import { NVD_CVES } from './vuln-fixtures.ts';

type Method = 'GET' | 'POST' | 'PATCH' | 'DELETE';

// ------------------------------------------------------------------ fixtures (synthetic)

const sec = (over: Record<string, unknown> = {}) =>
  SecuritySchema.parse({
    encryption: { product: 'BitLocker', volumes: [{ volume: 'C:', system: true, encrypted: true, status: 'FullyEncrypted', method: 'XtsAes256', protection: true }] },
    antivirus: [{ name: 'Microsoft Defender Antivirus', enabled: true, realtime: true, upToDate: null, signatureVersion: '1.401.1.0', signatureUpdatedAt: '2099-01-10T06:00:00Z' }],
    firewall: { product: 'Windows Defender Firewall', profiles: [{ name: 'Domain', enabled: true }, { name: 'Private', enabled: true }, { name: 'Public', enabled: true }] },
    secureBoot: true,
    tpm: { present: true, ready: true, version: '2.0' },
    ...over,
  });

/** OSV advisories (ids/CVEs CVE-2099-*, not real data). */
const OSV_DB: Record<string, { id: string; modified: string; aliases?: string[]; upstream?: string[]; summary: string }[]> = {
  // Ubuntu: openssl source package in a patched (backported) version → nothing; libxml2 → one advisory
  'Ubuntu:22.04:LTS|openssl|3.0.2-0ubuntu1.15': [],
  'Ubuntu:22.04:LTS|libxml2|2.9.13+dfsg-1ubuntu0.3': [{ id: 'UBUNTU-CVE-2099-0100', modified: '2099-01-05T00:00:00Z', upstream: ['CVE-2099-0100'], summary: 'libxml2 use after free' }],
  // Debian (no distroId, name-based detection)
  'Debian:12|bash|5.2.15-2': [{ id: 'DEBIAN-CVE-2099-0300', modified: '2099-01-05T00:00:00Z', upstream: ['CVE-2099-0300'], summary: 'bash issue' }],
  // Rocky: advisory lists the binary package
  'Rocky Linux:9|sudo|1.9.5p2-9.el9': [{ id: 'RLSA-2099:0001', modified: '2099-01-05T00:00:00Z', aliases: ['CVE-2099-0200'], summary: 'Important: sudo security update' }],
};

function fakeOsv() {
  const calls: { url: string; body: string }[] = [];
  let failNext = false;
  const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } });
  const fetch = async (url: string, init?: RequestInit) => {
    const body = init?.body ? String(init.body) : '';
    calls.push({ url, body });
    const u = new URL(url);
    if (u.hostname === 'kev.test') return json({ catalogVersion: 't', vulnerabilities: [] });
    if (u.hostname === 'epss.test') return json({ data: [] });
    if (u.hostname === 'nvd.test') {
      // only the OpenSSL CPE record (3.0.0 – 3.0.13 vulnerable by upstream version)
      const list = u.searchParams.has('lastModStartDate') ? [] : [NVD_CVES[2]!];
      return json({ resultsPerPage: list.length, startIndex: 0, totalResults: list.length, format: 'NVD_CVE', version: '2.0', vulnerabilities: list.map((cve) => ({ cve })) });
    }
    if (u.hostname !== 'osv.test') return new Response('not found', { status: 404 });
    if (failNext) {
      failNext = false;
      return new Response('down', { status: 400 });
    }
    if (u.pathname === '/v1/querybatch') {
      const q = JSON.parse(body) as { queries: { package: { ecosystem: string; name: string }; version: string }[] };
      return json({ results: q.queries.map((x) => ({ vulns: (OSV_DB[`${x.package.ecosystem}|${x.package.name}|${x.version}`] ?? []).map((v) => ({ id: v.id, modified: v.modified })) })) });
    }
    const m = u.pathname.match(/^\/v1\/vulns\/(.+)$/);
    if (m) {
      const id = decodeURIComponent(m[1]!);
      const v = Object.values(OSV_DB).flat().find((x) => x.id === id);
      return v ? json(v) : new Response('{}', { status: 404 });
    }
    return new Response('not found', { status: 404 });
  };
  return { fetch, calls, failOnce: () => (failNext = true) };
}

function fakeWebhookHttp(): DeliverDeps {
  return { fetch: async () => ({ status: 200, ok: true }), resolve: async () => ['203.0.113.10'], now: () => new Date() };
}

// ------------------------------------------------------------------ unit tests

describe('M7 units', () => {
  it('maps distributions to OSV ecosystems', () => {
    assert.equal(osvEcosystem({ distroId: 'ubuntu', build: '22.04' }), 'Ubuntu:22.04:LTS');
    assert.equal(osvEcosystem({ distroId: 'ubuntu', build: '23.10' }), 'Ubuntu:23.10');
    assert.equal(osvEcosystem({ name: 'Debian GNU/Linux', build: '12' }), 'Debian:12');
    assert.equal(osvEcosystem({ distroId: 'rocky', build: '9.3' }), 'Rocky Linux:9');
    assert.equal(osvEcosystem({ distroId: 'almalinux', build: '8.10' }), 'AlmaLinux:8');
    assert.equal(osvEcosystem({ distroId: 'arch', build: 'rolling' }), null);
    assert.equal(osvEcosystem({ name: 'Ubuntu', version: '22.04.4 LTS (Jammy Jellyfish)' }), 'Ubuntu:22.04:LTS');
    assert.equal(osvEcosystem({ name: 'Windows 11 Pro', build: '22631' }), null);
  });

  it('builds OSV queries: Debian by source package, RPM by binary + source', () => {
    assert.deepEqual(osvQueries('Ubuntu:22.04:LTS', { name: 'libxml2-utils', version: '2.9.13+dfsg-1ubuntu0.3', source: 'dpkg', sourceName: 'libxml2', sourceVersion: '2.9.13+dfsg-1ubuntu0.3' }), [
      { name: 'libxml2', version: '2.9.13+dfsg-1ubuntu0.3' },
    ]);
    assert.deepEqual(osvQueries('Debian:12', { name: 'bash', version: '5.2.15-2+b2', source: 'dpkg' }), [{ name: 'bash', version: '5.2.15-2+b2' }], 'old agents: binary fields');
    assert.deepEqual(osvQueries('Rocky Linux:9', { name: 'openssl-libs', version: '3.0.7-27.el9', source: 'rpm', sourceName: 'openssl', sourceVersion: '1:3.0.7-27.el9' }), [
      { name: 'openssl-libs', version: '1:3.0.7-27.el9' },
      { name: 'openssl', version: '1:3.0.7-27.el9' },
    ]);
    assert.deepEqual(osvQueries('Debian:12', { name: 'x', version: '1', source: 'rpm' }), []);
  });

  it('extracts CVE ids from OSV records', () => {
    assert.deepEqual(cveIdsOf({ id: 'UBUNTU-CVE-2099-0100', upstream: ['CVE-2099-0100'] }), ['CVE-2099-0100']);
    assert.deepEqual(cveIdsOf({ id: 'DSA-9999-1', aliases: ['CVE-2099-0002', 'CVE-2099-0001'] }), ['CVE-2099-0001', 'CVE-2099-0002']);
    assert.deepEqual(cveIdsOf({ id: 'GHSA-xxxx' }), []);
  });

  it('evaluates the security posture', () => {
    const now = new Date('2099-01-11T00:00:00Z');
    const o = { maxSignatureAgeDays: 3, now };
    const ok = evaluatePosture(sec(), 'windows', o);
    assert.equal(ok.compliant, true);
    assert.deepEqual(ok.issues, []);
    assert.equal(ok.tpm, 'ready');

    const suspended = evaluatePosture(sec({ encryption: { volumes: [{ volume: 'C:', system: true, encrypted: true, protection: false }] } }), 'windows', o);
    assert.equal(suspended.encryption, 'partial');
    assert.ok(suspended.issues.includes('encryption_suspended'));
    assert.equal(suspended.compliant, false);

    const dataDisk = evaluatePosture(sec({ encryption: { volumes: [{ volume: 'C:', system: true, encrypted: true }, { volume: 'D:', system: false, encrypted: false }] } }), 'windows', o);
    assert.equal(dataDisk.encryption, 'partial');

    const old = evaluatePosture(sec({ antivirus: [{ name: 'Defender', enabled: true, realtime: true, signatureUpdatedAt: '2099-01-01T00:00:00Z' }] }), 'windows', o);
    assert.equal(old.antivirus, 'outdated');
    const mac = evaluatePosture(sec({ antivirus: [{ name: 'XProtect', enabled: true, signatureUpdatedAt: '2098-12-20T00:00:00Z' }] }), 'macos', o);
    assert.equal(mac.antivirus, 'ok', 'XProtect: 30 days tolerated');

    const off = evaluatePosture(sec({ antivirus: [{ name: 'Defender', enabled: false }], firewall: { profiles: [{ name: 'Domain', enabled: true }, { name: 'Public', enabled: false }] }, secureBoot: false }), 'windows', o);
    assert.equal(off.antivirus, 'disabled');
    assert.equal(off.firewall, 'partial');
    assert.deepEqual([...off.issues].sort(), ['av_disabled', 'firewall_partial', 'secure_boot_off']);

    const linux = evaluatePosture(sec({ encryption: { product: 'LUKS', volumes: [{ volume: '/', system: true, encrypted: true }] }, antivirus: [], firewall: { product: 'ufw', enabled: true }, tpm: {} }), 'linux', o);
    assert.equal(linux.antivirus, 'unknown');
    assert.equal(linux.compliant, true, 'antivirus not required on Linux');
    assert.equal(evaluatePosture(sec({ antivirus: [] }), 'windows', o).antivirus, 'missing');
    assert.equal(evaluatePosture(sec({ encryption: { volumes: [] } }), 'windows', o).encryption, 'unknown');
  });

  it('parses CSV and asset values', () => {
    assert.equal(detectDelimiter('a;b;c\n1;2;3'), ';');
    assert.equal(detectDelimiter('a,b\n1,2'), ',');
    assert.deepEqual(parseCsv('\uFEFFname;notes\r\n"Monitor ""A""";"Zeile 1\nZeile 2"\r\n\r\nDrucker;x'), [
      ['name', 'notes'],
      ['Monitor "A"', 'Zeile 1\nZeile 2'],
      ['Drucker', 'x'],
    ]);
    assert.equal(parseDay('31.12.2027'), '2027-12-31');
    assert.equal(parseDay('2027-02-30'), null);
    assert.equal(parseMoney('1.234,56 €'), 1234.56);
    assert.equal(parseMoney('199.9'), 199.9);
    assert.equal(parseMoney('abc'), null);
    assert.equal(normalizeMac('00-1a-2b-3c-4d-5e'), '00:1A:2B:3C:4D:5E');
    assert.equal(normalizeMac('nope'), null);
    assert.equal(parseAssetType('Drucker'), 'printer');
    assert.equal(parseAssetType('Laptop'), 'notebook');
    assert.equal(parseAssetStatus('Lager'), 'in_stock');
    assert.equal(parseAssetType('Toaster'), null);
  });
});

// ------------------------------------------------------------------ OSV integration

describe('M7: OSV for Linux distribution packages', () => {
  let ctx: TestCtx;
  let deps: FeedDeps;
  let osv: ReturnType<typeof fakeOsv>;
  let ubuntu: EnrolledAgent;
  let debian: EnrolledAgent;
  let rocky: EnrolledAgent;
  let clock = new Date('2099-01-10T12:00:00Z');

  const api = async (method: Method, url: string, payload?: object) => {
    const res = await ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(ctx.adminToken), ...(payload && { payload }) });
    return { status: res.statusCode, body: res.body ? res.json() : null };
  };
  const tick = () => feedTick(ctx.handle.db, ctx.config, deps);
  const ids = async (a: EnrolledAgent) => ((await api('GET', `/devices/${a.deviceId}/vulnerabilities`)).body.items as { cveId: string; confidence: string; vendor: string; product: string }[]).map((i) => `${i.cveId}:${i.confidence}:${i.vendor}:${i.product}`).sort();

  before(async () => {
    ctx = await setup({ NVD_API_URL: 'https://nvd.test/rest/json/cves/2.0', KEV_URL: 'https://kev.test/kev.json', EPSS_URL: 'https://epss.test/epss', OSV_API_URL: 'https://osv.test/' });
    osv = fakeOsv();
    deps = { fetch: osv.fetch, sleep: async () => {}, log: () => {}, now: () => clock };
    ubuntu = await enrollOk(ctx, { hostname: 'UBUNTU-SECRET-HOST', os: 'linux' });
    debian = await enrollOk(ctx, { hostname: 'DEB-1', os: 'linux' });
    rocky = await enrollOk(ctx, { hostname: 'ROCKY-1', os: 'linux' });
    const ing = (a: EnrolledAgent, os: object, software: object[]) => ingestInventory(ctx.handle.db, a.deviceId, InventorySchema.parse(sampleInventory({ os, software })));
    await ing(ubuntu, { name: 'Ubuntu', version: '22.04.4 LTS (Jammy Jellyfish)', build: '22.04', distroId: 'ubuntu' }, [
      { name: 'openssl', version: '3.0.2-0ubuntu1.15', publisher: 'Ubuntu Developers', source: 'dpkg', arch: 'amd64', sourceName: 'openssl', sourceVersion: '3.0.2-0ubuntu1.15' },
      { name: 'libxml2', version: '2.9.13+dfsg-1ubuntu0.3', source: 'dpkg', arch: 'amd64', sourceName: 'libxml2', sourceVersion: '2.9.13+dfsg-1ubuntu0.3' },
      { name: 'libxml2-utils', version: '2.9.13+dfsg-1ubuntu0.3', source: 'dpkg', arch: 'amd64', sourceName: 'libxml2', sourceVersion: '2.9.13+dfsg-1ubuntu0.3' },
    ]);
    await ing(debian, { name: 'Debian GNU/Linux', version: '12 (bookworm)', build: '12' }, [{ name: 'bash', version: '5.2.15-2', source: 'dpkg', arch: 'amd64' }]);
    await ing(rocky, { name: 'Rocky Linux', version: '9.3 (Blue Onyx)', build: '9.3', distroId: 'rocky' }, [
      { name: 'sudo', version: '1.9.5p2-9.el9', source: 'rpm', arch: 'x86_64', sourceName: 'sudo', sourceVersion: '1.9.5p2-9.el9' },
    ]);
  });
  after(async () => ctx.close());

  it('queries OSV in batches with package identities only (no host data)', async () => {
    const r = await tick();
    assert.ok(r.synced.includes('osv'), JSON.stringify(r));
    const batch = osv.calls.filter((c) => c.url === 'https://osv.test/v1/querybatch');
    assert.equal(batch.length, 1, 'one batch for all packages');
    const q = JSON.parse(batch[0]!.body).queries as { package: { ecosystem: string; name: string }; version: string }[];
    const keys = q.map((x) => `${x.package.ecosystem}|${x.package.name}|${x.version}`).sort();
    assert.deepEqual(keys, ['Debian:12|bash|5.2.15-2', 'Rocky Linux:9|sudo|1.9.5p2-9.el9', 'Ubuntu:22.04:LTS|libxml2|2.9.13+dfsg-1ubuntu0.3', 'Ubuntu:22.04:LTS|openssl|3.0.2-0ubuntu1.15']);
    assert.ok(!osv.calls.some((c) => c.body.includes('UBUNTU-SECRET-HOST') || c.url.includes('UBUNTU-SECRET-HOST')), 'host names never leave the server');
    assert.equal(osv.calls.filter((c) => c.url.includes('/v1/vulns/')).length, 3, 'details for each new advisory');
    const [stub] = await ctx.handle.db.select().from(vulnerabilities).where(eq(vulnerabilities.cveId, 'CVE-2099-0100'));
    assert.equal(stub!.description, 'libxml2 use after free', 'CVE stub until NVD has it');
  });

  it('OSV findings replace the backport false positive of the CPE match', async () => {
    // openssl 3.0.2 is "vulnerable" by upstream version (CVE-2099-0003), but Ubuntu backported the fix
    // one finding per binary package of the affected source package (libxml2, libxml2-utils)
    assert.deepEqual(await ids(ubuntu), ['CVE-2099-0100:high:osv:Ubuntu:22.04:LTS/libxml2', 'CVE-2099-0100:high:osv:Ubuntu:22.04:LTS/libxml2']);
    assert.deepEqual(await ids(debian), ['CVE-2099-0300:high:osv:Debian:12/bash']);
    assert.deepEqual(await ids(rocky), ['CVE-2099-0200:high:osv:Rocky Linux:9/sudo']);
    const v = await api('GET', '/vulnerabilities/CVE-2099-0100');
    assert.deepEqual(v.body.affected.map((a: { softwareName: string }) => a.softwareName).sort(), ['libxml2', 'libxml2-utils'], 'every binary package of the source package');
  });

  it('is incremental: cached package versions are not queried again', async () => {
    const osvCalls = () => osv.calls.filter((c) => c.url.includes('osv.test')).length;
    const before = osvCalls();
    clock = new Date(clock.getTime() + 60_000);
    const r = await tick();
    assert.ok(!r.synced.includes('osv'));
    assert.equal(osvCalls(), before, 'no OSV calls');
  });

  it('a package update is checked on the next tick and the finding closes', async () => {
    await ingestInventory(
      ctx.handle.db,
      debian.deviceId,
      InventorySchema.parse(sampleInventory({ os: { name: 'Debian GNU/Linux', build: '12' }, software: [{ name: 'bash', version: '5.2.15-2+deb12u1', source: 'dpkg', arch: 'amd64' }] })),
    );
    clock = new Date(clock.getTime() + 60_000);
    const before = osv.calls.length;
    const r = await tick();
    assert.ok(r.synced.includes('osv'));
    const q = JSON.parse(osv.calls.slice(before).find((c) => c.url.endsWith('/v1/querybatch'))!.body).queries;
    assert.deepEqual(q.map((x: { version: string }) => x.version), ['5.2.15-2+deb12u1'], 'only the new version');
    assert.deepEqual(await ids(debian), []);
    const fixed = await api('GET', `/devices/${debian.deviceId}/vulnerabilities?status=fixed`);
    assert.deepEqual(fixed.body.items.map((i: { cveId: string }) => i.cveId), ['CVE-2099-0300']);
  });

  it('errors back off; "sync now" re-checks all cached versions', async () => {
    osv.failOnce();
    clock = new Date(clock.getTime() + 1000); // the request must be newer than the last attempt
    await requestSync(ctx.handle.db, ['osv'], clock);
    clock = new Date(clock.getTime() + 60_000);
    await tick();
    const feeds = (await api('GET', '/vulnerability-feeds')).body.items;
    assert.match(feeds.find((f: { name: string }) => f.name === 'osv').error, /HTTP 400/);
    clock = new Date(clock.getTime() + 16 * 60_000);
    await requestSync(ctx.handle.db, ['osv'], clock);
    clock = new Date(clock.getTime() + 60_000);
    const before = osv.calls.length;
    await tick();
    const q = JSON.parse(osv.calls.slice(before).find((c) => c.url.endsWith('/v1/querybatch'))!.body).queries;
    assert.equal(q.length, 4, 'forced: every installed version again');
    assert.equal((await api('GET', '/vulnerability-feeds')).body.items.find((f: { name: string }) => f.name === 'osv').error, null);
    assert.ok((await ctx.handle.db.select().from(osvPackages)).length >= 4);
  });
});

// ------------------------------------------------------------------ security posture

describe('M7: security status', () => {
  let ctx: TestCtx;
  let win: EnrolledAgent;
  let lin: EnrolledAgent;
  let old: EnrolledAgent;

  const api = async (method: Method, url: string, payload?: object, token = ctx.adminToken) => {
    const res = await ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(token), ...(payload && { payload }) });
    return { status: res.statusCode, body: (res.headers['content-type'] ?? '').includes('json') ? res.json() : res.body };
  };
  const fresh = () => new Date().toISOString();
  const ingestSec = (a: EnrolledAgent, security: object | null, os?: object) =>
    ingestInventory(ctx.handle.db, a.deviceId, InventorySchema.parse(sampleInventory({ security, ...(os && { os }) })), { maxSignatureAgeDays: 3 });

  before(async () => {
    ctx = await setup({}, { webhookDeps: fakeWebhookHttp() });
    win = await enrollOk(ctx, { hostname: 'WIN-SEC', os: 'windows' });
    lin = await enrollOk(ctx, { hostname: 'LNX-SEC', os: 'linux' });
    old = await enrollOk(ctx, { hostname: 'OLD-AGENT', os: 'windows' });
    const hook = await api('POST', '/webhooks', { name: 'SIEM', url: 'https://siem.example.test/hook', events: ['device.security_changed'] });
    assert.equal(hook.status, 201, JSON.stringify(hook.body));
    await ingestSec(win, { ...sec(), antivirus: [{ name: 'Microsoft Defender Antivirus', enabled: true, realtime: true, signatureUpdatedAt: fresh() }] });
    await ingestSec(lin, { encryption: { product: 'LUKS', volumes: [{ volume: '/', system: true, encrypted: true }] }, antivirus: [], firewall: { product: 'ufw', enabled: true }, secureBoot: null, tpm: {} }, { name: 'Ubuntu', build: '24.04' });
    await ingestSec(old, null);
  });
  after(async () => ctx.close());

  it('stores the posture per device and reports devices without status', async () => {
    const d = await api('GET', `/devices/${win.deviceId}/security`);
    assert.equal(d.status, 200);
    assert.equal(d.body.compliant, true);
    assert.equal(d.body.encryption, 'encrypted');
    assert.equal(d.body.details.encryption.product, 'BitLocker');
    assert.equal((await api('GET', `/devices/${old.deviceId}/security`)).status, 404, 'older agent: no status');

    const s = await api('GET', '/security-status');
    assert.equal(s.body.summary.devices, 3);
    assert.equal(s.body.summary.reported, 2);
    assert.equal(s.body.summary.compliant, 2);
    assert.equal(s.body.items.find((i: { hostname: string }) => i.hostname === 'OLD-AGENT').reported, false);
    assert.equal((await api('GET', '/security-status?reported=false')).body.total, 1);
  });

  it('a worsening is visible: issues, history, webhook event', async () => {
    await ingestSec(win, {
      ...sec(),
      encryption: { product: 'BitLocker', volumes: [{ volume: 'C:', system: true, encrypted: false, status: 'FullyDecrypted', protection: false }] },
      antivirus: [{ name: 'Microsoft Defender Antivirus', enabled: true, realtime: false, signatureUpdatedAt: fresh() }],
    });
    const d = await api('GET', `/devices/${win.deviceId}/security`);
    assert.equal(d.body.compliant, false);
    assert.deepEqual(d.body.issues.map((i: { code: string }) => i.code).sort(), ['av_realtime_off', 'unencrypted']);
    assert.equal(d.body.issues.find((i: { code: string }) => i.code === 'unencrypted').label, 'Systemlaufwerk nicht verschlüsselt');

    const hist = await ctx.handle.db.select().from(deviceHistory).where(eq(deviceHistory.deviceId, win.deviceId));
    const secHist = hist.filter((h) => h.category === 'security').map((h) => `${h.itemKey}=${JSON.stringify(h.newValue)}`);
    assert.ok(secHist.includes('Verschlüsselung C:="unverschlüsselt"'), secHist.join(' | '));
    assert.ok(secHist.includes('Virenschutz Microsoft Defender Antivirus="Echtzeitschutz aus"'));

    const deliveries = await ctx.handle.db.select().from(webhookDeliveries).where(eq(webhookDeliveries.event, 'device.security_changed'));
    assert.equal(deliveries.length, 1);
    const data = (deliveries[0]!.payload as { data: { hostname: string; newIssues: { code: string }[]; wasCompliant: boolean } }).data;
    assert.equal(data.hostname, 'WIN-SEC');
    assert.equal(data.wasCompliant, true);
    assert.deepEqual(data.newIssues.map((i) => i.code).sort(), ['av_realtime_off', 'unencrypted']);

    // same state again → no new event
    await ingestSec(win, {
      ...sec(),
      encryption: { product: 'BitLocker', volumes: [{ volume: 'C:', system: true, encrypted: false, protection: false }] },
      antivirus: [{ name: 'Microsoft Defender Antivirus', enabled: true, realtime: false, signatureUpdatedAt: fresh() }],
    });
    assert.equal((await ctx.handle.db.select().from(webhookDeliveries).where(eq(webhookDeliveries.event, 'device.security_changed'))).length, 1);
  });

  it('filters, CSV export, dynamic groups, report source, dashboard', async () => {
    assert.deepEqual((await api('GET', '/security-status?compliant=false')).body.items.map((i: { hostname: string }) => i.hostname), ['WIN-SEC']);
    assert.equal((await api('GET', '/security-status?encryption=unencrypted')).body.total, 1);
    assert.equal((await api('GET', '/security-status?issue=unencrypted')).body.total, 1);
    assert.equal((await api('GET', '/security-status?encryption=bogus')).status, 400);
    const csv = await api('GET', '/security-status?format=csv');
    assert.match(String(csv.body), /WIN-SEC.*Systemlaufwerk nicht verschlüsselt/);

    const preview = await api('POST', '/device-groups/preview', { filter: { match: 'all', rules: [{ field: 'encryption', op: 'ne', value: 'encrypted' }] } });
    assert.equal(preview.status, 200, JSON.stringify(preview.body));
    assert.deepEqual(preview.body.items.map((i: { hostname: string }) => i.hostname).sort(), ['OLD-AGENT', 'WIN-SEC'], 'unknown counts as not encrypted');
    const nonCompliant = await api('POST', '/device-groups/preview', { filter: { rules: [{ field: 'securityCompliant', op: 'eq', value: false }] } });
    assert.deepEqual(nonCompliant.body.items.map((i: { hostname: string }) => i.hostname).sort(), ['OLD-AGENT', 'WIN-SEC']);
    assert.equal((await api('POST', '/device-groups/preview', { filter: { rules: [{ field: 'securityCompliant', op: 'eq', value: 'x' }] } })).status, 400);

    const rep = await api('POST', '/reports/preview', { source: 'security', columns: ['hostname', 'compliant', 'encryption', 'antivirusProducts', 'issueCount'], sort: { field: 'hostname', dir: 'asc' } });
    assert.equal(rep.status, 200, JSON.stringify(rep.body));
    assert.deepEqual(rep.body.rows.map((r: { hostname: string; issueCount: number }) => `${r.hostname}:${r.issueCount}`), ['LNX-SEC:0', 'WIN-SEC:2']);
    assert.equal(rep.body.rows[1].antivirusProducts, 'Microsoft Defender Antivirus');

    const dash = await api('GET', '/dashboard');
    assert.equal(dash.body.security.noncompliant, 1);
    assert.equal(dash.body.security.compliant, 1);
    const tick = await metricsTick(ctx.handle.db, ctx.config);
    assert.equal(tick.values['security.noncompliant'], 1);
    assert.equal(tick.values['security.unencrypted'], 1);
  });

  it('respects device scope and permissions', async () => {
    const none = await userWithGrants(ctx, 'sec-nobody', ['devices:read']);
    assert.equal((await api('GET', '/security-status', undefined, none.token)).status, 403);
    const reader = await userWithGrants(ctx, 'sec-reader', ['inventory:read']);
    assert.equal((await api('GET', '/security-status', undefined, reader.token)).body.total, 3);
  });
});

// ------------------------------------------------------------------ assets

describe('M7: assets without agent', () => {
  let ctx: TestCtx;
  let pc: EnrolledAgent;

  const api = async (method: Method, url: string, payload?: object, token = ctx.adminToken) => {
    const res = await ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(token), ...(payload && { payload }) });
    return { status: res.statusCode, body: (res.headers['content-type'] ?? '').includes('json') ? res.json() : res.body };
  };
  const inDays = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString().slice(0, 10);

  before(async () => {
    ctx = await setup();
    pc = await enrollOk(ctx, { hostname: 'PC-0815', os: 'windows' });
  });
  after(async () => ctx.close());

  it('creates, validates and links assets', async () => {
    const m = await api('POST', '/assets', {
      name: 'Monitor Empfang',
      type: 'monitor',
      manufacturer: 'Contoso',
      model: 'View 27',
      serialNumber: 'MON-1',
      inventoryNumber: 'INV-0001',
      macAddress: '00-1a-2b-3c-4d-5e',
      warrantyUntil: inDays(10),
      cost: 249.9,
      deviceId: pc.deviceId,
      location: 'Empfang',
    });
    assert.equal(m.status, 201, JSON.stringify(m.body));
    assert.equal(m.body.macAddress, '00:1A:2B:3C:4D:5E');
    assert.equal(m.body.deviceHostname, 'PC-0815');
    assert.equal(m.body.cost, 249.9);
    assert.equal(m.body.status, 'in_use');

    assert.equal((await api('POST', '/assets', { name: 'Dup', inventoryNumber: 'inv-0001' })).status, 409, 'inventory number unique (case-insensitive)');
    assert.equal((await api('POST', '/assets', { name: 'X', ipAddress: '999.1.1.1' })).status, 400);
    assert.equal((await api('POST', '/assets', { name: 'X', macAddress: 'zz' })).status, 400);
    assert.equal((await api('POST', '/assets', { name: 'X', type: 'toaster' })).status, 400);
    assert.equal((await api('POST', '/assets', { name: 'X', deviceId: '00000000-0000-4000-8000-000000000000' })).status, 400);

    const p = await api('POST', '/assets', { name: 'Drucker 2. OG', type: 'printer', ipAddress: '10.0.0.50', status: 'in_stock', warrantyUntil: inDays(-5) });
    const patched = await api('PATCH', `/assets/${p.body.id}`, { status: 'in_use', location: '2. OG' });
    assert.equal(patched.body.status, 'in_use');
    assert.equal(patched.body.ipAddress, '10.0.0.50', 'PATCH keeps omitted fields');
    assert.equal((await api('PATCH', `/assets/${p.body.id}`, { inventoryNumber: 'INV-0001' })).status, 409);

    const forDevice = await api('GET', `/devices/${pc.deviceId}/assets`);
    assert.deepEqual(forDevice.body.items.map((a: { name: string }) => a.name), ['Monitor Empfang']);
  });

  it('lists with search, filters and warranty window', async () => {
    assert.equal((await api('GET', '/assets?search=empfang')).body.total, 1);
    assert.equal((await api('GET', '/assets?search=PC-0815')).body.total, 1, 'search by linked device');
    assert.equal((await api('GET', '/assets?type=printer')).body.total, 1);
    const warranty = await api('GET', '/assets?warrantyDays=30&sort=warrantyUntil');
    assert.deepEqual(warranty.body.items.map((a: { name: string }) => a.name), ['Drucker 2. OG', 'Monitor Empfang'], 'expired first');
    assert.equal((await api('GET', '/assets?warrantyDays=5')).body.total, 1);
    const types = await api('GET', '/asset-types');
    assert.equal(types.body.types.find((t: { key: string }) => t.key === 'printer').label, 'Drucker');
  });

  it('imports CSV (German Excel format), matches by inventory number, reports errors', async () => {
    const csv = [
      'Bezeichnung;Typ;Status;Hersteller;Seriennummer;Inventarnummer;Standort;Garantie bis;Kosten;Gerät;Unbekannt',
      'Monitor Empfang;Monitor;In Benutzung;Contoso;MON-1;INV-0001;Empfang links;31.12.2030;1.234,56;PC-0815;x',
      'Telefon Zentrale;Telefon;Lager;Fabrikam;TEL-9;INV-0002;Zentrale;;;;',
      'Kaputt;Toaster;;;;INV-0003;;;;;',
      'Switch Keller;Switch;;;SW-1;;Keller;2030-01-01;;NICHT-DA;',
      'Doppelt;Monitor;;;;INV-0002;;;;;',
    ].join('\r\n');
    const dry = await api('POST', '/assets/import', { csv, dryRun: true });
    assert.equal(dry.status, 200, JSON.stringify(dry.body));
    assert.equal(dry.body.dryRun, true);
    assert.equal(dry.body.updated, 1);
    assert.equal(dry.body.created, 2);
    assert.equal(dry.body.skipped, 2);
    assert.deepEqual(dry.body.errors.map((e: { line: number }) => e.line), [4, 6]);
    assert.match(dry.body.errors[0].message, /Unbekannter Typ "Toaster"/);
    assert.deepEqual(dry.body.warnings.map((w: { line: number }) => w.line), [5]);
    assert.deepEqual(dry.body.unknownColumns, ['Unbekannt']);
    assert.equal((await api('GET', '/assets')).body.total, 2, 'dry run changes nothing');

    const real = await api('POST', '/assets/import', { csv });
    assert.equal(real.body.created, 2);
    const list = (await api('GET', '/assets?limit=100')).body.items as { name: string; location: string; warrantyUntil: string; cost: number; type: string; status: string }[];
    assert.equal(list.length, 4);
    const mon = list.find((a) => a.name === 'Monitor Empfang')!;
    assert.equal(mon.location, 'Empfang links');
    assert.equal(mon.warrantyUntil, '2030-12-31');
    assert.equal(mon.cost, 1234.56);
    const tel = list.find((a) => a.name === 'Telefon Zentrale')!;
    assert.equal(tel.type, 'phone');
    assert.equal(tel.status, 'in_stock');
    assert.equal(list.find((a) => a.name === 'Switch Keller')!.type, 'network');
    const audit = await api('GET', '/audit-log?action=asset.import');
    assert.equal(audit.body.items[0].details.created, 2);
  });

  it('exports CSV that re-imports without changes', async () => {
    const csv = await api('GET', '/assets?format=csv');
    assert.equal(csv.status, 200);
    const text = String(csv.body);
    assert.ok(text.startsWith('\uFEFFname;type;status;'), text.slice(0, 80));
    assert.match(text, /"Monitor Empfang";"monitor";"in_use"/);
    const again = await api('POST', '/assets/import', { csv: text, dryRun: true });
    assert.equal(again.body.errors.length, 0, JSON.stringify(again.body.errors));
    assert.equal(again.body.warnings.length, 0, 'linked device resolved by host name');
    // matched by inventory number (monitor, phone) or serial number (switch); the printer has neither
    assert.equal(again.body.updated, 3);
    assert.equal(again.body.created, 1);
  });

  it('report source, dashboard and permissions', async () => {
    const rep = await api('POST', '/reports/preview', { source: 'assets', columns: ['name', 'type', 'device', 'warrantyDaysLeft'], filters: [{ field: 'type', op: 'eq', value: 'monitor' }] });
    assert.equal(rep.status, 200, JSON.stringify(rep.body));
    assert.equal(rep.body.rows[0].device, 'PC-0815');
    assert.ok(rep.body.rows[0].warrantyDaysLeft > 365);
    const dash = await api('GET', '/dashboard');
    assert.equal(dash.body.assets.total, 4);
    assert.equal(dash.body.assets.warrantyExpired, 1);

    const reader = await userWithGrants(ctx, 'asset-reader', ['assets:read']);
    assert.equal((await api('GET', '/assets', undefined, reader.token)).status, 200);
    assert.equal((await api('POST', '/assets', { name: 'x' }, reader.token)).status, 403);
    assert.equal((await api('POST', '/assets/import', { csv: 'name\nx' }, reader.token)).status, 403);
    assert.equal((await api('GET', `/devices/${pc.deviceId}/assets`, undefined, reader.token)).status, 404, 'device outside the (empty) device scope');
    const helpdesk = await api('GET', '/roles');
    assert.ok(helpdesk.body.items.find((r: { name: string }) => r.name === 'Helpdesk').permissions.includes('assets:read'));

    const id = (await api('GET', '/assets?search=Telefon')).body.items[0].id;
    assert.equal((await api('DELETE', `/assets/${id}`)).status, 204);
    assert.equal((await api('GET', `/assets/${id}`)).status, 404);
  });
});
