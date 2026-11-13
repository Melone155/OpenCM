import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { eq } from 'drizzle-orm';
import { metricsTick } from '../src/dashboard.ts';
import { devices, webhookDeliveries } from '../src/db/schema.ts';
import { ingestInventory } from '../src/inventory/ingest.ts';
import { InventorySchema } from '../src/inventory/schema.ts';
import { evaluateLicenses } from '../src/licenses.ts';
import { blockedAddress, MAX_ATTEMPTS, webhookTick, type DeliverDeps } from '../src/webhooks/deliver.ts';
import { initSecretBox } from '../src/auth/secretbox.ts';
import { enrollOk, sampleInventory, type EnrolledAgent } from './agent-helpers.ts';
import { bearer, setup, userWithGrants, type TestCtx } from './helpers.ts';

type Method = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';

/** Fake HTTP for webhooks: records requests, answers with the queued status codes. */
function fakeHttp() {
  const calls: { url: string; headers: Record<string, string>; body: string }[] = [];
  const statuses: number[] = [];
  let now = new Date('2026-11-12T10:00:00Z');
  const deps: DeliverDeps = {
    fetch: async (url, init) => {
      calls.push({ url, headers: init.headers, body: init.body });
      const status = statuses.shift() ?? 200;
      return { status, ok: status < 300 };
    },
    resolve: async (host) => (host === 'evil-dns.example.test' ? ['169.254.169.254'] : ['203.0.113.10']),
    now: () => now,
  };
  return { deps, calls, statuses, advance: (ms: number) => (now = new Date(now.getTime() + ms)), at: () => now };
}

describe('M6: dashboard, reports, webhooks, licenses', () => {
  let ctx: TestCtx;
  const http = fakeHttp();
  let w1: EnrolledAgent;
  let w2: EnrolledAgent;
  let l1: EnrolledAgent;

  before(async () => {
    ctx = await setup({}, { webhookDeps: http.deps });
    w1 = await enrollOk(ctx, { hostname: 'WIN-A', os: 'windows' });
    w2 = await enrollOk(ctx, { hostname: 'WIN-B', os: 'windows' });
    l1 = await enrollOk(ctx, { hostname: 'LNX-A', os: 'linux' });
    const inv = (software: object[]) => InventorySchema.parse(sampleInventory({ software }));
    await ingestInventory(ctx.handle.db, w1.deviceId, inv([{ name: 'Notepad++ (64-bit x64)', version: '8.6.4', publisher: 'Notepad++ Team', source: 'registry', arch: 'x64' }, { name: 'Mozilla Firefox', version: '131.0', publisher: 'Mozilla', source: 'registry', arch: 'x64' }]));
    await ingestInventory(ctx.handle.db, w2.deviceId, inv([{ name: 'Notepad++ (64-bit x64)', version: '8.5.0', publisher: 'Notepad++ Team', source: 'registry', arch: 'x64' }]));
    await ingestInventory(ctx.handle.db, l1.deviceId, inv([{ name: 'htop', version: '3.3.0', publisher: '', source: 'dpkg', arch: 'amd64' }]));
    await ctx.handle.db.update(devices).set({ lastSeenAt: new Date() }).where(eq(devices.id, w1.deviceId));
  });
  after(async () => ctx.close());

  const api = async (method: Method, url: string, payload?: object, token = ctx.adminToken) => {
    const res = await ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(token), ...(payload && { payload }) });
    return { status: res.statusCode, body: (res.headers['content-type'] ?? '').includes('json') ? res.json() : res.body };
  };

  // ------------------------------------------------------------ reports

  it('lists report sources the caller may read', async () => {
    const all = (await api('GET', '/report-sources')).body.items.map((s: { key: string }) => s.key);
    assert.deepEqual(all.sort(), ['assets', 'devices', 'licenses', 'patches', 'security', 'software', 'tasks', 'vulnerabilities']);
    const limited = await userWithGrants(ctx, 'rep-devices', ['reports:read', 'devices:read']);
    assert.deepEqual((await api('GET', '/report-sources', undefined, limited.token)).body.items.map((s: { key: string }) => s.key), ['devices']);
  });

  it('previews reports with whitelisted columns, filters and sorting', async () => {
    const r = await api('POST', '/reports/preview', { source: 'devices', columns: ['hostname', 'os', 'online'], filters: [{ field: 'os', op: 'eq', value: 'WINDOWS' }], sort: { field: 'hostname', dir: 'desc' } });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.rows, [
      { hostname: 'WIN-B', os: 'windows', online: false },
      { hostname: 'WIN-A', os: 'windows', online: true },
    ]);
    assert.deepEqual(r.body.columns[2], { key: 'online', label: 'Online', type: 'boolean' });

    const sw = await api('POST', '/reports/preview', { source: 'software', columns: ['hostname', 'name', 'version'], filters: [{ field: 'name', op: 'contains', value: 'notepad++' }, { field: 'version', op: 'starts', value: '8.6' }] });
    assert.deepEqual(sw.body.rows, [{ hostname: 'WIN-A', name: 'Notepad++ (64-bit x64)', version: '8.6.4' }]);

    const like = await api('POST', '/reports/preview', { source: 'software', columns: ['name'], filters: [{ field: 'name', op: 'contains', value: '%' }] });
    assert.equal(like.body.rows.length, 0, '% is matched literally, not as a wildcard');
    const inList = await api('POST', '/reports/preview', { source: 'devices', columns: ['hostname'], filters: [{ field: 'hostname', op: 'in', value: ['win-a', 'lnx-a'] }] });
    assert.equal(inList.body.rows.length, 2);
    const empty = await api('POST', '/reports/preview', { source: 'devices', columns: ['hostname'], filters: [{ field: 'loggedOnUser', op: 'notempty' }] });
    assert.equal(empty.body.rows.length, 3);
    const trunc = await api('POST', '/reports/preview', { source: 'devices', columns: ['hostname'], limit: 2 });
    assert.equal(trunc.body.truncated, true);
  });

  it('rejects unknown columns, operators and wrong value types (no SQL from the client)', async () => {
    const bad = [
      { source: 'devices', columns: ['hostname; drop table devices'] },
      { source: 'devices', columns: ['hostname'], filters: [{ field: 'cert_fingerprint', op: 'eq', value: 'x' }] },
      { source: 'devices', columns: ['hostname'], filters: [{ field: 'hostname', op: 'regex', value: '.*' }] },
      { source: 'devices', columns: ['hostname'], filters: [{ field: 'lastSeenAt', op: 'gt', value: 'yesterday' }] },
      { source: 'devices', columns: ['hostname'], filters: [{ field: 'online', op: 'gt', value: true }] },
      { source: 'devices', columns: ['hostname'], filters: [{ field: 'os', op: 'contains', value: { $ne: 1 } }] },
      { source: 'devices', columns: ['hostname'], sort: { field: '1; select 1', dir: 'asc' } },
      { source: 'users', columns: ['username'] },
    ];
    for (const b of bad) assert.equal((await api('POST', '/reports/preview', b)).status, 400, JSON.stringify(b));
    const noPerm = await userWithGrants(ctx, 'rep-only', ['reports:read']);
    assert.equal((await api('POST', '/reports/preview', { source: 'devices' }, noPerm.token)).status, 403);
  });

  it('respects the device scope of the caller', async () => {
    const g = await api('POST', '/device-groups', { kind: 'static', name: 'Nur Linux', deviceIds: [l1.deviceId] });
    const u = await userWithGrants(ctx, 'rep-scoped', ['reports:read']);
    const role = await api('POST', '/roles', { name: 'inv-readers', permissions: ['inventory:read'] });
    await api('PATCH', `/users/${u.userId}`, { roleAssignments: [{ roleId: role.body.id, scopeDeviceGroupIds: [g.body.id] }, { roleId: u.roleId, scopeDeviceGroupIds: null }] });
    const r = await api('POST', '/reports/preview', { source: 'software', columns: ['hostname', 'name'] }, u.token);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.rows, [{ hostname: 'LNX-A', name: 'htop' }]);
  });

  it('saves private and shared reports and exports CSV', async () => {
    const other = await userWithGrants(ctx, 'rep-other', ['reports:read', 'devices:read']);
    const priv = await api('POST', '/reports', { name: 'Meine Geräte', source: 'devices', columns: ['hostname', 'os'], filters: [], shared: false });
    assert.equal(priv.status, 201, JSON.stringify(priv.body));
    const shared = await api('POST', '/reports', { name: 'Windows=Geräte', source: 'devices', columns: ['hostname', 'os'], filters: [{ field: 'os', op: 'eq', value: 'windows' }], shared: true });
    assert.equal((await api('GET', '/reports', undefined, other.token)).body.items.length, 1, 'only the shared report');
    assert.equal((await api('GET', `/reports/${priv.body.id}`, undefined, other.token)).status, 404);
    assert.equal((await api('PATCH', `/reports/${shared.body.id}`, { name: 'x' }, other.token)).status, 403, 'only the owner edits');
    assert.equal((await api('POST', '/reports', { name: 'bad', source: 'devices', columns: ['nope'] })).status, 400);

    const json = await api('GET', `/reports/${shared.body.id}/run`, undefined, other.token);
    assert.equal(json.body.rows.length, 2);
    const csv = await api('GET', `/reports/${shared.body.id}/run?format=csv`);
    assert.ok(String(csv.body).startsWith('﻿"Gerät";"Betriebssystem"'));
    assert.match(String(csv.body), /"WIN-A";"windows"/);
    assert.equal((await api('DELETE', `/reports/${priv.body.id}`)).status, 204);
  });

  // ------------------------------------------------------------ licenses

  it('tracks license usage against the inventory and flags overuse', async () => {
    const l = await api('POST', '/licenses', { name: 'Notepad++ Volume', vendor: 'Don Ho', softwarePattern: 'Notepad++*', seats: 1, expiresAt: '2026-11-30', cost: 120.5 });
    assert.equal(l.status, 201, JSON.stringify(l.body));
    assert.equal(l.body.used, 2);
    assert.equal(l.body.available, -1);
    assert.equal(l.body.overused, true);
    assert.equal(l.body.devices.length, 2);
    assert.equal(l.body.cost, '120.50');
    const list = (await api('GET', '/licenses')).body.items;
    assert.equal(list[0].overused, true);
    assert.equal(typeof list[0].daysToExpiry, 'number');
    assert.equal('softwareRegex' in list[0], false);
    const p = await api('PATCH', `/licenses/${l.body.id}`, { seats: 5, publisherPattern: 'Notepad++ Team' });
    assert.equal(p.body.overused, false);
    assert.equal(p.body.used, 2);
    const ff = await api('POST', '/licenses', { name: 'Firefox', softwarePattern: 'Mozilla Firefox', seats: 10 });
    assert.equal(ff.body.used, 1);
    const rep = await api('POST', '/reports/preview', { source: 'licenses', columns: ['name', 'seats', 'used', 'overused'], sort: { field: 'name', dir: 'asc' } });
    assert.deepEqual(rep.body.rows[0], { name: 'Firefox', seats: 10, used: 1, overused: false });
  });

  // ------------------------------------------------------------ webhooks

  let hookId = '';
  let secret = '';

  it('validates webhook URLs (https, no link-local/metadata, no credentials)', async () => {
    for (const url of ['http://hooks.example.test/x', 'https://169.254.169.254/latest', 'https://[fe80::1]/x', 'https://user:pw@hooks.example.test/', 'ftp://x.test/', 'not a url', 'https://metadata.google.internal/']) {
      assert.equal((await api('POST', '/webhooks', { name: 'bad', url, events: ['*'] })).status, 400, url);
    }
    assert.equal(blockedAddress('169.254.1.1'), true);
    assert.equal(blockedAddress('10.0.0.1'), false, 'internal systems (e.g. a ticket system) remain allowed');
    assert.equal((await api('POST', '/webhooks', { name: 'bad', url: 'https://hooks.example.test/', events: ['no.such.event'] })).status, 400);
  });

  it('creates webhooks, shows the secret once and signs test deliveries', async () => {
    const r = await api('POST', '/webhooks', { name: 'Ticketsystem', url: 'https://hooks.example.test/opencm', events: ['device.enrolled', 'license.overused'] });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    hookId = r.body.id;
    secret = r.body.secret;
    assert.ok(secret.length >= 24);
    assert.equal('secretEnc' in r.body, false);
    const list = (await api('GET', '/webhooks')).body.items;
    assert.equal(list[0].secret, undefined, 'the secret is never shown again');

    const t = await api('POST', `/webhooks/${hookId}/test`);
    assert.equal(t.status, 200, JSON.stringify(t.body));
    assert.equal(t.body.status, 'succeeded');
    const call = http.calls.at(-1)!;
    assert.equal(call.url, 'https://hooks.example.test/opencm');
    assert.equal(call.headers['x-opencm-event'], 'webhook.test');
    const expected = `sha256=${createHmac('sha256', secret).update(`${call.headers['x-opencm-timestamp']}.${call.body}`).digest('hex')}`;
    assert.equal(call.headers['x-opencm-signature'], expected);
    assert.equal(JSON.parse(call.body).id, t.body.id);
  });

  it('queues events in the outbox and retries with back-off until success or the last attempt', async () => {
    const secretBox = await initSecretBox(ctx.config.PKI_DIR);
    await enrollOk(ctx, { hostname: 'WIN-NEW', os: 'windows' });
    let pending = await ctx.handle.db.select().from(webhookDeliveries).where(eq(webhookDeliveries.event, 'device.enrolled'));
    assert.equal(pending.length, 1);
    assert.equal(pending[0]!.status, 'pending');
    assert.equal((pending[0]!.payload as { data: { hostname: string } }).data.hostname, 'WIN-NEW');

    http.statuses.push(500);
    // deliveries are due "now" (real time) – the fake clock runs ahead of it
    http.advance(Date.now() - http.at().getTime() + 1000);
    let r = await webhookTick(ctx.handle.db, ctx.config, secretBox, http.deps);
    assert.deepEqual(r, { attempted: 1, succeeded: 0, failed: 1 });
    pending = await ctx.handle.db.select().from(webhookDeliveries).where(eq(webhookDeliveries.event, 'device.enrolled'));
    assert.equal(pending[0]!.attempts, 1);
    assert.equal(pending[0]!.lastError, 'HTTP 500');
    assert.equal((await webhookTick(ctx.handle.db, ctx.config, secretBox, http.deps)).attempted, 0, 'waits for the back-off');
    http.advance(61_000);
    r = await webhookTick(ctx.handle.db, ctx.config, secretBox, http.deps);
    assert.equal(r.succeeded, 1);

    // a receiver that always fails: the delivery ends as failed after MAX_ATTEMPTS
    const ov = await api('POST', '/licenses', { name: 'Overused', softwarePattern: 'htop', seats: 0 });
    assert.equal(ov.body.overused, true);
    assert.equal((await evaluateLicenses(ctx.handle.db)).newlyOverused >= 1, true);
    assert.equal((await evaluateLicenses(ctx.handle.db)).newlyOverused, 0, 'only on the transition');
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      http.statuses.push(503);
      http.advance(7 * 3600_000);
      await webhookTick(ctx.handle.db, ctx.config, secretBox, http.deps);
    }
    const lic = await ctx.handle.db.select().from(webhookDeliveries).where(eq(webhookDeliveries.event, 'license.overused'));
    assert.ok(lic.length >= 1);
    assert.ok(lic.every((d) => d.status === 'failed' && d.attempts === MAX_ATTEMPTS), JSON.stringify(lic.map((d) => [d.status, d.attempts])));

    const re = await api('POST', `/webhook-deliveries/${lic[0]!.id}/redeliver`);
    assert.equal(re.body.status, 'pending');
    assert.equal(re.body.attempts, 0);
    const log = await api('GET', `/webhooks/${hookId}/deliveries?status=succeeded`);
    assert.ok(log.body.items.length >= 2);
  });

  it('refuses targets that resolve to link-local addresses at delivery time', async () => {
    const r = await api('POST', '/webhooks', { name: 'dns', url: 'https://evil-dns.example.test/', events: ['webhook.test'] });
    const t = await api('POST', `/webhooks/${r.body.id}/test`);
    assert.equal(t.body.status, 'pending');
    assert.match(t.body.lastError, /link-local/);
  });

  // ------------------------------------------------------------ dashboard & metrics

  it('dashboard shows only permitted sections; metrics build daily trends', async () => {
    const m = await metricsTick(ctx.handle.db, ctx.config);
    assert.equal(m.values['devices.total'], 4);
    assert.equal(m.values['devices.online'], 1);
    await metricsTick(ctx.handle.db, ctx.config); // same day: upsert, no duplicate
    const d = (await api('GET', '/dashboard')).body;
    assert.equal(d.devices.total, 4);
    assert.equal(d.devices.byOs.windows, 3);
    assert.ok(d.licenses.overused >= 1);
    assert.equal(d.trends['devices.total'].length, 1);
    assert.equal(d.trends['devices.total'][0].value, 4);

    const limited = await userWithGrants(ctx, 'dash-dev', ['devices:read']);
    const ld = (await api('GET', '/dashboard', undefined, limited.token)).body;
    assert.ok(ld.devices);
    assert.equal(ld.vulnerabilities, undefined);
    assert.equal(ld.licenses, undefined);
    assert.deepEqual(Object.keys(ld.trends).sort(), ['devices.online', 'devices.stale7d', 'devices.total']);
  });
});
