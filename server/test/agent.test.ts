import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { eq } from 'drizzle-orm';
import { devices } from '../src/db/schema.ts';
import { initPki } from '../src/pki/ca.ts';
import {
  agentRequest,
  createEnrollmentToken,
  enroll,
  enrollOk,
  newAgentKey,
  sampleInventory,
  startAgentServer,
  type AgentServerHandle,
} from './agent-helpers.ts';
import { bearer, setup, userWithGrants, type TestCtx } from './helpers.ts';

describe('M1: enrollment, mTLS agent endpoint, inventory', () => {
  let ctx: TestCtx;
  let agentSrv: AgentServerHandle;
  before(async () => {
    ctx = await setup();
    agentSrv = await startAgentServer(ctx);
  });
  after(async () => {
    await agentSrv.close();
    await ctx.close();
  });

  const api = (method: 'GET' | 'POST' | 'DELETE', url: string, payload?: object, token = ctx.adminToken) =>
    ctx.app.inject({ method, url: `/api/v1${url}`, headers: bearer(token), ...(payload && { payload }) });
  const call = (path: string, body: unknown, a: { certPem?: string; keyPem?: string; caPem: string }) =>
    agentRequest(agentSrv.port, `/agent/v1${path}`, body, a);

  // ------------------------------------------------------------ enrollment tokens

  it('creates enrollment tokens with install commands; token is shown once', async () => {
    const t = await createEnrollmentToken(ctx, { name: 'Standort Nord', maxUses: 5, expiresInHours: 48 });
    assert.match(t.token, /^oce_/);
    assert.match(t.installCommands.windows, /agent-downloads\/windows\/\$arch/);
    assert.ok(t.installCommands.windows.includes(`--token '${t.token}'`));
    assert.ok(t.installCommands.linux.includes('/api/v1/agent-downloads/linux/$ARCH'));
    assert.ok(t.installCommands.macos.includes('/agent-downloads/macos/'));
    const list = (await api('GET', '/enrollment-tokens')).json();
    const listed = list.items.find((i: { id: string }) => i.id === t.id);
    assert.equal(listed.maxUses, 5);
    assert.equal(listed.token, undefined);
    assert.equal(listed.tokenHash, undefined);
  });

  it('requires devices:create for enrollment tokens', async () => {
    const { token } = await userWithGrants(ctx, 'viewer', ['devices:read']);
    assert.equal((await api('POST', '/enrollment-tokens', { name: 'x' }, token)).statusCode, 403);
  });

  it('rejects invalid, revoked, expired and used-up tokens', async () => {
    assert.equal((await enroll(ctx, 'oce_doesnotexist')).res.statusCode, 401);

    const revoked = await createEnrollmentToken(ctx, { name: 'revoked' });
    assert.equal((await api('DELETE', `/enrollment-tokens/${revoked.id}`)).statusCode, 204);
    assert.equal((await enroll(ctx, revoked.token)).res.statusCode, 401);

    const once = await createEnrollmentToken(ctx, { name: 'once', maxUses: 1 });
    assert.equal((await enroll(ctx, once.token)).res.statusCode, 200);
    assert.equal((await enroll(ctx, once.token)).res.statusCode, 401);

    const expired = await createEnrollmentToken(ctx, { name: 'expired' });
    const { enrollmentTokens } = await import('../src/db/schema.ts');
    await ctx.handle.db.update(enrollmentTokens).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(enrollmentTokens.id, expired.id));
    assert.equal((await enroll(ctx, expired.token)).res.statusCode, 401);
  });

  it('rejects a broken CSR without consuming the token', async () => {
    const t = await createEnrollmentToken(ctx, { name: 'csr', maxUses: 1 });
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v1/agent/enroll',
      payload: { token: t.token, csr: 'not a csr', hostname: 'X', os: 'linux', machineId: 'machine-broken-csr' },
    });
    assert.equal(res.statusCode, 400);
    assert.equal(res.json().error.code, 'invalid_csr');
    assert.equal((await enroll(ctx, t.token)).res.statusCode, 200, 'token still usable');
  });

  it('enrolls a device and issues a client cert bound to the device id', async () => {
    const t = await createEnrollmentToken(ctx, { name: 'enroll' });
    const { res } = await enroll(ctx, t.token, { hostname: 'PC-ENROLL', machineId: 'machine-enroll-1' });
    assert.equal(res.statusCode, 200);
    const body = res.json();
    assert.match(body.certificate, /BEGIN CERTIFICATE/);
    assert.equal(body.caCertificate, ctx.pki.caCertPem);
    assert.equal(body.agentUrl, 'https://cm.test.local:8443');
    const { X509Certificate } = await import('node:crypto');
    const cert = new X509Certificate(body.certificate);
    assert.ok(cert.subject.includes(`CN=${body.deviceId}`), 'CN is the server-assigned device id');
    assert.ok(cert.checkIssued(new X509Certificate(ctx.pki.caCertPem)));

    const dev = (await api('GET', `/devices/${body.deviceId}`)).json();
    assert.equal(dev.hostname, 'PC-ENROLL');
    assert.equal(dev.status, 'active');
    assert.equal(dev.online, false);

    const audit = (await api('GET', '/audit-log?action=device.enroll')).json();
    assert.ok(audit.items.some((e: { targetId: string }) => e.targetId === body.deviceId));
  });

  it('a registered machine cannot enroll again; after deletion it becomes a new device (REV-004)', async () => {
    const first = await enrollOk(ctx, { machineId: 'machine-reenroll', hostname: 'OLD-NAME' });
    const t = await createEnrollmentToken(ctx, { name: 'again' });
    const again = await enroll(ctx, t.token, { machineId: 'machine-reenroll', hostname: 'NEW-NAME' });
    assert.equal(again.res.statusCode, 409);
    assert.equal((await call('/heartbeat', { agentVersion: '0.2.0' }, first)).status, 200, 'existing certificate keeps working');
    assert.equal((await api('GET', `/devices/${first.deviceId}`)).json().hostname, 'OLD-NAME');

    assert.equal((await api('DELETE', `/devices/${first.deviceId}`)).statusCode, 204);
    const second = await enrollOk(ctx, { machineId: 'machine-reenroll', hostname: 'NEW-NAME' });
    assert.notEqual(second.deviceId, first.deviceId);
    assert.equal((await call('/heartbeat', { agentVersion: '0.2.0' }, first)).status, 403);
    assert.equal((await call('/heartbeat', { agentVersion: '0.2.0' }, second)).status, 200);
  });

  // ------------------------------------------------------------ mTLS

  it('refuses TLS connections without client certificate', async () => {
    await assert.rejects(call('/heartbeat', { agentVersion: 'x' }, { caPem: ctx.pki.caCertPem }));
  });

  it('refuses client certificates from a foreign CA', async () => {
    const foreign = await initPki(mkdtempSync(join(tmpdir(), 'foreign-pki-')), ['localhost']);
    const key = await newAgentKey();
    const cert = await foreign.signClientCsr(key.csrPem, '00000000-0000-0000-0000-000000000000', 30);
    await assert.rejects(call('/heartbeat', { agentVersion: 'x' }, { certPem: cert.pem, keyPem: key.keyPem, caPem: ctx.pki.caCertPem }));
  });

  it('heartbeat updates last contact and requests the first inventory', async () => {
    const agent = await enrollOk(ctx, { hostname: 'PC-HB' });
    const hb = await call('/heartbeat', { agentVersion: '0.2.1', loggedOnUsers: ['CONTOSO\\anna'] }, agent);
    assert.equal(hb.status, 200);
    assert.equal(hb.body.inventoryRequested, true);
    assert.equal(hb.body.renewCertificate, false);
    assert.equal(hb.body.heartbeatSeconds, 60);

    const dev = (await api('GET', `/devices/${agent.deviceId}`)).json();
    assert.equal(dev.online, true);
    assert.equal(dev.agentVersion, '0.2.1');
    assert.equal(dev.loggedOnUser, 'CONTOSO\\anna');
    assert.equal(dev.lastIp, '127.0.0.1');
  });

  it('validates heartbeat and inventory payloads', async () => {
    const agent = await enrollOk(ctx);
    assert.equal((await call('/heartbeat', {}, agent)).status, 400);
    assert.equal((await call('/inventory', { collectedAt: 'not-a-date' }, agent)).status, 400);
  });

  it('stores inventory, normalises software and records history', async () => {
    const agent = await enrollOk(ctx, { hostname: 'PC-INV' });
    assert.equal((await call('/inventory', sampleInventory(), agent)).status, 204);

    const dev = (await api('GET', `/devices/${agent.deviceId}`)).json();
    assert.equal(dev.manufacturer, 'Contoso');
    assert.equal(dev.serialNumber, 'SN-TEST-0001');
    assert.equal(dev.osVersion, 'Windows 11 Pro 10.0.22631');
    assert.equal(dev.inventoryRequested, false);
    assert.ok(dev.lastInventoryAt);

    const inv = (await api('GET', `/devices/${agent.deviceId}/inventory`)).json();
    assert.equal(inv.hardware.cpu.cores, 8);
    assert.equal(inv.services[0].name, 'Spooler');
    assert.equal(inv.software, undefined, 'software is served separately');

    const sw = (await api('GET', `/devices/${agent.deviceId}/software?search=fire`)).json();
    assert.deepEqual(sw.items.map((s: { name: string }) => s.name), ['Mozilla Firefox']);

    // second inventory: firefox updated, 7-zip removed, VLC added, RAM upgraded, new admin
    const next = sampleInventory({
      software: [
        { name: 'Mozilla Firefox', version: '132.0', publisher: 'Mozilla', source: 'registry', arch: 'x64' },
        { name: 'VLC media player', version: '3.0.21', publisher: 'VideoLAN', source: 'registry', arch: 'x64' },
      ],
      localGroups: [{ name: 'Administrators', members: ['Administrator', 'eve'] }],
    });
    (next.hardware as { memoryBytes: number }).memoryBytes = 68719476736;
    assert.equal((await call('/inventory', next, agent)).status, 204);

    const hist = (await api('GET', `/devices/${agent.deviceId}/history?limit=100`)).json();
    const facts = hist.items.map((h: { category: string; change: string; itemKey: string }) => `${h.category}:${h.change}:${h.itemKey}`);
    assert.ok(facts.includes('device:added:initial inventory'));
    assert.ok(facts.includes('software:changed:Mozilla Firefox (x64)'));
    assert.ok(facts.includes('software:removed:7-Zip 23.01 (x64) (x64)'));
    assert.ok(facts.includes('software:added:VLC media player (x64)'));
    assert.ok(facts.includes('hardware:changed:memoryBytes'));
    assert.ok(facts.includes('group:changed:Administrators'));
    assert.equal(hist.total, 6, `unexpected history: ${facts.join(' | ')}`);

    const ffChange = hist.items.find((h: { itemKey: string }) => h.itemKey === 'Mozilla Firefox (x64)');
    assert.equal(ffChange.oldValue, '131.0');
    assert.equal(ffChange.newValue, '132.0');

    const swOnly = (await api('GET', `/devices/${agent.deviceId}/history?category=software`)).json();
    assert.equal(swOnly.total, 3);
  });

  it('identical inventory produces no history noise (free space / IPs / run state ignored)', async () => {
    const agent = await enrollOk(ctx);
    await call('/inventory', sampleInventory(), agent);
    const noisy = sampleInventory({
      disks: [{ name: 'C:', mount: 'C:\\', fsType: 'NTFS', sizeBytes: 512000000000, freeBytes: 1 }],
      network: [{ name: 'Ethernet', mac: '00:11:22:33:44:55', up: true, ipv4: ['10.9.9.9'], ipv6: [] }],
      services: [{ name: 'Spooler', displayName: 'Print Spooler', state: 'Stopped', startMode: 'Auto' }],
      loggedOnUsers: [],
    });
    await call('/inventory', noisy, agent);
    assert.equal((await api('GET', `/devices/${agent.deviceId}/history`)).json().total, 1);
  });

  it('inventory request flag is set by admins and delivered via heartbeat', async () => {
    const agent = await enrollOk(ctx);
    await call('/inventory', sampleInventory(), agent);
    assert.equal((await call('/heartbeat', { agentVersion: '1' }, agent)).body.inventoryRequested, false);
    assert.equal((await api('POST', `/devices/${agent.deviceId}/inventory-request`)).statusCode, 202);
    assert.equal((await call('/heartbeat', { agentVersion: '1' }, agent)).body.inventoryRequested, true);
  });

  it('signals renewal near expiry and renews over mTLS', async () => {
    const agent = await enrollOk(ctx);
    await ctx.handle.db.update(devices).set({ certExpiresAt: new Date(Date.now() + 5 * 86_400_000) }).where(eq(devices.id, agent.deviceId));
    assert.equal((await call('/heartbeat', { agentVersion: '1' }, agent)).body.renewCertificate, true);

    const key = await newAgentKey();
    const renewed = await call('/certificate/renew', { csr: key.csrPem }, agent);
    assert.equal(renewed.status, 200);
    const next = { ...agent, certPem: renewed.body.certificate, keyPem: key.keyPem };
    assert.equal((await call('/heartbeat', { agentVersion: '1' }, next)).body.renewCertificate, false);
    assert.equal((await call('/heartbeat', { agentVersion: '1' }, agent)).status, 403, 'old certificate is superseded');
  });

  it('revoked devices are locked out immediately', async () => {
    const agent = await enrollOk(ctx);
    assert.equal((await call('/heartbeat', { agentVersion: '1' }, agent)).status, 200);
    // body-less POST that still sends Content-Type: application/json (common client behaviour)
    const rev = await ctx.app.inject({
      method: 'POST',
      url: `/api/v1/devices/${agent.deviceId}/revoke`,
      headers: { ...bearer(ctx.adminToken), 'content-type': 'application/json' },
    });
    assert.equal(rev.statusCode, 200);
    assert.equal(rev.json().status, 'revoked');
    assert.equal((await call('/heartbeat', { agentVersion: '1' }, agent)).status, 403);
    assert.equal((await call('/inventory', sampleInventory(), agent)).status, 403);
  });

  // ------------------------------------------------------------ devices API

  it('lists devices with filters and enforces permissions', async () => {
    await enrollOk(ctx, { hostname: 'MAC-DESIGN-01', os: 'macos' });
    const lin = await enrollOk(ctx, { hostname: 'LNX-WEB-01', os: 'linux' });
    await call('/heartbeat', { agentVersion: '1' }, lin);

    const macs = (await api('GET', '/devices?os=macos')).json();
    assert.deepEqual(macs.items.map((d: { hostname: string }) => d.hostname), ['MAC-DESIGN-01']);

    const online = (await api('GET', '/devices?online=true&os=linux')).json();
    assert.deepEqual(online.items.map((d: { hostname: string }) => d.hostname), ['LNX-WEB-01']);
    const offlineLinux = (await api('GET', '/devices?online=false&os=linux')).json();
    assert.equal(offlineLinux.total, 0);

    const search = (await api('GET', '/devices?search=web')).json();
    assert.equal(search.total, 1);
    assert.equal((await api('GET', '/devices?search=100%25')).statusCode, 200, 'LIKE wildcards are escaped');

    assert.equal((await api('GET', '/devices?os=amiga')).statusCode, 400);

    const { token } = await userWithGrants(ctx, 'devreader', ['devices:read']);
    assert.equal((await api('GET', '/devices', undefined, token)).statusCode, 200);
    assert.equal((await api('GET', `/devices/${lin.deviceId}/software`, undefined, token)).statusCode, 403, 'inventory:read needed');
    assert.equal((await api('POST', `/devices/${lin.deviceId}/revoke`, undefined, token)).statusCode, 403);
    assert.equal((await api('DELETE', `/devices/${lin.deviceId}`, undefined, token)).statusCode, 403);
  });

  it('deletes devices including their inventory', async () => {
    const agent = await enrollOk(ctx);
    await call('/inventory', sampleInventory(), agent);
    assert.equal((await api('DELETE', `/devices/${agent.deviceId}`)).statusCode, 204);
    assert.equal((await api('GET', `/devices/${agent.deviceId}`)).statusCode, 404);
    assert.equal((await call('/heartbeat', { agentVersion: '1' }, agent)).status, 403);
  });
});

describe('M1: agent downloads', () => {
  let ctx: TestCtx;
  before(async () => {
    ctx = await setup();
    mkdirSync(ctx.config.AGENT_DOWNLOAD_DIR, { recursive: true });
    writeFileSync(join(ctx.config.AGENT_DOWNLOAD_DIR, 'opencm-agent-windows-amd64.exe'), 'MZ-fake-binary');
    writeFileSync(join(ctx.config.AGENT_DOWNLOAD_DIR, 'opencm-agent-darwin-arm64'), 'fake-macho');
    writeFileSync(join(ctx.config.AGENT_DOWNLOAD_DIR, 'version.txt'), '0.2.0\n');
    writeFileSync(join(ctx.config.AGENT_DOWNLOAD_DIR, 'unrelated.txt'), 'x');
  });
  after(async () => ctx.close());

  it('lists binaries publicly with checksums', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/v1/agent-downloads' });
    assert.equal(res.statusCode, 200);
    const body = res.json();
    assert.equal(body.version, '0.2.0');
    assert.deepEqual(body.items.map((i: { os: string; arch: string }) => `${i.os}/${i.arch}`), ['macos/arm64', 'windows/amd64']);
    const { createHash } = await import('node:crypto');
    assert.equal(body.items[1].sha256, createHash('sha256').update('MZ-fake-binary').digest('hex'));
  });

  it('serves a binary and 404s for missing platforms', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/v1/agent-downloads/windows/amd64' });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body, 'MZ-fake-binary');
    assert.match(String(res.headers['content-disposition']), /opencm-agent\.exe/);
    assert.equal((await ctx.app.inject({ method: 'GET', url: '/api/v1/agent-downloads/linux/arm64' })).statusCode, 404);
    assert.equal((await ctx.app.inject({ method: 'GET', url: '/api/v1/agent-downloads/..%2F..%2Fetc/passwd' })).statusCode, 400);
  });
});
