import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { coversGrant } from '../src/auth/escalation.ts';
import { hashPassword, verifyPassword } from '../src/auth/password.ts';
import { ALL_PERMISSIONS, hasPermission, isValidGrant } from '../src/auth/permissions.ts';
import { generateToken, hashToken } from '../src/auth/tokens.ts';
import { agentPublicUrl, agentTlsHostnames, loadConfig } from '../src/config.ts';

describe('permissions', () => {
  it('matches exact, module wildcard and global wildcard', () => {
    assert.equal(hasPermission(['users:read'], 'users:read'), true);
    assert.equal(hasPermission(['users:read'], 'users:create'), false);
    assert.equal(hasPermission(['users:*'], 'users:delete'), true);
    assert.equal(hasPermission(['users:*'], 'roles:read'), false);
    assert.equal(hasPermission(['*'], 'scripts:approve'), true);
    assert.equal(hasPermission([], 'users:read'), false);
  });

  it('does not treat a module prefix as wildcard', () => {
    // "device:*" must not match "devices:read" / "device_groups:read"
    assert.equal(hasPermission(['device:*'], 'devices:read'), false);
    assert.equal(hasPermission(['devices:*'], 'device_groups:read'), false);
  });

  it('validates grants against the catalogue', () => {
    assert.equal(isValidGrant('*'), true);
    assert.equal(isValidGrant('scripts:approve'), true);
    assert.equal(isValidGrant('scripts:*'), true);
    assert.equal(isValidGrant('audit:delete'), false);
    assert.equal(isValidGrant('nope:read'), false);
    assert.equal(isValidGrant('users'), false);
    assert.ok(ALL_PERMISSIONS.length > 40);
  });
});

describe('escalation guard', () => {
  it('only lets actors hand out what they hold', () => {
    assert.equal(coversGrant(['*'], '*'), true);
    assert.equal(coversGrant(['users:*'], '*'), false);
    assert.equal(coversGrant(['users:*'], 'users:delete'), true);
    assert.equal(coversGrant(['users:read'], 'users:*'), false);
    assert.equal(coversGrant(['users:read', 'users:create', 'users:update', 'users:delete'], 'users:*'), true);
    assert.equal(coversGrant(['users:read'], 'roles:read'), false);
  });
});

describe('password hashing', () => {
  it('hashes with argon2id and verifies', async () => {
    const h = await hashPassword('correct horse battery staple');
    assert.match(h, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    assert.equal(await verifyPassword(h, 'correct horse battery staple'), true);
    assert.equal(await verifyPassword(h, 'wrong'), false);
    assert.equal(await verifyPassword('garbage', 'x'), false);
    assert.notEqual(await hashPassword('same'), await hashPassword('same'));
  });
});

describe('config', () => {
  it('treats empty env values as unset (docker compose ${VAR:-})', () => {
    const c = loadConfig({ BOOTSTRAP_ADMIN_USER: '', BOOTSTRAP_ADMIN_PASSWORD: '', AGENT_PUBLIC_URL: '', PUBLIC_URL: 'https://cm.example.org' });
    assert.equal(c.BOOTSTRAP_ADMIN_USER, undefined);
    assert.equal(agentPublicUrl(c), 'https://cm.example.org:8443');
    assert.deepEqual(agentTlsHostnames(loadConfig({ PUBLIC_URL: 'https://cm.example.org', AGENT_TLS_HOSTNAMES: '10.0.0.5, cm-intern' })), [
      'cm.example.org',
      'localhost',
      '10.0.0.5',
      'cm-intern',
    ]);
  });

  it('rejects invalid values with a readable message', () => {
    assert.throws(() => loadConfig({ PORT: 'abc' }), /PORT/);
  });
});

describe('inventory diff', () => {
  it('reports added/removed/changed and ignores volatile data', async () => {
    const { InventorySchema } = await import('../src/inventory/schema.ts');
    const { diffInventories } = await import('../src/inventory/diff.ts');
    const base = {
      collectedAt: '2026-11-12T10:00:00Z',
      software: [{ name: 'A', version: '1' }, { name: 'B', version: '1' }],
      disks: [{ name: 'C:', sizeBytes: 100, freeBytes: 50 }],
      services: [{ name: 'svc', state: 'Running', startMode: 'Auto' }],
    };
    const next = {
      ...base,
      software: [{ name: 'A', version: '2' }, { name: 'C', version: '1' }],
      disks: [{ name: 'C:', sizeBytes: 100, freeBytes: 10 }],
      services: [{ name: 'svc', state: 'Stopped', startMode: 'Auto' }],
    };
    const d = diffInventories(InventorySchema.parse(base), InventorySchema.parse(next));
    assert.deepEqual(
      d.map((x) => `${x.category}:${x.change}:${x.itemKey}`).sort(),
      ['software:added:C', 'software:changed:A', 'software:removed:B'],
    );
  });
});

describe('schedules', () => {
  it('computes cron occurrences in the job time zone (incl. DST)', async () => {
    const { nextCronRun, assertCron } = await import('../src/jobs/schedule.ts');
    // 03:00 Berlin = 02:00 UTC in winter, 01:00 UTC in summer
    assert.equal(nextCronRun('0 3 * * *', 'Europe/Berlin', new Date('2026-01-10T12:00:00Z')).toISOString(), '2026-01-11T02:00:00.000Z');
    assert.equal(nextCronRun('0 3 * * *', 'Europe/Berlin', new Date('2026-07-10T12:00:00Z')).toISOString(), '2026-07-11T01:00:00.000Z');
    assert.equal(nextCronRun('*/15 * * * 1-5', 'UTC', new Date('2026-11-13T23:50:00Z')).toISOString(), '2026-11-16T00:00:00.000Z'); // Fri → Mon
    assert.throws(() => assertCron('0 3 * *', 'UTC'), /5 fields/);
    assert.throws(() => assertCron('61 * * * *', 'UTC'));
  });

  it('evaluates maintenance windows incl. windows across midnight', async () => {
    const { inMaintenanceWindow } = await import('../src/jobs/schedule.ts');
    const workdaysNight = { days: [1, 2, 3, 4, 5], start: '22:00', end: '05:00' };
    // 2026-11-16 is a Monday
    assert.equal(inMaintenanceWindow(new Date('2026-11-16T22:30:00Z'), workdaysNight, 'UTC'), true); // Mon 22:30
    assert.equal(inMaintenanceWindow(new Date('2026-11-17T04:59:00Z'), workdaysNight, 'UTC'), true); // Tue 04:59 (Mon window)
    assert.equal(inMaintenanceWindow(new Date('2026-11-17T05:00:00Z'), workdaysNight, 'UTC'), false);
    assert.equal(inMaintenanceWindow(new Date('2026-11-16T03:00:00Z'), workdaysNight, 'UTC'), false); // Mon 03:00 → Sunday's window, not allowed
    assert.equal(inMaintenanceWindow(new Date('2026-11-21T03:00:00Z'), workdaysNight, 'UTC'), true); // Sat 03:00 (Fri window)
    const day = { days: [0, 6], start: '08:00', end: '12:00' };
    assert.equal(inMaintenanceWindow(new Date('2026-11-21T07:30:00Z'), day, 'Europe/Berlin'), true); // Sat 08:30 Berlin
    assert.equal(inMaintenanceWindow(new Date('2026-11-21T07:30:00Z'), day, 'UTC'), false);
    assert.equal(inMaintenanceWindow(new Date(), null, 'UTC'), true);
  });
});

describe('script parameters', () => {
  it('fills defaults, checks types and rejects unknown names', async () => {
    const { resolveParams } = await import('../src/jobs/params.ts');
    const defs = [
      { name: 'Days', type: 'number' as const, required: true },
      { name: 'Mode', type: 'string' as const, required: false, default: 'safe' },
      { name: 'Force', type: 'boolean' as const, required: false },
    ];
    assert.deepEqual(resolveParams(defs, { Days: 7 }), { values: { Days: 7, Mode: 'safe' }, errors: [] });
    assert.deepEqual(resolveParams(defs, {}).errors, ['parameter "Days" is required']);
    assert.deepEqual(resolveParams(defs, { Days: '7' }).errors, ['parameter "Days" must be of type number']);
    assert.deepEqual(resolveParams(defs, { Days: 1, Evil: 'x' }).errors, ['unknown parameter "Evil"']);
  });
});

describe('vulnerability matching primitives', () => {
  it('compares versions like rpmvercmp', async () => {
    const { compareVersions } = await import('../src/vuln/version.ts');
    const cases: [string, string, number][] = [
      ['1.0', '1.0.1', -1],
      ['1.10', '1.9', 1],
      ['131.0', '131.0.2', -1],
      ['2.17.0', '2.17.0-rc1', 1],
      ['1.0rc1', '1.0', -1],
      ['23.01', '23.1', 0],
      ['1.1.1w', '1.1.1k', 1],
      ['10.0.22631.4460', '10.0.22631.4317', 1],
      ['99999999999999999999.1', '99999999999999999999.0', 1],
    ];
    for (const [a, b, want] of cases) assert.equal(compareVersions(a, b), want, `${a} vs ${b}`);
  });

  it('normalises package versions', async () => {
    const { normalizeVersion } = await import('../src/vuln/version.ts');
    assert.equal(normalizeVersion('1:3.0.2-0ubuntu1.10', 'dpkg'), '3.0.2');
    assert.equal(normalizeVersion('2.36+dfsg-1', 'dpkg'), '2.36');
    assert.equal(normalizeVersion('3.0.7-27.el9', 'rpm'), '3.0.7');
    assert.equal(normalizeVersion('v1.2.3'), '1.2.3');
    assert.equal(normalizeVersion('131.0', 'registry'), '131.0');
  });

  it('evaluates CPE version criteria', async () => {
    const { versionMatches } = await import('../src/vuln/version.ts');
    const range = { version: '*', versionStartIncluding: '2.0.1', versionEndExcluding: '2.15.0' };
    assert.equal(versionMatches('2.14.1', range), true);
    assert.equal(versionMatches('2.15.0', range), false);
    assert.equal(versionMatches('2.0.0', range), false);
    assert.equal(versionMatches('3.0.13', { version: '*', versionEndIncluding: '3.0.13' }), true);
    assert.equal(versionMatches('5.5', { version: '5.5' }), true);
    assert.equal(versionMatches('1.0', { version: '*' }), false, 'unbounded wildcard ignored');
    assert.equal(versionMatches('1.0', { version: '-' }), false);
    assert.equal(versionMatches('', range), false);
  });

  it('parses escaped CPE 2.3 strings', async () => {
    const { parseCpe23 } = await import('../src/vuln/cpe.ts');
    assert.deepEqual(parseCpe23('cpe:2.3:a:don_ho:notepad\\+\\+:5.5:*:*:*:*:*:*:*'), { part: 'a', vendor: 'don_ho', product: 'notepad++', version: '5.5', update: '*', targetSw: '*' });
    assert.equal(parseCpe23('cpe:2.3:a:x\\:y:z:1:*:*:*:*:*:*:*')!.vendor, 'x:y');
    assert.equal(parseCpe23('cpe:/a:old:format'), null);
  });

  it('maps software via rules first, then heuristics; globs are literal-safe', async () => {
    const { mapSoftware, globToRegExp, normalizeName } = await import('../src/vuln/mapping.ts');
    assert.equal(normalizeName('7-Zip 23.01 (x64)'), '7-zip');
    assert.equal(normalizeName('Git version 2.43.0'), 'git');
    assert.equal(globToRegExp('a.b(*)').test('a.b(x)'), true);
    assert.equal(globToRegExp('a.b').test('axb'), false, 'dot is literal');
    const index = new Map([['firefox', new Set(['mozilla'])], ['widget', new Set(['acme', 'other'])]]);
    const rules = [
      { id: 'r1', namePattern: 'Mozilla Firefox*', publisherPattern: null, source: null, vendor: 'mozilla', product: 'firefox', ignore: false, priority: 100, enabled: true },
      { id: 'r2', namePattern: 'Internal*', publisherPattern: null, source: null, vendor: null, product: null, ignore: true, priority: 50, enabled: true },
    ];
    assert.deepEqual(mapSoftware({ name: 'Mozilla Firefox (x64 de)', publisher: 'Mozilla', source: 'registry' }, rules, index), { vendor: 'mozilla', product: 'firefox', method: 'rule', ruleId: 'r1', confidence: 'high' });
    assert.deepEqual(mapSoftware({ name: 'Internal Tool', publisher: '', source: 'registry' }, rules, index), { ignored: true, ruleId: 'r2' });
    const h = mapSoftware({ name: 'Acme Widget', publisher: 'ACME Corp.', source: 'registry' }, rules, index);
    assert.equal(h && 'vendor' in h && `${h.vendor}:${h.product}:${h.confidence}`, 'acme:widget:medium');
    const distro = mapSoftware({ name: 'widget', publisher: 'Acme', source: 'dpkg' }, rules, index);
    assert.equal(distro && 'confidence' in distro && distro.confidence, 'low', 'distro packages: backports possible');
    assert.equal(mapSoftware({ name: 'Widget', publisher: 'Unknown', source: 'registry' }, rules, index), null, 'ambiguous vendor → no mapping');
  });

  it('suggests products only on distinctive words', async () => {
    const { suggestProducts } = await import('../src/vuln/mapping.ts');
    const index = new Map([
      ['patrol_agent', new Set(['bmc'])],
      ['sql_server', new Set(['microsoft'])],
      ['keepass', new Set(['keepass'])],
    ]);
    assert.deepEqual(suggestProducts({ name: 'OpenCM Agent', publisher: 'Fuchs-Host', source: 'registry' }, index), [], 'generic word only');
    assert.deepEqual(suggestProducts({ name: 'KeePass Classic 1.40', publisher: 'Dominik Reichl', source: 'registry' }, index), [{ vendor: 'keepass', product: 'keepass' }]);
  });
});

describe('tokens', () => {
  it('are random, prefixed and hashed deterministically', () => {
    const a = generateToken('ocs');
    assert.match(a, /^ocs_[A-Za-z0-9_-]{43}$/);
    assert.notEqual(a, generateToken('ocs'));
    assert.equal(hashToken(a), hashToken(a));
    assert.equal(hashToken(a).length, 64);
  });
});
