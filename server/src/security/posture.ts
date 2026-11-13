/**
 * Security posture (M7): derives a per-device status from the inventory section
 * "security" (disk encryption, antivirus, firewall, Secure Boot, TPM).
 */
import { and, count, eq, inArray, sql, type SQL } from 'drizzle-orm';
import type { DeviceScope } from '../auth/scope.ts';
import type { Db } from '../db/client.ts';
import { devices, deviceSecurity } from '../db/schema.ts';
import type { Security } from '../inventory/schema.ts';
import { emitEvent } from '../webhooks/events.ts';

export const ENCRYPTION_STATES = ['encrypted', 'partial', 'unencrypted', 'unknown'] as const;
export const ANTIVIRUS_STATES = ['ok', 'outdated', 'disabled', 'missing', 'unknown'] as const;
export const FIREWALL_STATES = ['on', 'partial', 'off', 'unknown'] as const;
export const TPM_STATES = ['ready', 'present', 'missing', 'unknown'] as const;

export type EncryptionState = (typeof ENCRYPTION_STATES)[number];
export type AntivirusState = (typeof ANTIVIRUS_STATES)[number];
export type FirewallState = (typeof FIREWALL_STATES)[number];
export type TpmState = (typeof TPM_STATES)[number];

/** Issue codes (stable, used by the UI, webhooks and filters). */
export const ISSUES = {
  unencrypted: 'Systemlaufwerk nicht verschlüsselt',
  encryption_partial: 'Nicht alle Laufwerke verschlüsselt',
  encryption_suspended: 'Verschlüsselung angehalten (Schlüssel ungeschützt)',
  encryption_unknown: 'Verschlüsselungsstatus unbekannt',
  av_missing: 'Kein Virenschutz gefunden',
  av_disabled: 'Virenschutz deaktiviert',
  av_outdated: 'Virensignaturen veraltet',
  av_realtime_off: 'Echtzeitschutz aus',
  firewall_off: 'Firewall aus',
  firewall_partial: 'Firewall nicht in allen Profilen aktiv',
  firewall_unknown: 'Firewall-Status unbekannt',
  secure_boot_off: 'Secure Boot aus',
  tpm_missing: 'Kein TPM',
} as const;
export type Issue = keyof typeof ISSUES;

export interface Posture {
  encryption: EncryptionState;
  antivirus: AntivirusState;
  firewall: FirewallState;
  secureBoot: boolean | null;
  tpm: TpmState;
  compliant: boolean;
  issues: Issue[];
}

export interface PostureOptions {
  /** signature age that counts as outdated (days) */
  maxSignatureAgeDays: number;
  now?: Date;
}

const DAY = 86_400_000;

function encryptionState(sec: Security, issues: Issue[]): EncryptionState {
  const vols = sec.encryption.volumes.filter((v) => v.encrypted !== null);
  if (!vols.length) {
    issues.push('encryption_unknown');
    return 'unknown';
  }
  if (vols.some((v) => v.encrypted && v.protection === false)) issues.push('encryption_suspended');
  const sys = vols.find((v) => v.system);
  if (sys && !sys.encrypted) {
    issues.push('unencrypted');
    return 'unencrypted';
  }
  const enc = vols.filter((v) => v.encrypted).length;
  if (enc === 0) {
    issues.push('unencrypted');
    return 'unencrypted';
  }
  if (enc < vols.length) {
    issues.push('encryption_partial');
    return 'partial';
  }
  return issues.includes('encryption_suspended') ? 'partial' : 'encrypted';
}

function antivirusState(sec: Security, os: string, o: PostureOptions, issues: Issue[]): AntivirusState {
  const now = o.now ?? new Date();
  // macOS XProtect is updated every few weeks – a daily threshold would always fire
  const maxAge = (os === 'macos' ? Math.max(o.maxSignatureAgeDays, 30) : o.maxSignatureAgeDays) * DAY;
  const products = sec.antivirus;
  if (!products.length) {
    if (os === 'linux') return 'unknown'; // not required on Linux
    issues.push('av_missing');
    return 'missing';
  }
  const fresh = (p: Security['antivirus'][number]) => {
    if (p.upToDate !== null) return p.upToDate;
    if (!p.signatureUpdatedAt) return true; // nothing to judge
    const t = Date.parse(p.signatureUpdatedAt);
    return Number.isNaN(t) || now.getTime() - t <= maxAge;
  };
  const enabled = products.filter((p) => p.enabled !== false);
  if (!enabled.length) {
    issues.push('av_disabled');
    return 'disabled';
  }
  const good = enabled.filter((p) => p.realtime !== false && fresh(p));
  if (good.length) return 'ok';
  if (enabled.some((p) => p.realtime === false)) {
    issues.push('av_realtime_off');
    return 'disabled';
  }
  issues.push('av_outdated');
  return 'outdated';
}

function firewallState(sec: Security, issues: Issue[]): FirewallState {
  const profiles = sec.firewall.profiles.filter((p) => p.enabled !== null);
  if (profiles.length) {
    const on = profiles.filter((p) => p.enabled).length;
    if (on === profiles.length) return 'on';
    if (on === 0) {
      issues.push('firewall_off');
      return 'off';
    }
    issues.push('firewall_partial');
    return 'partial';
  }
  if (sec.firewall.enabled === true) return 'on';
  if (sec.firewall.enabled === false) {
    issues.push('firewall_off');
    return 'off';
  }
  issues.push('firewall_unknown');
  return 'unknown';
}

function tpmState(sec: Security, os: string, issues: Issue[]): TpmState {
  if (sec.tpm.present === true) return sec.tpm.ready === false ? 'present' : 'ready';
  if (sec.tpm.present === false) {
    if (os === 'windows') issues.push('tpm_missing');
    return 'missing';
  }
  return 'unknown';
}

/** Pure evaluation – unit tested. */
export function evaluatePosture(sec: Security, os: string, o: PostureOptions): Posture {
  const issues: Issue[] = [];
  const encryption = encryptionState(sec, issues);
  const antivirus = antivirusState(sec, os, o, issues);
  const firewall = firewallState(sec, issues);
  const tpm = tpmState(sec, os, issues);
  if (sec.secureBoot === false) issues.push('secure_boot_off');
  const avOk = os === 'linux' ? antivirus === 'ok' || antivirus === 'unknown' : antivirus === 'ok';
  const compliant = encryption === 'encrypted' && firewall === 'on' && avOk;
  return { encryption, antivirus, firewall, secureBoot: sec.secureBoot, tpm, compliant, issues };
}

type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];

/**
 * Called inside the inventory transaction. Returns the webhook payload for
 * device.security_changed when new issues appeared – the caller emits it after commit.
 */
export async function storePosture(
  tx: Tx,
  deviceId: string,
  os: string,
  hostname: string,
  sec: Security,
  collectedAt: Date,
  o: PostureOptions,
): Promise<{ posture: Posture; event: Record<string, unknown> | null }> {
  const p = evaluatePosture(sec, os, o);
  const [prev] = await tx.select({ issues: deviceSecurity.issues, compliant: deviceSecurity.compliant }).from(deviceSecurity).where(eq(deviceSecurity.deviceId, deviceId));
  const row = {
    collectedAt,
    encryption: p.encryption,
    antivirus: p.antivirus,
    firewall: p.firewall,
    secureBoot: p.secureBoot,
    tpm: p.tpm,
    compliant: p.compliant,
    issues: p.issues,
    details: sec as unknown as Record<string, unknown>,
    updatedAt: new Date(),
  };
  await tx.insert(deviceSecurity).values({ deviceId, ...row }).onConflictDoUpdate({ target: deviceSecurity.deviceId, set: row });
  if (!prev) return { posture: p, event: null };
  const added = p.issues.filter((i) => !prev.issues.includes(i));
  if (!added.length) return { posture: p, event: null };
  return {
    posture: p,
    event: {
      deviceId,
      hostname,
      compliant: p.compliant,
      wasCompliant: prev.compliant,
      newIssues: added.map((code) => ({ code, label: ISSUES[code] })),
      resolvedIssues: prev.issues.filter((i) => !(p.issues as string[]).includes(i)),
      encryption: p.encryption,
      antivirus: p.antivirus,
      firewall: p.firewall,
    },
  };
}

export async function emitSecurityChanged(db: Db, event: Record<string, unknown> | null): Promise<void> {
  if (event) await emitEvent(db, 'device.security_changed', event);
}

const scopeCond = (scope: DeviceScope | null): SQL | undefined => (!scope || scope.all ? undefined : scope.ids.size ? inArray(devices.id, [...scope.ids]) : sql`false`);

/** Fleet counters for the overview page and the dashboard. */
export async function securityMetrics(db: Db, scope: DeviceScope | null) {
  const active = and(eq(devices.status, 'active'), scopeCond(scope));
  const [totals] = await db
    .select({
      devices: count(),
      reported: sql<number>`count(${deviceSecurity.deviceId})::int`,
      compliant: sql<number>`count(*) filter (where ${deviceSecurity.compliant})::int`,
      noncompliant: sql<number>`count(*) filter (where ${deviceSecurity.deviceId} is not null and not ${deviceSecurity.compliant})::int`,
    })
    .from(devices)
    .leftJoin(deviceSecurity, eq(deviceSecurity.deviceId, devices.id))
    .where(active);
  const group = async (col: typeof deviceSecurity.encryption | typeof deviceSecurity.antivirus | typeof deviceSecurity.firewall) => {
    const rows = await db
      .select({ state: col, n: count() })
      .from(deviceSecurity)
      .innerJoin(devices, eq(devices.id, deviceSecurity.deviceId))
      .where(active)
      .groupBy(col);
    return Object.fromEntries(rows.map((r) => [r.state, Number(r.n)]));
  };
  const [encryption, antivirus, firewall] = await Promise.all([group(deviceSecurity.encryption), group(deviceSecurity.antivirus), group(deviceSecurity.firewall)]);
  const issueRows = await db
    .select({ issue: sql<string>`unnest(${deviceSecurity.issues})`, n: count() })
    .from(deviceSecurity)
    .innerJoin(devices, eq(devices.id, deviceSecurity.deviceId))
    .where(active)
    .groupBy(sql`1`);
  return {
    devices: Number(totals?.devices ?? 0),
    reported: Number(totals?.reported ?? 0),
    compliant: Number(totals?.compliant ?? 0),
    noncompliant: Number(totals?.noncompliant ?? 0),
    encryption,
    antivirus,
    firewall,
    issues: Object.fromEntries(issueRows.map((r) => [r.issue, Number(r.n)])),
  };
}
