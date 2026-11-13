/**
 * OSV (osv.dev) for Linux distribution packages (M7).
 *
 * Distributions backport security fixes, so upstream-version CPE matching produces
 * false positives for dpkg/rpm packages. OSV carries the distributions' own advisories
 * with exact package versions. We ask OSV which advisories affect each installed
 * (ecosystem, package, version) and cache the answer; evaluateFindings() turns the
 * cache into findings and skips CPE matching for every package OSV has checked.
 *
 * Only package names and versions are sent – never host names or addresses.
 */
import { and, eq, inArray, lt, sql } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { deviceInventory, devices, deviceSoftware, osvPackages, osvVulns, vulnerabilities } from '../db/schema.ts';
import type { FetchFn } from './nvd.ts';

// ---------------------------------------------------------------- ecosystem mapping

export interface OsInfo {
  name?: string | null;
  version?: string | null;
  build?: string | null;
  distroId?: string | null;
}

function distroOf(os: OsInfo): string | null {
  const id = os.distroId?.toLowerCase().trim();
  if (id) return id;
  const n = (os.name ?? '').toLowerCase();
  if (n.includes('ubuntu')) return 'ubuntu';
  if (n.includes('debian')) return 'debian';
  if (n.includes('rocky')) return 'rocky';
  if (n.includes('alma')) return 'almalinux';
  return null;
}

/** OSV ecosystem name for a Linux installation, or null if OSV has no data for it. */
export function osvEcosystem(os: OsInfo): string | null {
  const distro = distroOf(os);
  const ver = (os.build || os.version || '').match(/\d+(?:\.\d+)?/)?.[0];
  if (!distro || !ver) return null;
  const major = ver.split('.')[0]!;
  switch (distro) {
    case 'debian':
      return `Debian:${major}`;
    case 'ubuntu': {
      const m = ver.match(/^(\d{2})\.(\d{2})$/);
      if (!m) return null;
      const lts = m[2] === '04' && Number(m[1]) % 2 === 0;
      return `Ubuntu:${m[1]}.${m[2]}${lts ? ':LTS' : ''}`;
    }
    case 'rocky':
      return `Rocky Linux:${major}`;
    case 'almalinux':
      return `AlmaLinux:${major}`;
    default:
      return null;
  }
}

export interface SoftwareRef {
  name: string;
  version: string;
  source: string;
  sourceName?: string | null;
  sourceVersion?: string | null;
}

/**
 * Package identities to query for one installed package. Debian/Ubuntu advisories are
 * keyed by source package; for RPM distributions we ask for the binary and the source
 * package name (advisories list either), with the full epoch:version-release.
 */
export function osvQueries(ecosystem: string, sw: SoftwareRef): { name: string; version: string }[] {
  const deb = ecosystem.startsWith('Debian:') || ecosystem.startsWith('Ubuntu:');
  if (deb) {
    if (sw.source !== 'dpkg') return [];
    const version = sw.sourceVersion || sw.version;
    return version ? [{ name: sw.sourceName || sw.name, version }] : [];
  }
  if (sw.source !== 'rpm') return [];
  const version = sw.sourceVersion || sw.version;
  if (!version) return [];
  const names = new Set([sw.name, ...(sw.sourceName ? [sw.sourceName] : [])]);
  return [...names].map((name) => ({ name, version }));
}

export const osvKey = (ecosystem: string, name: string, version: string) => `${ecosystem}\u0000${name}\u0000${version}`;

const CVE_RE = /CVE-\d{4}-\d{4,}/g;

/** CVE ids of an OSV record: the id itself, aliases, upstream ids (DEBIAN-CVE-…, UBUNTU-CVE-…). */
export function cveIdsOf(v: { id: string; aliases?: string[]; upstream?: string[]; related?: string[] }): string[] {
  const out = new Set<string>();
  for (const s of [v.id, ...(v.aliases ?? []), ...(v.upstream ?? [])]) for (const m of s.toUpperCase().matchAll(CVE_RE)) out.add(m[0]);
  return [...out].sort();
}

// ---------------------------------------------------------------- inventory side

export interface LinuxDevice {
  id: string;
  ecosystem: string;
}

/** Active Linux devices with a supported distribution (from the last inventory). */
export async function osvDevices(db: Db, deviceIds?: string[]): Promise<LinuxDevice[]> {
  const rows = await db
    .select({ id: devices.id, os: sql<OsInfo | null>`${deviceInventory.data}->'os'` })
    .from(devices)
    .innerJoin(deviceInventory, eq(deviceInventory.deviceId, devices.id))
    .where(and(eq(devices.status, 'active'), eq(devices.os, 'linux'), deviceIds ? inArray(devices.id, deviceIds) : undefined));
  const out: LinuxDevice[] = [];
  for (const r of rows) {
    const os = typeof r.os === 'string' ? (JSON.parse(r.os) as OsInfo) : r.os;
    const eco = os ? osvEcosystem(os) : null;
    if (eco) out.push({ id: r.id, ecosystem: eco });
  }
  return out;
}

// ---------------------------------------------------------------- sync

export interface OsvOptions {
  baseUrl: string;
  fetch: FetchFn;
  sleep: (ms: number) => Promise<void>;
  intervalHours: number;
  maxPackages: number;
  maxDetails: number;
  log?: (msg: string, data?: Record<string, unknown>) => void;
}

export interface OsvSyncResult {
  queried: number;
  affected: number;
  details: number;
  changed: boolean;
}

interface BatchResult {
  vulns?: { id: string; modified?: string }[];
  next_page_token?: string;
}

async function post(o: OsvOptions, path: string, body: unknown): Promise<unknown> {
  for (let attempt = 0; ; attempt++) {
    const res = await o.fetch(`${o.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'OpenCM vulnerability sync' },
      body: JSON.stringify(body),
    });
    if (res.ok) return res.json();
    if ([429, 500, 502, 503, 504].includes(res.status) && attempt < 3) {
      await o.sleep(2000 * 2 ** attempt);
      continue;
    }
    throw new Error(`OSV ${path} failed: HTTP ${res.status}`);
  }
}

async function get(o: OsvOptions, path: string): Promise<unknown | null> {
  for (let attempt = 0; ; attempt++) {
    const res = await o.fetch(`${o.baseUrl}${path}`, { headers: { 'user-agent': 'OpenCM vulnerability sync' } });
    if (res.ok) return res.json();
    if (res.status === 404) return null; // withdrawn record
    if ([429, 500, 502, 503, 504].includes(res.status) && attempt < 3) {
      await o.sleep(2000 * 2 ** attempt);
      continue;
    }
    throw new Error(`OSV ${path} failed: HTTP ${res.status}`);
  }
}

type Query = { ecosystem: string; name: string; version: string };

/** One query with all pages (rarely more than one). */
async function queryAllPages(o: OsvOptions, q: Query, first: BatchResult): Promise<{ id: string; modified?: string }[]> {
  const vulns = [...(first.vulns ?? [])];
  let token = first.next_page_token;
  for (let i = 0; token && i < 20; i++) {
    const r = (await post(o, '/v1/query', { package: { ecosystem: q.ecosystem, name: q.name }, version: q.version, page_token: token })) as BatchResult;
    vulns.push(...(r.vulns ?? []));
    token = r.next_page_token;
  }
  return vulns;
}

/**
 * Incremental: queries package versions never checked or checked longer than
 * intervalHours ago, then fetches details of advisories not cached yet (or modified).
 */
export async function syncOsv(db: Db, o: OsvOptions, now = new Date()): Promise<OsvSyncResult> {
  const result: OsvSyncResult = { queried: 0, affected: 0, details: 0, changed: false };
  const devs = await osvDevices(db);
  if (!devs.length) return result;
  const ecoByDevice = new Map(devs.map((d) => [d.id, d.ecosystem]));
  const ecosystems = [...new Set(devs.map((d) => d.ecosystem))];

  // distinct package identities currently installed
  const software = await db
    .selectDistinct({
      deviceId: deviceSoftware.deviceId,
      name: deviceSoftware.name,
      version: deviceSoftware.version,
      source: deviceSoftware.source,
      sourceName: deviceSoftware.sourceName,
      sourceVersion: deviceSoftware.sourceVersion,
    })
    .from(deviceSoftware)
    .where(and(inArray(deviceSoftware.deviceId, [...ecoByDevice.keys()]), inArray(deviceSoftware.source, ['dpkg', 'rpm'])));
  const wanted = new Map<string, Query>();
  for (const s of software) {
    const eco = ecoByDevice.get(s.deviceId)!;
    for (const q of osvQueries(eco, s)) wanted.set(osvKey(eco, q.name, q.version), { ecosystem: eco, ...q });
  }

  const cached = await db
    .select({ ecosystem: osvPackages.ecosystem, name: osvPackages.name, version: osvPackages.version, vulnIds: osvPackages.vulnIds, checkedAt: osvPackages.checkedAt })
    .from(osvPackages)
    .where(inArray(osvPackages.ecosystem, ecosystems));
  const cache = new Map(cached.map((c) => [osvKey(c.ecosystem, c.name, c.version), c]));
  const staleBefore = now.getTime() - o.intervalHours * 3600_000;
  const missing: Query[] = [];
  const stale: Query[] = [];
  for (const [k, q] of wanted) {
    const c = cache.get(k);
    if (!c) missing.push(q);
    else if (c.checkedAt.getTime() < staleBefore) stale.push(q);
  }
  const todo = [...missing, ...stale].slice(0, o.maxPackages);

  const modifiedById = new Map<string, string | undefined>();
  for (let i = 0; i < todo.length; i += 1000) {
    const chunk = todo.slice(i, i + 1000);
    const body = { queries: chunk.map((q) => ({ package: { ecosystem: q.ecosystem, name: q.name }, version: q.version })) };
    const res = (await post(o, '/v1/querybatch', body)) as { results?: BatchResult[] };
    const results = res.results ?? [];
    const rows: (typeof osvPackages.$inferInsert)[] = [];
    for (let j = 0; j < chunk.length; j++) {
      const q = chunk[j]!;
      const r = results[j] ?? {};
      const vulns = r.next_page_token ? await queryAllPages(o, q, r) : (r.vulns ?? []);
      for (const v of vulns) modifiedById.set(v.id, v.modified);
      const ids = [...new Set(vulns.map((v) => v.id))].sort();
      const before = cache.get(osvKey(q.ecosystem, q.name, q.version));
      if (!before || before.vulnIds.join(',') !== ids.join(',')) result.changed = true;
      if (ids.length) result.affected++;
      rows.push({ ecosystem: q.ecosystem, name: q.name, version: q.version, vulnIds: ids, checkedAt: now });
    }
    await db
      .insert(osvPackages)
      .values(rows)
      .onConflictDoUpdate({ target: [osvPackages.ecosystem, osvPackages.name, osvPackages.version], set: { vulnIds: sql`excluded.vuln_ids`, checkedAt: sql`excluded.checked_at` } });
    result.queried += chunk.length;
  }
  // only when the whole backlog was processed – otherwise unchecked rows are not stale yet
  if (todo.length === missing.length + stale.length) await pruneOsvCache(db, new Date(now.getTime() - o.intervalHours * 7 * 3600_000));

  // advisory details: new ids, or ids whose "modified" moved on
  const referenced = new Set<string>();
  for (const c of cached) for (const id of c.vulnIds) referenced.add(id);
  for (const id of modifiedById.keys()) referenced.add(id);
  if (!referenced.size) return result;
  const known = new Map<string, Date | null>();
  const refList = [...referenced];
  for (let i = 0; i < refList.length; i += 5000) {
    for (const k of await db.select({ id: osvVulns.id, modified: osvVulns.modified }).from(osvVulns).where(inArray(osvVulns.id, refList.slice(i, i + 5000)))) known.set(k.id, k.modified);
  }
  const needDetails = refList
    .filter((id) => {
      if (!known.has(id)) return true;
      const m = modifiedById.get(id);
      const k = known.get(id);
      return !!m && (!k || Date.parse(m) > k.getTime());
    })
    .slice(0, o.maxDetails);

  for (const id of needDetails) {
    const v = (await get(o, `/v1/vulns/${encodeURIComponent(id)}`)) as { id: string; summary?: string; details?: string; aliases?: string[]; upstream?: string[]; modified?: string } | null;
    if (!v) {
      await db.insert(osvVulns).values({ id, summary: '', cveIds: [], fetchedAt: now }).onConflictDoNothing();
      continue;
    }
    const cves = cveIdsOf(v);
    const summary = (v.summary || v.details || '').slice(0, 1000);
    const row = { summary, cveIds: cves, modified: v.modified ? new Date(v.modified) : null, fetchedAt: now };
    await db.insert(osvVulns).values({ id, ...row }).onConflictDoUpdate({ target: osvVulns.id, set: row });
    // CVEs not mirrored from NVD yet get a stub (like KEV); NVD fills in scores later
    if (cves.length) {
      await db
        .insert(vulnerabilities)
        .values(cves.map((cveId) => ({ cveId, description: summary })))
        .onConflictDoNothing();
    }
    result.details++;
    result.changed = true;
  }
  return result;
}

// ---------------------------------------------------------------- evaluation helper

export interface OsvIndex {
  /** devices with a supported distribution → ecosystem */
  ecosystemOf: Map<string, string>;
  /** checked package identities → CVE ids (empty = checked, not affected) */
  cves: Map<string, string[]>;
}

/** Loads what evaluateFindings needs for the given devices. CVEs are limited to mirrored ones. */
export async function loadOsvIndex(db: Db, deviceIds: string[]): Promise<OsvIndex> {
  const devs = await osvDevices(db, deviceIds);
  const ecosystemOf = new Map(devs.map((d) => [d.id, d.ecosystem]));
  const cves = new Map<string, string[]>();
  if (!devs.length) return { ecosystemOf, cves };
  const ecosystems = [...new Set(devs.map((d) => d.ecosystem))];
  const pkgs = await db.select().from(osvPackages).where(inArray(osvPackages.ecosystem, ecosystems));
  const ids = [...new Set(pkgs.flatMap((p) => p.vulnIds))];
  const cveByVuln = new Map<string, string[]>();
  for (let i = 0; i < ids.length; i += 5000) {
    for (const v of await db.select({ id: osvVulns.id, cveIds: osvVulns.cveIds }).from(osvVulns).where(inArray(osvVulns.id, ids.slice(i, i + 5000)))) cveByVuln.set(v.id, v.cveIds);
  }
  const allCves = [...new Set([...cveByVuln.values()].flat())];
  const mirrored = new Set<string>();
  for (let i = 0; i < allCves.length; i += 5000) {
    for (const r of await db.select({ id: vulnerabilities.cveId }).from(vulnerabilities).where(inArray(vulnerabilities.cveId, allCves.slice(i, i + 5000)))) mirrored.add(r.id);
  }
  for (const p of pkgs) {
    const list = new Set<string>();
    for (const id of p.vulnIds) for (const c of cveByVuln.get(id) ?? []) if (mirrored.has(c)) list.add(c);
    cves.set(osvKey(p.ecosystem, p.name, p.version), [...list]);
  }
  return { ecosystemOf, cves };
}

/**
 * Installed package versions are re-checked every intervalHours; rows not refreshed for
 * a long time belong to versions that are no longer installed anywhere.
 */
export async function pruneOsvCache(db: Db, olderThan: Date): Promise<void> {
  await db.delete(osvPackages).where(lt(osvPackages.checkedAt, olderThan));
}
