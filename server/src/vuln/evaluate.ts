import { and, eq, inArray, isNull, sql } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { devices, deviceSoftware, deviceVulnerabilities, vulnCpeMatches, vulnerabilities } from '../db/schema.ts';
import { loadRules, mapSoftware, type Mapping, type ProductIndex } from './mapping.ts';
import { loadOsvIndex, osvKey, osvQueries } from './osv.ts';
import { normalizeVersion, versionMatches } from './version.ts';

// ---------------------------------------------------------------- product index cache

let indexCache: { at: number; index: ProductIndex } | null = null;
const INDEX_TTL_MS = 10 * 60_000;

/** Distinct NVD (product → vendors) for application CPEs. Cached; invalidated after feed syncs. */
export async function productIndex(db: Db, fresh = false): Promise<ProductIndex> {
  if (!fresh && indexCache && Date.now() - indexCache.at < INDEX_TTL_MS) return indexCache.index;
  const rows = await db.selectDistinct({ vendor: vulnCpeMatches.vendor, product: vulnCpeMatches.product }).from(vulnCpeMatches);
  const index: ProductIndex = new Map();
  for (const r of rows) {
    let s = index.get(r.product);
    if (!s) index.set(r.product, (s = new Set()));
    s.add(r.vendor);
  }
  indexCache = { at: Date.now(), index };
  return index;
}

export function invalidateProductIndex(): void {
  indexCache = null;
}

// ---------------------------------------------------------------- evaluation

export interface NewFinding {
  deviceId: string;
  cveId: string;
  softwareName: string;
  softwareVersion: string;
}

export interface EvaluationResult {
  devices: number;
  findingsOpen: number;
  newFindings: NewFinding[];
  fixed: number;
}

interface Finding {
  deviceId: string;
  cveId: string;
  softwareName: string;
  softwareVersion: string;
  vendor: string;
  product: string;
  confidence: string;
}

/**
 * Re-evaluates findings for the given devices (default: all active devices):
 * software → CPE → version-matched CVEs. New findings are opened, vanished ones
 * marked fixed, re-appearing ones re-opened.
 */
export async function evaluateFindings(db: Db, opts: { deviceIds?: string[]; now?: Date; osv?: boolean } = {}): Promise<EvaluationResult> {
  const now = opts.now ?? new Date();
  const deviceWhere = opts.deviceIds ? and(eq(devices.status, 'active'), inArray(devices.id, opts.deviceIds)) : eq(devices.status, 'active');
  const targetDevices = (await db.select({ id: devices.id }).from(devices).where(deviceWhere)).map((d) => d.id);
  if (!targetDevices.length) return { devices: 0, findingsOpen: 0, newFindings: [], fixed: 0 };

  const software = await db
    .select({
      deviceId: deviceSoftware.deviceId,
      name: deviceSoftware.name,
      version: deviceSoftware.version,
      publisher: deviceSoftware.publisher,
      source: deviceSoftware.source,
      sourceName: deviceSoftware.sourceName,
      sourceVersion: deviceSoftware.sourceVersion,
    })
    .from(deviceSoftware)
    .where(inArray(deviceSoftware.deviceId, targetDevices));

  const found = new Map<string, Finding>();

  // 1) OSV (distribution advisories): authoritative for packages OSV has checked
  const osvIndex = opts.osv ? await loadOsvIndex(db, targetDevices) : null;
  const osvCovered = (s: (typeof software)[number]): boolean => {
    const eco = osvIndex?.ecosystemOf.get(s.deviceId);
    if (!eco) return false;
    const queries = osvQueries(eco, s);
    let covered = false;
    for (const q of queries) {
      const cves = osvIndex!.cves.get(osvKey(eco, q.name, q.version));
      if (!cves) continue;
      covered = true;
      for (const cveId of cves) {
        const k = `${s.deviceId}\u0000${cveId}\u0000${s.name}`;
        if (!found.has(k)) found.set(k, { deviceId: s.deviceId, cveId, softwareName: s.name, softwareVersion: s.version, vendor: 'osv', product: `${eco}/${q.name}`, confidence: 'high' });
      }
    }
    return covered;
  };

  // 2) NVD CPE matching for everything else
  const rules = await loadRules(db);
  const index = await productIndex(db);
  const mapCache = new Map<string, Mapping | null>();
  const mapped: { s: (typeof software)[number]; m: Mapping; v: string }[] = [];
  for (const s of software) {
    if (osvIndex && osvCovered(s)) continue;
    const key = `${s.name}\u0000${s.publisher}\u0000${s.source}`;
    let m = mapCache.get(key);
    if (m === undefined) {
      const r = mapSoftware({ name: s.name, publisher: s.publisher, source: s.source }, rules, index);
      m = r && !('ignored' in r) ? r : null;
      mapCache.set(key, m);
    }
    const v = normalizeVersion(s.version, s.source);
    if (m && v) mapped.push({ s, m, v });
  }

  // all CPE matches for the mapped products in one query
  const products = [...new Set(mapped.map((x) => x.m.product))];
  const matches = products.length ? await db.select().from(vulnCpeMatches).where(inArray(vulnCpeMatches.product, products)) : [];
  const byPair = new Map<string, typeof matches>();
  for (const m of matches) {
    const k = `${m.vendor}\u0000${m.product}`;
    const list = byPair.get(k);
    if (list) list.push(m);
    else byPair.set(k, [m]);
  }

  for (const { s, m, v } of mapped) {
    for (const c of byPair.get(`${m.vendor}\u0000${m.product}`) ?? []) {
      if (!versionMatches(v, c)) continue;
      const k = `${s.deviceId}\u0000${c.cveId}\u0000${s.name}`;
      if (!found.has(k)) {
        found.set(k, { deviceId: s.deviceId, cveId: c.cveId, softwareName: s.name, softwareVersion: s.version, vendor: m.vendor, product: m.product, confidence: m.confidence });
      }
    }
  }

  const existing = await db.select().from(deviceVulnerabilities).where(inArray(deviceVulnerabilities.deviceId, targetDevices));
  const existingByKey = new Map(existing.map((e) => [`${e.deviceId}\u0000${e.cveId}\u0000${e.softwareName}`, e]));
  const newFindings: NewFinding[] = [];
  const toInsert: (typeof deviceVulnerabilities.$inferInsert)[] = [];
  const toReopenOrTouch: Finding[] = [];
  for (const [k, f] of found) {
    const e = existingByKey.get(k);
    if (!e) {
      toInsert.push({ ...f, status: 'open', firstSeen: now, lastSeen: now });
      newFindings.push({ deviceId: f.deviceId, cveId: f.cveId, softwareName: f.softwareName, softwareVersion: f.softwareVersion });
    } else {
      if (e.status === 'fixed') newFindings.push({ deviceId: f.deviceId, cveId: f.cveId, softwareName: f.softwareName, softwareVersion: f.softwareVersion });
      toReopenOrTouch.push(f);
    }
  }
  const toFix = existing.filter((e) => e.status === 'open' && !found.has(`${e.deviceId}\u0000${e.cveId}\u0000${e.softwareName}`));

  await db.transaction(async (tx) => {
    for (let i = 0; i < toInsert.length; i += 500) await tx.insert(deviceVulnerabilities).values(toInsert.slice(i, i + 500)).onConflictDoNothing();
    for (const f of toReopenOrTouch) {
      await tx
        .update(deviceVulnerabilities)
        .set({ status: 'open', fixedAt: null, lastSeen: now, softwareVersion: f.softwareVersion, confidence: f.confidence })
        .where(and(eq(deviceVulnerabilities.deviceId, f.deviceId), eq(deviceVulnerabilities.cveId, f.cveId), eq(deviceVulnerabilities.softwareName, f.softwareName)));
    }
    for (const e of toFix) {
      await tx
        .update(deviceVulnerabilities)
        .set({ status: 'fixed', fixedAt: now })
        .where(and(eq(deviceVulnerabilities.deviceId, e.deviceId), eq(deviceVulnerabilities.cveId, e.cveId), eq(deviceVulnerabilities.softwareName, e.softwareName)));
    }
  });

  return { devices: targetDevices.length, findingsOpen: found.size, newFindings, fixed: toFix.length };
}

/** Enriches new findings for notifications: only critical or known-exploited, not accepted. */
export async function notableFindings(db: Db, findings: NewFinding[]) {
  if (!findings.length) return [];
  const ids = [...new Set(findings.map((f) => f.cveId))];
  const vulns = await db
    .select({ cveId: vulnerabilities.cveId, severity: vulnerabilities.cvssSeverity, score: vulnerabilities.cvssScore, kev: vulnerabilities.kev })
    .from(vulnerabilities)
    .where(and(inArray(vulnerabilities.cveId, ids), isNull(vulnerabilities.acceptedAt), sql`(${vulnerabilities.kev} or ${vulnerabilities.cvssSeverity} = 'CRITICAL')`));
  if (!vulns.length) return [];
  const byId = new Map(vulns.map((v) => [v.cveId, v]));
  const hosts = new Map(
    (await db.select({ id: devices.id, hostname: devices.hostname }).from(devices).where(inArray(devices.id, [...new Set(findings.map((f) => f.deviceId))]))).map((d) => [d.id, d.hostname]),
  );
  return findings
    .filter((f) => byId.has(f.cveId))
    .map((f) => {
      const v = byId.get(f.cveId)!;
      return { ...f, hostname: hosts.get(f.deviceId) ?? '', severity: v.severity, cvssScore: v.score, kev: v.kev };
    });
}
