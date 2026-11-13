import { inArray, sql } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { vulnCpeMatches, vulnerabilities, type VulnReference } from '../db/schema.ts';
import { parseCpe23 } from './cpe.ts';

// ---------------------------------------------------------------- parsing

interface NvdCvssData {
  version: string;
  vectorString: string;
  baseScore: number;
  baseSeverity?: string;
}
interface NvdMetric {
  source: string;
  type: string;
  cvssData: NvdCvssData;
  baseSeverity?: string; // v2: severity lives on the metric
}
interface NvdCpeMatch {
  vulnerable: boolean;
  criteria: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}
export interface NvdCve {
  id: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  descriptions?: { lang: string; value: string }[];
  metrics?: Record<string, NvdMetric[] | undefined>;
  weaknesses?: { description: { lang: string; value: string }[] }[];
  configurations?: { nodes: { cpeMatch?: NvdCpeMatch[] }[] }[];
  references?: { url: string; tags?: string[] }[];
  cisaExploitAdd?: string;
  cisaActionDue?: string;
  cisaRequiredAction?: string;
}

export type VulnRow = typeof vulnerabilities.$inferInsert;
export type MatchRow = Omit<typeof vulnCpeMatches.$inferInsert, 'id'>;

const METRIC_PREFERENCE = ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2'];
const MAX_REFS = 20;

function pickCvss(metrics: NvdCve['metrics']) {
  for (const key of METRIC_PREFERENCE) {
    const list = metrics?.[key];
    if (!list?.length) continue;
    const m = list.find((x) => x.type === 'Primary') ?? list[0]!;
    const severity = (m.cvssData.baseSeverity ?? m.baseSeverity ?? '').toUpperCase() || null;
    return { score: m.cvssData.baseScore, severity, version: m.cvssData.version, vector: m.cvssData.vectorString };
  }
  return null;
}

/** NVD CVE JSON → vulnerability row + application CPE matches (vulnerable=true, part "a"). */
export function parseNvdCve(cve: NvdCve): { vuln: VulnRow; matches: MatchRow[]; rejected: boolean } {
  const cvss = pickCvss(cve.metrics);
  const cwes = new Set<string>();
  for (const w of cve.weaknesses ?? []) for (const d of w.description) if (/^CWE-\d+$/.test(d.value)) cwes.add(d.value);
  const vuln: VulnRow = {
    cveId: cve.id,
    description: cve.descriptions?.find((d) => d.lang === 'en')?.value ?? '',
    published: cve.published ? new Date(`${cve.published}Z`.replace(/ZZ$/, 'Z')) : null,
    lastModified: cve.lastModified ? new Date(`${cve.lastModified}Z`.replace(/ZZ$/, 'Z')) : null,
    vulnStatus: cve.vulnStatus ?? '',
    cvssScore: cvss?.score ?? null,
    cvssSeverity: cvss?.severity ?? null,
    cvssVersion: cvss?.version ?? null,
    cvssVector: cvss?.vector ?? null,
    cwes: [...cwes],
    refs: (cve.references ?? []).slice(0, MAX_REFS).map((r): VulnReference => ({ url: r.url, tags: r.tags ?? [] })),
    updatedAt: new Date(),
  };
  const seen = new Set<string>();
  const matches: MatchRow[] = [];
  for (const cfg of cve.configurations ?? []) {
    for (const node of cfg.nodes) {
      for (const m of node.cpeMatch ?? []) {
        if (!m.vulnerable) continue;
        const cpe = parseCpe23(m.criteria);
        if (!cpe || cpe.part !== 'a') continue;
        const row: MatchRow = {
          cveId: cve.id,
          vendor: cpe.vendor.toLowerCase(),
          product: cpe.product.toLowerCase(),
          version: cpe.version || '*',
          targetSw: cpe.targetSw || '*',
          versionStartIncluding: m.versionStartIncluding ?? null,
          versionStartExcluding: m.versionStartExcluding ?? null,
          versionEndIncluding: m.versionEndIncluding ?? null,
          versionEndExcluding: m.versionEndExcluding ?? null,
        };
        const k = JSON.stringify(row);
        if (seen.has(k)) continue;
        seen.add(k);
        matches.push(row);
      }
    }
  }
  return { vuln, matches, rejected: (cve.vulnStatus ?? '').toLowerCase() === 'rejected' };
}

const CHUNK = 500;

/** Upserts a page of CVEs and replaces their CPE matches. KEV/EPSS/acceptance fields are preserved. */
export async function storeCves(db: Db, cves: NvdCve[]): Promise<{ stored: number; rejected: number }> {
  const parsed = cves.map(parseNvdCve);
  const rejected = parsed.filter((p) => p.rejected).map((p) => p.vuln.cveId);
  const keep = parsed.filter((p) => !p.rejected);
  await db.transaction(async (tx) => {
    if (rejected.length) await tx.delete(vulnerabilities).where(inArray(vulnerabilities.cveId, rejected));
    for (let i = 0; i < keep.length; i += CHUNK) {
      const part = keep.slice(i, i + CHUNK);
      await tx
        .insert(vulnerabilities)
        .values(part.map((p) => p.vuln))
        .onConflictDoUpdate({
          target: vulnerabilities.cveId,
          set: {
            description: sql`excluded.description`,
            published: sql`excluded.published`,
            lastModified: sql`excluded.last_modified`,
            vulnStatus: sql`excluded.vuln_status`,
            cvssScore: sql`excluded.cvss_score`,
            cvssSeverity: sql`excluded.cvss_severity`,
            cvssVersion: sql`excluded.cvss_version`,
            cvssVector: sql`excluded.cvss_vector`,
            cwes: sql`excluded.cwes`,
            refs: sql`excluded.refs`,
            updatedAt: sql`excluded.updated_at`,
          },
        });
      const ids = part.map((p) => p.vuln.cveId);
      await tx.delete(vulnCpeMatches).where(inArray(vulnCpeMatches.cveId, ids));
      const rows = part.flatMap((p) => p.matches);
      for (let j = 0; j < rows.length; j += CHUNK) await tx.insert(vulnCpeMatches).values(rows.slice(j, j + CHUNK));
    }
  });
  return { stored: keep.length, rejected: rejected.length };
}

// ---------------------------------------------------------------- fetching

export type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

export interface NvdOptions {
  baseUrl: string;
  apiKey?: string;
  fetch: FetchFn;
  sleep: (ms: number) => Promise<void>;
  pageSize?: number;
  /** stop after this many pages (keeps worker ticks bounded; the cursor resumes) */
  maxPages?: number;
  log?: (msg: string, data?: Record<string, unknown>) => void;
}

interface NvdPage {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: { cve: NvdCve }[];
}

const MAX_WINDOW_MS = 120 * 86_400_000; // NVD limit for lastMod ranges
const fmt = (d: Date) => d.toISOString().replace('Z', '+00:00');

export async function fetchNvdPage(o: NvdOptions, params: Record<string, string>): Promise<NvdPage> {
  const url = `${o.baseUrl}?${new URLSearchParams(params)}`;
  // NVD: 5 req / 30 s without key, 50 with key. On 403/429/503 back off and retry.
  for (let attempt = 0; ; attempt++) {
    const res = await o.fetch(url, { headers: { 'user-agent': 'OpenCM vulnerability sync', ...(o.apiKey && { apiKey: o.apiKey }) } });
    if (res.ok) return (await res.json()) as NvdPage;
    if ([403, 429, 500, 502, 503, 504].includes(res.status) && attempt < 5) {
      o.log?.('nvd: backing off', { status: res.status, attempt });
      await o.sleep(Math.min(60_000, 6000 * 2 ** attempt));
      continue;
    }
    throw new Error(`NVD request failed: HTTP ${res.status}`);
  }
}

export interface NvdCursor {
  mode?: 'full' | 'incremental';
  startIndex?: number;
  fullStartedAt?: string;
  lastModified?: string; // incremental watermark
  windowStart?: string;
  windowEnd?: string;
}

/**
 * One bounded sync step. Full mirror is paged by startIndex and resumable; afterwards
 * incremental windows (≤120 days) by lastModified. Returns the new cursor and whether
 * the sync is complete for now.
 */
export async function syncNvd(db: Db, o: NvdOptions, cursor: NvdCursor, now = new Date()): Promise<{ cursor: NvdCursor; done: boolean; stored: number }> {
  const pageSize = o.pageSize ?? 2000;
  const delay = o.apiKey ? 700 : 6500;
  const maxPages = o.maxPages ?? Number.POSITIVE_INFINITY;
  let stored = 0;
  let pages = 0;
  const c: NvdCursor = { ...cursor };

  if (!c.mode || c.mode === 'full') {
    c.mode = 'full';
    c.startIndex ??= 0;
    c.fullStartedAt ??= now.toISOString();
    for (;;) {
      if (pages >= maxPages) return { cursor: c, done: false, stored };
      if (pages > 0) await o.sleep(delay);
      const page = await fetchNvdPage(o, { resultsPerPage: String(pageSize), startIndex: String(c.startIndex) });
      pages++;
      stored += (await storeCves(db, page.vulnerabilities.map((v) => v.cve))).stored;
      c.startIndex += page.vulnerabilities.length;
      o.log?.('nvd: full sync progress', { startIndex: c.startIndex, total: page.totalResults });
      if (!page.vulnerabilities.length || c.startIndex >= page.totalResults) {
        return { cursor: { mode: 'incremental', lastModified: c.fullStartedAt }, done: true, stored };
      }
    }
  }

  // incremental
  let watermark = new Date(c.lastModified ?? now.toISOString());
  while (watermark < now) {
    const windowEnd = new Date(Math.min(now.getTime(), watermark.getTime() + MAX_WINDOW_MS));
    let startIndex = c.windowStart === watermark.toISOString() ? (c.startIndex ?? 0) : 0;
    for (;;) {
      if (pages >= maxPages) return { cursor: { mode: 'incremental', lastModified: watermark.toISOString(), windowStart: watermark.toISOString(), startIndex }, done: false, stored };
      if (pages > 0) await o.sleep(delay);
      const page = await fetchNvdPage(o, {
        resultsPerPage: String(pageSize),
        startIndex: String(startIndex),
        lastModStartDate: fmt(watermark),
        lastModEndDate: fmt(windowEnd),
      });
      pages++;
      stored += (await storeCves(db, page.vulnerabilities.map((v) => v.cve))).stored;
      startIndex += page.vulnerabilities.length;
      if (!page.vulnerabilities.length || startIndex >= page.totalResults) break;
    }
    watermark = windowEnd;
  }
  return { cursor: { mode: 'incremental', lastModified: watermark.toISOString() }, done: true, stored };
}
