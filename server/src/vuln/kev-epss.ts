import { and, eq, isNotNull, notInArray, sql } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { deviceVulnerabilities, vulnerabilities } from '../db/schema.ts';
import type { FetchFn } from './nvd.ts';

interface KevEntry {
  cveID: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}

/** CISA Known Exploited Vulnerabilities: flags CVEs (creates stubs for CVEs not yet mirrored). */
export async function syncKev(db: Db, url: string, fetchFn: FetchFn): Promise<{ total: number; catalogVersion: string | null }> {
  const res = await fetchFn(url, { headers: { 'user-agent': 'OpenCM vulnerability sync' } });
  if (!res.ok) throw new Error(`KEV download failed: HTTP ${res.status}`);
  const body = (await res.json()) as { catalogVersion?: string; vulnerabilities: KevEntry[] };
  const entries = body.vulnerabilities.filter((e) => /^CVE-\d{4}-\d+$/.test(e.cveID));
  const ids = entries.map((e) => e.cveID);
  await db.transaction(async (tx) => {
    for (let i = 0; i < entries.length; i += 500) {
      const part = entries.slice(i, i + 500);
      await tx
        .insert(vulnerabilities)
        .values(
          part.map((e) => ({
            cveId: e.cveID,
            description: e.shortDescription ?? e.vulnerabilityName ?? '',
            kev: true,
            kevDateAdded: e.dateAdded ?? null,
            kevDueDate: e.dueDate ?? null,
            kevRansomware: e.knownRansomwareCampaignUse ?? null,
            kevRequiredAction: e.requiredAction ?? null,
          })),
        )
        .onConflictDoUpdate({
          target: vulnerabilities.cveId,
          set: {
            kev: true,
            kevDateAdded: sql`excluded.kev_date_added`,
            kevDueDate: sql`excluded.kev_due_date`,
            kevRansomware: sql`excluded.kev_ransomware`,
            kevRequiredAction: sql`excluded.kev_required_action`,
            // keep the NVD description; fill it only for stubs
            description: sql`case when ${vulnerabilities.description} = '' then excluded.description else ${vulnerabilities.description} end`,
          },
        });
    }
    // entries removed from the catalogue (rare) lose the flag
    if (ids.length) {
      await tx
        .update(vulnerabilities)
        .set({ kev: false })
        .where(and(eq(vulnerabilities.kev, true), notInArray(vulnerabilities.cveId, ids)));
    }
  });
  return { total: entries.length, catalogVersion: body.catalogVersion ?? null };
}

/** FIRST EPSS for CVEs that currently have findings (100 CVEs per request). */
export async function syncEpss(db: Db, baseUrl: string, fetchFn: FetchFn): Promise<{ updated: number }> {
  const rows = await db
    .selectDistinct({ cveId: deviceVulnerabilities.cveId })
    .from(deviceVulnerabilities)
    .where(and(eq(deviceVulnerabilities.status, 'open'), isNotNull(deviceVulnerabilities.cveId)));
  const ids = rows.map((r) => r.cveId);
  let updated = 0;
  for (let i = 0; i < ids.length; i += 100) {
    const batch = ids.slice(i, i + 100);
    const res = await fetchFn(`${baseUrl}?cve=${batch.join(',')}&limit=100`, { headers: { 'user-agent': 'OpenCM vulnerability sync' } });
    if (!res.ok) throw new Error(`EPSS request failed: HTTP ${res.status}`);
    const body = (await res.json()) as { data: { cve: string; epss: string; percentile: string; date: string }[] };
    for (const d of body.data) {
      if (!batch.includes(d.cve)) continue;
      await db
        .update(vulnerabilities)
        .set({ epss: Number(d.epss), epssPercentile: Number(d.percentile), epssDate: d.date })
        .where(eq(vulnerabilities.cveId, d.cve));
      updated++;
    }
  }
  return { updated };
}
