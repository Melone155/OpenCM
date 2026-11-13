import type { NvdCve } from '../src/vuln/nvd.ts';

/**
 * Synthetic CVEs in the exact NVD API 2.0 format (ids CVE-2099-*, not real data).
 */
const cpe = (vendor: string, product: string, version = '*') => `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
const v31 = (score: number, severity: string) => ({
  cvssMetricV31: [{ source: 'nvd@nist.gov', type: 'Primary', cvssData: { version: '3.1', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', baseScore: score, baseSeverity: severity } }],
});
const base = (id: string, desc: string, metrics: NvdCve['metrics'], matches: object[], extra: Partial<NvdCve> = {}): NvdCve => ({
  id,
  published: '2099-01-01T10:00:00.000',
  lastModified: '2099-01-02T10:00:00.000',
  vulnStatus: 'Analyzed',
  descriptions: [
    { lang: 'en', value: desc },
    { lang: 'es', value: 'descripción' },
  ],
  metrics,
  weaknesses: [{ description: [{ lang: 'en', value: 'CWE-787' }, { lang: 'en', value: 'NVD-CWE-noinfo' }] }],
  configurations: [{ nodes: [{ operator: 'OR', negate: false, cpeMatch: matches }] } as never],
  references: [{ url: `https://example.org/${id}`, tags: ['Vendor Advisory'] }],
  ...extra,
});

export const NVD_CVES: NvdCve[] = [
  base('CVE-2099-0001', 'Firefox memory corruption', v31(9.8, 'CRITICAL'), [{ vulnerable: true, criteria: cpe('mozilla', 'firefox'), versionEndExcluding: '132.0' }]),
  base('CVE-2099-0002', '7-Zip heap overflow', v31(7.8, 'HIGH'), [{ vulnerable: true, criteria: cpe('7-zip', '7-zip', '23.01') }]),
  base('CVE-2099-0003', 'OpenSSL issue', v31(5.9, 'MEDIUM'), [
    { vulnerable: true, criteria: cpe('openssl', 'openssl'), versionStartIncluding: '3.0.0', versionEndIncluding: '3.0.13' },
  ]),
  base('CVE-2099-0004', 'Notepad++ issue (escaped CPE)', v31(7.3, 'HIGH'), [
    { vulnerable: true, criteria: 'cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:*:*:*:*:*:*:*:*', versionEndExcluding: '8.6.5' },
  ]),
  base('CVE-2099-0005', 'All Firefox versions (unbounded wildcard → ignored)', v31(4.3, 'MEDIUM'), [{ vulnerable: true, criteria: cpe('mozilla', 'firefox') }]),
  base(
    'CVE-2099-0006',
    'Platform-only and OS entries',
    v31(8.1, 'HIGH'),
    [
      { vulnerable: false, criteria: cpe('mozilla', 'firefox', '131.0') },
      { vulnerable: true, criteria: 'cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:*:*' },
    ],
  ),
  base('CVE-2099-0007', 'Will be rejected later', v31(6.5, 'MEDIUM'), [{ vulnerable: true, criteria: cpe('7-zip', '7-zip'), versionEndExcluding: '24.0' }]),
  base('CVE-2099-0008', 'Acme Widget issue (heuristic mapping)', { cvssMetricV2: [{ source: 'nvd@nist.gov', type: 'Primary', baseSeverity: 'HIGH', cvssData: { version: '2.0', vectorString: 'AV:N/AC:L/Au:N/C:P/I:P/A:P', baseScore: 7.5 } }] }, [
    { vulnerable: true, criteria: cpe('acme', 'widget'), versionEndIncluding: '1.5' },
  ]),
  base('CVE-2099-0009', 'Log4j-style issue, nothing installed', v31(10, 'CRITICAL'), [
    { vulnerable: true, criteria: cpe('apache', 'log4j'), versionStartIncluding: '2.0.1', versionEndExcluding: '2.15.0' },
  ]),
];

/** Returned by incremental (lastModStartDate) requests. */
export const NVD_MODIFIED: NvdCve[] = [
  { ...NVD_CVES[6]!, vulnStatus: 'Rejected', configurations: [] },
  base('CVE-2099-0010', 'New Notepad++ issue', v31(9.1, 'CRITICAL'), [{ vulnerable: true, criteria: 'cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.6.2:*:*:*:*:*:*:*' }]),
];

export const KEV = {
  title: 'CISA Catalog of Known Exploited Vulnerabilities',
  catalogVersion: '2099.01.01',
  dateReleased: '2099-01-01T00:00:00Z',
  count: 2,
  vulnerabilities: [
    { cveID: 'CVE-2099-0001', vendorProject: 'Mozilla', product: 'Firefox', vulnerabilityName: 'Firefox RCE', dateAdded: '2099-01-03', shortDescription: 'KEV text', requiredAction: 'Apply updates.', dueDate: '2000-01-01', knownRansomwareCampaignUse: 'Known' },
    { cveID: 'CVE-2099-0999', vendorProject: 'Other', product: 'Thing', vulnerabilityName: 'Not in NVD mirror yet', dateAdded: '2099-01-03', shortDescription: 'Stub from KEV', requiredAction: 'Patch.', dueDate: '2099-02-01', knownRansomwareCampaignUse: 'Unknown' },
  ],
};

export interface FakeFeeds {
  fetch: (url: string, init?: RequestInit) => Promise<Response>;
  calls: string[];
  webhooks: { body: string; headers: Record<string, string> }[];
  failKev: boolean;
  nvdRateLimitOnce: boolean;
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** Simulated feed endpoints (NVD pages of max. 3 results, KEV, EPSS, webhook target). */
export function fakeFeeds(): FakeFeeds {
  const f: FakeFeeds = {
    calls: [],
    webhooks: [],
    failKev: false,
    nvdRateLimitOnce: true,
    async fetch(url, init) {
      f.calls.push(url);
      const u = new URL(url);
      if (u.hostname === 'hooks.test') {
        f.webhooks.push({ body: String(init?.body), headers: (init?.headers ?? {}) as Record<string, string> });
        return new Response(null, { status: 204 });
      }
      if (u.hostname === 'kev.test') return f.failKev ? new Response('down', { status: 503 }) : json(KEV);
      if (u.hostname === 'epss.test') {
        const ids = (u.searchParams.get('cve') ?? '').split(',');
        return json({ status: 'OK', data: ids.map((cve, i) => ({ cve, epss: (0.9 - i * 0.1).toFixed(9), percentile: '0.990000000', date: '2099-01-05' })) });
      }
      if (u.hostname === 'nvd.test') {
        if (f.nvdRateLimitOnce) {
          f.nvdRateLimitOnce = false;
          return new Response('rate limited', { status: 403 });
        }
        const list = u.searchParams.has('lastModStartDate') ? NVD_MODIFIED : NVD_CVES;
        const start = Number(u.searchParams.get('startIndex') ?? 0);
        const size = Math.min(3, Number(u.searchParams.get('resultsPerPage') ?? 2000));
        return json({
          resultsPerPage: size,
          startIndex: start,
          totalResults: list.length,
          format: 'NVD_CVE',
          version: '2.0',
          vulnerabilities: list.slice(start, start + size).map((cve) => ({ cve })),
        });
      }
      return new Response('not found', { status: 404 });
    },
  };
  return f;
}
