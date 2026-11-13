/**
 * Version normalisation and comparison for CVE matching.
 * Comparison follows rpmvercmp: versions are split into alternating numeric and
 * alphabetic segments; numeric segments compare numerically and win over alpha.
 */

/** Strips packaging decorations so the upstream version remains. */
export function normalizeVersion(version: string, source = ''): string {
  let v = version.trim();
  if (!v) return '';
  if (source === 'dpkg') {
    v = v.replace(/^\d+:/, ''); // epoch
    v = v.replace(/[-+~][^-+~]*$/, (m) => (/^-/.test(m) ? '' : m)); // debian revision
    v = v.replace(/[+~](dfsg|ds|really|deb|ubuntu|build).*$/i, '');
  } else if (source === 'rpm') {
    v = v.replace(/^\d+:/, '');
    v = v.replace(/-[^-]*$/, ''); // release
  }
  v = v.replace(/^v(?=\d)/i, '');
  return v;
}

function segments(v: string): string[] {
  return v.match(/\d+|[a-z]+/gi) ?? [];
}

/** -1 / 0 / 1 */
export function compareVersions(a: string, b: string): number {
  const sa = segments(a);
  const sb = segments(b);
  const n = Math.max(sa.length, sb.length);
  for (let i = 0; i < n; i++) {
    const x = sa[i];
    const y = sb[i];
    if (x === undefined) return y === undefined ? 0 : /^\d/.test(y) ? -1 : 1; // 1.0 < 1.0.1, 1.0 > 1.0rc1
    if (y === undefined) return /^\d/.test(x) ? 1 : -1;
    const xn = /^\d/.test(x);
    const yn = /^\d/.test(y);
    if (xn && yn) {
      const d = BigInt(x) - BigInt(y);
      if (d !== 0n) return d > 0n ? 1 : -1;
    } else if (xn !== yn) {
      return xn ? 1 : -1;
    } else {
      const c = x.toLowerCase().localeCompare(y.toLowerCase());
      if (c !== 0) return c > 0 ? 1 : -1;
    }
  }
  return 0;
}

export interface VersionCriteria {
  version: string; // exact version, '*' (any → use range) or '-' (not applicable)
  versionStartIncluding?: string | null;
  versionStartExcluding?: string | null;
  versionEndIncluding?: string | null;
  versionEndExcluding?: string | null;
}

/**
 * True if `installed` satisfies the criteria. Wildcard criteria without any range
 * bound ("all versions") deliberately do NOT match – they would flag every version
 * forever and drown real findings.
 */
export function versionMatches(installed: string, c: VersionCriteria): boolean {
  if (!installed || !/\d/.test(installed)) return false;
  if (c.version === '-' || c.version === '') return false;
  if (c.version !== '*') return compareVersions(installed, c.version) === 0;
  const { versionStartIncluding: si, versionStartExcluding: se, versionEndIncluding: ei, versionEndExcluding: ee } = c;
  if (!si && !se && !ei && !ee) return false;
  if (si && compareVersions(installed, si) < 0) return false;
  if (se && compareVersions(installed, se) <= 0) return false;
  if (ei && compareVersions(installed, ei) > 0) return false;
  if (ee && compareVersions(installed, ee) >= 0) return false;
  return true;
}
