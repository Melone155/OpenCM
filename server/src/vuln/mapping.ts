import { sql } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { cpeRules } from '../db/schema.ts';

/**
 * Software → CPE (vendor/product) mapping.
 *  1. rules (user rules and built-in rules, ordered by priority; first match wins)
 *  2. heuristic: normalised name against products that actually have CVEs in NVD,
 *     vendor disambiguated by publisher / leading name word.
 */

export interface SoftwareKey {
  name: string;
  publisher: string;
  source: string;
}

export interface CpeRule {
  id: string;
  namePattern: string;
  publisherPattern: string | null;
  source: string | null;
  vendor: string | null;
  product: string | null;
  ignore: boolean;
  priority: number;
  enabled: boolean;
}

export interface Mapping {
  vendor: string;
  product: string;
  method: 'rule' | 'heuristic';
  ruleId: string | null;
  confidence: 'high' | 'medium' | 'low';
}

export type MappingResult = Mapping | { ignored: true; ruleId: string } | null;

/** Distribution packages: backported fixes do not change the upstream version. */
export const DISTRO_SOURCES = new Set(['dpkg', 'rpm']);

/** Glob (`*`, `?`) → anchored, case-insensitive RegExp. Everything else is literal (no ReDoS). */
export function globToRegExp(glob: string): RegExp {
  const re = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${re}$`, 'i');
}

const compiled = new Map<string, RegExp>();
function matchesGlob(glob: string, value: string): boolean {
  let re = compiled.get(glob);
  if (!re) {
    re = globToRegExp(glob);
    if (compiled.size > 5000) compiled.clear();
    compiled.set(glob, re);
  }
  return re.test(value);
}

export function ruleMatches(rule: CpeRule, sw: SoftwareKey): boolean {
  if (!rule.enabled) return false;
  if (rule.source && rule.source !== sw.source) return false;
  if (!matchesGlob(rule.namePattern, sw.name)) return false;
  if (rule.publisherPattern && !matchesGlob(rule.publisherPattern, sw.publisher)) return false;
  return true;
}

/** "Mozilla Firefox (x64 de)" → "mozilla firefox"; "7-Zip 23.01 (x64)" → "7-zip" */
export function normalizeName(name: string): string {
  return name
    .toLowerCase()
    .replace(/\([^)]*\)/g, ' ')
    .replace(/\b(x64|x86|amd64|arm64|64-bit|32-bit|64 bit|32 bit|version|v)\b/g, ' ')
    .replace(/\s\d[\w.\-]*/g, ' ') // trailing version tokens
    .replace(/[®™©]/g, '')
    .replace(/\s+-\s+.*$/, '') // " - de-DE" suffixes
    .replace(/\s+/g, ' ')
    .trim();
}

const tokens = (s: string) =>
  s
    .toLowerCase()
    .split(/[^a-z0-9+]+/)
    .filter((t) => t.length > 1 && !['inc', 'ltd', 'llc', 'gmbh', 'corp', 'corporation', 'the', 'foundation', 'software', 'project', 'team', 'co', 'org'].includes(t));

/** product → vendors, built from NVD data (only products with known CVEs). */
export type ProductIndex = Map<string, Set<string>>;

export function heuristicMapping(sw: SoftwareKey, index: ProductIndex): Mapping | null {
  const norm = normalizeName(sw.name);
  if (!norm) return null;
  const words = norm.split(' ');
  const candidates = [words.join('_'), words.slice(1).join('_'), words.join('-'), words.join('')].filter((c, i, a) => c && a.indexOf(c) === i);
  const pubTokens = new Set(tokens(sw.publisher));
  for (const product of candidates) {
    const vendors = index.get(product);
    if (!vendors?.size) continue;
    // vendor = leading name word (e.g. "mozilla firefox") or overlapping with publisher
    const byName = [...vendors].find((v) => v === words[0]);
    const byPublisher = [...vendors].filter((v) => tokens(v).some((t) => pubTokens.has(t)));
    const vendor = byName ?? (byPublisher.length === 1 ? byPublisher[0] : vendors.size === 1 ? [...vendors][0] : undefined);
    if (!vendor) continue;
    return { vendor, product, method: 'heuristic', ruleId: null, confidence: DISTRO_SOURCES.has(sw.source) ? 'low' : 'medium' };
  }
  return null;
}

export function mapSoftware(sw: SoftwareKey, rules: CpeRule[], index: ProductIndex): MappingResult {
  for (const r of rules) {
    if (!ruleMatches(r, sw)) continue;
    if (r.ignore) return { ignored: true, ruleId: r.id };
    if (r.vendor && r.product) {
      return { vendor: r.vendor, product: r.product, method: 'rule', ruleId: r.id, confidence: DISTRO_SOURCES.has(sw.source) ? 'low' : 'high' };
    }
  }
  return heuristicMapping(sw, index);
}

export async function loadRules(db: Db): Promise<CpeRule[]> {
  const rows = await db.select().from(cpeRules).where(sql`${cpeRules.enabled}`);
  // user rules before built-in rules at equal priority
  return rows.sort((a, b) => a.priority - b.priority || (a.origin === b.origin ? 0 : a.origin === 'user' ? -1 : 1));
}

/** Words that say nothing about the product – a match on them alone is no evidence. */
const GENERIC = new Set([
  'agent', 'server', 'service', 'services', 'client', 'console', 'manager', 'management', 'browser', 'network', 'boot', 'web',
  'tool', 'tools', 'driver', 'drivers', 'update', 'updater', 'runtime', 'host', 'desktop', 'app', 'application', 'suite',
  'plugin', 'addin', 'add', 'in', 'for', 'and', 'pro', 'professional', 'enterprise', 'edition', 'express', 'setup', 'helper',
  'support', 'common', 'core', 'shared', 'components', 'component', 'library', 'sdk', 'kit', 'package', 'microsoft', 'windows',
]);

/** Suggest NVD products for unmapped software (overlap of distinctive tokens). */
export function suggestProducts(sw: SoftwareKey, index: ProductIndex, limit = 5): { vendor: string; product: string }[] {
  const want = new Set(tokens(normalizeName(sw.name)).filter((t) => !GENERIC.has(t)));
  if (!want.size) return [];
  const scored: { vendor: string; product: string; score: number }[] = [];
  for (const [product, vendors] of index) {
    const pt = tokens(product.replace(/_/g, ' ')).filter((t) => !GENERIC.has(t));
    if (!pt.length) continue;
    const hit = pt.filter((t) => want.has(t)).length;
    if (!hit) continue;
    const score = hit / Math.max(pt.length, want.size);
    for (const vendor of vendors) scored.push({ vendor, product, score: score + (tokens(sw.publisher).some((t) => tokens(vendor).includes(t)) ? 0.5 : 0) });
  }
  return scored
    .sort((a, b) => b.score - a.score || a.product.length - b.product.length)
    .slice(0, limit)
    .map(({ vendor, product }) => ({ vendor, product }));
}

/**
 * Built-in rules for common software (seeded with origin "builtin"; can be disabled
 * or overridden by user rules). Vendor/product names follow the NVD CPE dictionary.
 */
export const BUILTIN_RULES: { namePattern: string; source?: string; vendor?: string; product?: string; ignore?: boolean; note?: string }[] = [
  // Windows / macOS applications
  { namePattern: 'Mozilla Firefox*', vendor: 'mozilla', product: 'firefox' },
  { namePattern: 'Firefox', source: 'app', vendor: 'mozilla', product: 'firefox' },
  { namePattern: 'Mozilla Thunderbird*', vendor: 'mozilla', product: 'thunderbird' },
  { namePattern: 'Thunderbird', source: 'app', vendor: 'mozilla', product: 'thunderbird' },
  { namePattern: 'Google Chrome', vendor: 'google', product: 'chrome' },
  { namePattern: 'Microsoft Edge', vendor: 'microsoft', product: 'edge_chromium' },
  { namePattern: '7-Zip*', vendor: '7-zip', product: '7-zip' },
  { namePattern: 'Notepad++*', vendor: 'notepad-plus-plus', product: 'notepad++' },
  { namePattern: 'Adobe Acrobat Reader*', vendor: 'adobe', product: 'acrobat_reader_dc' },
  { namePattern: 'VLC media player', vendor: 'videolan', product: 'vlc_media_player' },
  { namePattern: 'VLC', source: 'app', vendor: 'videolan', product: 'vlc_media_player' },
  { namePattern: 'PuTTY*', vendor: 'putty', product: 'putty' },
  { namePattern: 'WinSCP*', vendor: 'winscp', product: 'winscp' },
  { namePattern: 'WinRAR*', vendor: 'rarlab', product: 'winrar' },
  { namePattern: 'Git', vendor: 'git-scm', product: 'git' },
  { namePattern: 'Git version *', vendor: 'git-scm', product: 'git' },
  { namePattern: 'Python 3.* (*', vendor: 'python', product: 'python' },
  { namePattern: 'KeePass Password Safe*', vendor: 'keepass', product: 'keepass' },
  { namePattern: 'FileZilla*', vendor: 'filezilla-project', product: 'filezilla_client' },
  { namePattern: 'Wireshark*', vendor: 'wireshark', product: 'wireshark' },
  { namePattern: 'OpenVPN*', vendor: 'openvpn', product: 'openvpn' },
  { namePattern: 'TeamViewer*', vendor: 'teamviewer', product: 'teamviewer' },
  { namePattern: 'AnyDesk*', vendor: 'anydesk', product: 'anydesk' },
  { namePattern: 'Microsoft Visual Studio Code*', vendor: 'microsoft', product: 'visual_studio_code' },
  { namePattern: 'Visual Studio Code', source: 'app', vendor: 'microsoft', product: 'visual_studio_code' },
  { namePattern: 'Node.js', vendor: 'nodejs', product: 'node.js' },
  { namePattern: 'LibreOffice*', vendor: 'libreoffice', product: 'libreoffice' },
  { namePattern: 'Foxit PDF Reader*', vendor: 'foxit', product: 'pdf_reader' },
  { namePattern: 'GIMP*', vendor: 'gimp', product: 'gimp' },
  { namePattern: 'Zoom Workplace*', vendor: 'zoom', product: 'workplace' },
  { namePattern: 'Safari', source: 'app', vendor: 'apple', product: 'safari' },
  // Noise: components that the heuristic might map wrongly
  { namePattern: 'Microsoft Visual C++ *Redistributable*', ignore: true, note: 'Redistributables werden über Windows Update / M5 behandelt' },
  { namePattern: 'Microsoft .NET*', ignore: true, note: 'Betriebssystemnah → M5 Patch-Management' },
  { namePattern: 'Update for *', ignore: true },
  { namePattern: 'Security Update for *', ignore: true },
  // Linux distribution packages (confidence "low": backports!)
  { namePattern: 'openssl', vendor: 'openssl', product: 'openssl' },
  { namePattern: 'libssl3', source: 'dpkg', vendor: 'openssl', product: 'openssl' },
  { namePattern: 'openssh-server', vendor: 'openbsd', product: 'openssh' },
  { namePattern: 'openssh-client', vendor: 'openbsd', product: 'openssh' },
  { namePattern: 'openssh', vendor: 'openbsd', product: 'openssh' },
  { namePattern: 'sudo', vendor: 'sudo_project', product: 'sudo' },
  { namePattern: 'curl', vendor: 'haxx', product: 'curl' },
  { namePattern: 'bash', vendor: 'gnu', product: 'bash' },
  { namePattern: 'apache2', vendor: 'apache', product: 'http_server' },
  { namePattern: 'httpd', vendor: 'apache', product: 'http_server' },
  { namePattern: 'nginx', vendor: 'f5', product: 'nginx' },
  { namePattern: 'samba', vendor: 'samba', product: 'samba' },
  { namePattern: 'bind9', vendor: 'isc', product: 'bind' },
  { namePattern: 'git', source: 'dpkg', vendor: 'git-scm', product: 'git' },
  { namePattern: 'git', source: 'rpm', vendor: 'git-scm', product: 'git' },
  { namePattern: 'vim', vendor: 'vim', product: 'vim' },
  { namePattern: 'libc6', vendor: 'gnu', product: 'glibc' },
  { namePattern: 'glibc', vendor: 'gnu', product: 'glibc' },
  { namePattern: 'xz-utils', vendor: 'tukaani', product: 'xz' },
  { namePattern: 'xz', source: 'rpm', vendor: 'tukaani', product: 'xz' },
  { namePattern: 'polkit', vendor: 'polkit_project', product: 'polkit' },
  { namePattern: 'policykit-1', vendor: 'polkit_project', product: 'polkit' },
  { namePattern: 'mariadb-server', vendor: 'mariadb', product: 'mariadb' },
  { namePattern: 'tomcat*', vendor: 'apache', product: 'tomcat' },
];

/** Seeds/updates built-in rules (idempotent: matched by namePattern+source+origin). */
export async function ensureBuiltinRules(db: Db): Promise<void> {
  const existing = await db.select({ namePattern: cpeRules.namePattern, source: cpeRules.source }).from(cpeRules).where(sql`${cpeRules.origin} = 'builtin'`);
  const key = (p: string, s: string | null | undefined) => `${p}\u0000${s ?? ''}`;
  const have = new Set(existing.map((e) => key(e.namePattern, e.source)));
  const missing = BUILTIN_RULES.filter((r) => !have.has(key(r.namePattern, r.source)));
  if (!missing.length) return;
  await db.insert(cpeRules).values(
    missing.map((r) => ({
      namePattern: r.namePattern,
      source: r.source ?? null,
      vendor: r.vendor ?? null,
      product: r.product ?? null,
      ignore: !!r.ignore,
      priority: r.ignore ? 50 : 100,
      origin: 'builtin',
      note: r.note ?? '',
    })),
  );
}
