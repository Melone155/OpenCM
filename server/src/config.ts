import { z } from 'zod';

const bool = z
  .enum(['true', 'false', '1', '0'])
  .transform((v) => v === 'true' || v === '1');

const ConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().positive().default(8080),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_URL: z.string().min(1).optional(),
  REDIS_URL: z.string().default('redis://localhost:6379'),
  PUBLIC_URL: z.string().url().default('http://localhost:8080'),
  SESSION_TTL_HOURS: z.coerce.number().positive().default(12),
  COOKIE_SECURE: bool.default(false),
  LOGIN_RATE_LIMIT_PER_MIN: z.coerce.number().int().positive().default(10),
  BOOTSTRAP_ADMIN_USER: z.string().min(1).optional(),
  BOOTSTRAP_ADMIN_PASSWORD: z.string().min(12).optional(),

  // ---- agents (M1)
  /** CA + server certificate for the agent endpoint */
  PKI_DIR: z.string().default('./data/pki'),
  /** directory with opencm-agent-<os>-<arch>[.exe] (+ optional version.txt) */
  AGENT_DOWNLOAD_DIR: z.string().default('./data/files/agent'),
  /** mTLS listener for agents */
  AGENT_PORT: z.coerce.number().int().positive().default(8443),
  /** URL agents use for the mTLS endpoint; default https://<PUBLIC_URL host>:<AGENT_PORT> */
  AGENT_PUBLIC_URL: z.string().url().optional(),
  /** extra SANs for the agent endpoint certificate, comma separated */
  AGENT_TLS_HOSTNAMES: z.string().default(''),
  AGENT_HEARTBEAT_SECONDS: z.coerce.number().int().min(10).max(3600).default(60),
  AGENT_CERT_DAYS: z.coerce.number().int().min(1).max(3650).default(365),
  ENROLL_RATE_LIMIT_PER_MIN: z.coerce.number().int().positive().default(30),

  // ---- jobs (M2)
  /** offer newer agent binaries to agents via heartbeat */
  AGENT_AUTO_UPDATE: bool.default(true),
  /** stored output per task; the rest is dropped and the task marked truncated */
  TASK_OUTPUT_MAX_BYTES: z.coerce.number().int().min(1024).max(64 * 1024 * 1024).default(1024 * 1024),
  /** extra time before a dispatched/running task is declared timed out */
  TASK_TIMEOUT_GRACE_SECONDS: z.coerce.number().int().min(0).max(3600).default(120),
  /** allow approving script versions you authored yourself (four-eyes rules follow in M4) */
  SCRIPT_SELF_APPROVAL: bool.default(false),

  // ---- vulnerabilities (M3)
  VULN_FEEDS_ENABLED: bool.default(true),
  NVD_API_URL: z.string().url().default('https://services.nvd.nist.gov/rest/json/cves/2.0'),
  /** optional – raises the NVD rate limit from 5 to 50 requests / 30 s */
  NVD_API_KEY: z.string().min(1).optional(),
  /** pages (à 2000 CVEs) per worker run; the full mirror resumes on the next run */
  NVD_MAX_PAGES_PER_RUN: z.coerce.number().int().min(1).max(1000).default(20),
  KEV_URL: z.string().url().default('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
  EPSS_URL: z.string().url().default('https://api.first.org/data/v1/epss'),
  NVD_SYNC_INTERVAL_HOURS: z.coerce.number().positive().default(2),
  KEV_SYNC_INTERVAL_HOURS: z.coerce.number().positive().default(6),
  EPSS_SYNC_INTERVAL_HOURS: z.coerce.number().positive().default(24),
  /** POST target for new critical / known-exploited findings */
  VULN_WEBHOOK_URL: z.string().url().optional(),
  VULN_WEBHOOK_SECRET: z.string().min(16).optional(),

  // ---- permissions (M4) – defaults for the runtime security settings
  FOUR_EYES_ENABLED: bool.default(true),
  FOUR_EYES_DEVICE_THRESHOLD: z.coerce.number().int().min(0).max(1_000_000).default(50),
  /** devices of a user's own runs within this window count towards the four-eyes threshold (0 = each request on its own) */
  FOUR_EYES_WINDOW_MINUTES: z.coerce.number().int().min(0).max(7 * 24 * 60).default(60),
  MFA_REQUIRED: bool.default(false),
  API_TOKEN_MAX_DAYS: z.coerce.number().int().min(1).max(3650).default(365),

  // ---- LDAP / Active Directory (enabled when LDAP_URL is set)
  LDAP_URL: z.string().regex(/^ldaps?:\/\//, 'must start with ldap:// or ldaps://').optional(),
  LDAP_BIND_DN: z.string().optional(),
  LDAP_BIND_PASSWORD: z.string().optional(),
  LDAP_BASE_DN: z.string().optional(),
  LDAP_USER_FILTER: z.string().default('(&(objectClass=user)(sAMAccountName={username}))'),
  LDAP_USERNAME_ATTRIBUTE: z.string().default('sAMAccountName'),
  LDAP_DISPLAYNAME_ATTRIBUTE: z.string().default('displayName'),
  LDAP_EMAIL_ATTRIBUTE: z.string().default('mail'),
  LDAP_GROUP_BASE_DN: z.string().optional(),
  /** resolve nested AD groups (LDAP_MATCHING_RULE_IN_CHAIN); otherwise memberOf only */
  LDAP_NESTED_GROUPS: bool.default(true),
  /** only members of groups mapped in OpenCM may log in */
  LDAP_REQUIRE_GROUP: bool.default(true),
  LDAP_STARTTLS: bool.default(false),
  LDAP_CA_FILE: z.string().optional(),
  LDAP_TLS_INSECURE: bool.default(false),
  LDAP_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60_000).default(10_000),

  // ---- software distribution & patches (M5)
  /** directory for uploaded installer files (content-addressed by SHA-256) */
  PACKAGE_DIR: z.string().default('./data/files/packages'),
  PACKAGE_MAX_BYTES: z.coerce.number().int().min(1024).default(4 * 1024 ** 3),
  /** total download bandwidth for package files to agents, KiB/s (0 = unlimited) */
  PACKAGE_BANDWIDTH_KBPS: z.coerce.number().int().min(0).default(0),
  /** per-device download bandwidth, KiB/s (0 = unlimited) */
  PACKAGE_BANDWIDTH_PER_DEVICE_KBPS: z.coerce.number().int().min(0).default(0),
  /** automatic patch scan interval per online device (0 = off) */
  PATCH_SCAN_INTERVAL_HOURS: z.coerce.number().min(0).max(24 * 30).default(24),

  // ---- reports, webhooks (M6)
  /** allow plain http:// webhook targets (https is required otherwise) */
  WEBHOOK_ALLOW_HTTP: bool.default(false),
  WEBHOOK_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60_000).default(10_000),
  METRICS_RETENTION_DAYS: z.coerce.number().int().min(30).max(3650).default(400),

  // ---- OSV, security status (M7)
  /** query osv.dev for Linux distribution packages (only package names + versions are sent) */
  OSV_ENABLED: bool.default(true),
  OSV_API_URL: z.string().url().default('https://api.osv.dev'),
  /** re-check a package version after this many hours */
  OSV_SYNC_INTERVAL_HOURS: z.coerce.number().positive().default(24),
  /** packages per worker run (1000 per querybatch request) */
  OSV_MAX_PACKAGES_PER_RUN: z.coerce.number().int().min(1).max(1_000_000).default(20_000),
  /** advisory detail requests per worker run */
  OSV_MAX_DETAILS_PER_RUN: z.coerce.number().int().min(1).max(100_000).default(2000),
  /** antivirus signatures older than this count as outdated (macOS XProtect: at least 30) */
  SECURITY_AV_MAX_AGE_DAYS: z.coerce.number().int().min(1).max(365).default(3),
});

export type Config = z.infer<typeof ConfigSchema>;

export function agentPublicUrl(c: Config): string {
  if (c.AGENT_PUBLIC_URL) return c.AGENT_PUBLIC_URL.replace(/\/$/, '');
  return `https://${new URL(c.PUBLIC_URL).hostname}:${c.AGENT_PORT}`;
}

export function agentTlsHostnames(c: Config): string[] {
  const names = new Set<string>([new URL(c.PUBLIC_URL).hostname, new URL(agentPublicUrl(c)).hostname, 'localhost']);
  for (const h of c.AGENT_TLS_HOSTNAMES.split(',')) if (h.trim()) names.add(h.trim());
  return [...names];
}

/** A device counts as online if it checked in within 3 heartbeat intervals. */
export function onlineThresholdSeconds(c: Config): number {
  return c.AGENT_HEARTBEAT_SECONDS * 3;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  // Empty values count as unset: docker compose passes `${VAR:-}` as "".
  const cleaned = Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined && v.trim() !== ''));
  const parsed = ConfigSchema.safeParse(cleaned);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration: ${issues}`);
  }
  return parsed.data;
}
