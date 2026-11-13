import {
  type AnyPgColumn,
  bigint,
  bigserial,
  boolean,
  date,
  doublePrecision,
  index,
  inet,
  integer,
  uniqueIndex,
  jsonb,
  numeric,
  pgTable,
  primaryKey,
  real,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';

const ts = (name: string) => timestamp(name, { withTimezone: true });
const createdAt = () => ts('created_at').notNull().defaultNow();
const updatedAt = () => ts('updated_at').notNull().defaultNow();

// ---------------------------------------------------------------- identity / RBAC

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  username: text('username').notNull().unique(),
  displayName: text('display_name').notNull().default(''),
  email: text('email'),
  /** null for externally authenticated users (LDAP/OIDC, M4) */
  passwordHash: text('password_hash'),
  authSource: text('auth_source').notNull().default('local'),
  isActive: boolean('is_active').notNull().default(true),
  lastLoginAt: ts('last_login_at'),
  /** AES-256-GCM encrypted TOTP secret (see auth/secretbox.ts) */
  mfaSecretEnc: text('mfa_secret_enc'),
  mfaEnabled: boolean('mfa_enabled').notNull().default(false),
  mfaRecoveryHashes: text('mfa_recovery_hashes').array().notNull().default([]),
  /** last accepted TOTP time step – prevents code replay */
  mfaLastCounter: bigint('mfa_last_counter', { mode: 'number' }),
  ldapDn: text('ldap_dn'),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const groups = pgTable('groups', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull().unique(),
  description: text('description').notNull().default(''),
  /** DN of an LDAP/AD group whose members are synced into this group at login */
  ldapGroup: text('ldap_group'),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const userGroups = pgTable(
  'user_groups',
  {
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    groupId: uuid('group_id').notNull().references(() => groups.id, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.userId, t.groupId] })],
);

export const roles = pgTable('roles', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull().unique(),
  description: text('description').notNull().default(''),
  /** permission strings "module:action", "module:*" or "*" */
  permissions: text('permissions').array().notNull().default([]),
  isSystem: boolean('is_system').notNull().default(false),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

/**
 * Role assignment. scopeDeviceGroupIds = null → global; otherwise the role only
 * applies to devices in these device groups (enforced from M4 on).
 */
export const userRoles = pgTable(
  'user_roles',
  {
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    roleId: uuid('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
    scopeDeviceGroupIds: uuid('scope_device_group_ids').array(),
  },
  (t) => [primaryKey({ columns: [t.userId, t.roleId] })],
);

export const groupRoles = pgTable(
  'group_roles',
  {
    groupId: uuid('group_id').notNull().references(() => groups.id, { onDelete: 'cascade' }),
    roleId: uuid('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
    scopeDeviceGroupIds: uuid('scope_device_group_ids').array(),
  },
  (t) => [primaryKey({ columns: [t.groupId, t.roleId] })],
);

export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    tokenHash: text('token_hash').notNull().unique(),
    /** MFA is mandatory but not set up yet: only MFA setup is allowed */
    mfaPending: boolean('mfa_pending').notNull().default(false),
    ip: inet('ip'),
    userAgent: text('user_agent'),
    createdAt: createdAt(),
    lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
    expiresAt: ts('expires_at').notNull(),
  },
  (t) => [index('sessions_user_idx').on(t.userId), index('sessions_expires_idx').on(t.expiresAt)],
);

/** Personal / service API tokens (endpoints follow in M4). */
export const apiTokens = pgTable('api_tokens', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  tokenHash: text('token_hash').notNull().unique(),
  /** subset of the owner's permissions; empty = inherit owner */
  permissions: text('permissions').array().notNull().default([]),
  expiresAt: ts('expires_at'),
  lastUsedAt: ts('last_used_at'),
  revokedAt: ts('revoked_at'),
  createdAt: createdAt(),
});

/** Runtime settings (security policies) that admins change via API. */
export const settings = pgTable('settings', {
  key: text('key').primaryKey(),
  value: jsonb('value').$type<Record<string, unknown>>().notNull(),
  updatedAt: updatedAt(),
  updatedBy: uuid('updated_by').references(() => users.id, { onDelete: 'set null' }),
});

/** Four-eyes approvals for critical actions. */
export const approvalRequests = pgTable(
  'approval_requests',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    action: text('action').notNull(), // job.run | script.run | remediation.run | job.enable
    summary: text('summary').notNull(),
    payload: jsonb('payload').$type<Record<string, unknown>>().notNull(),
    deviceCount: integer('device_count').notNull().default(0),
    status: text('status').notNull().default('pending'), // pending | approved | rejected | expired | failed
    requestedBy: uuid('requested_by').references(() => users.id, { onDelete: 'set null' }),
    requestedAt: ts('requested_at').notNull().defaultNow(),
    expiresAt: ts('expires_at').notNull(),
    decidedBy: uuid('decided_by').references(() => users.id, { onDelete: 'set null' }),
    decidedAt: ts('decided_at'),
    reason: text('reason'),
    result: jsonb('result').$type<Record<string, unknown>>(),
  },
  (t) => [index('approval_requests_status_idx').on(t.status, t.requestedAt)],
);

// ---------------------------------------------------------------- audit

/** Append-only. UPDATE/DELETE are rejected by a trigger (migration 0001). */
export const auditLog = pgTable(
  'audit_log',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    at: ts('at').notNull().defaultNow(),
    actorType: text('actor_type').notNull(), // user | api_token | agent | system
    actorId: uuid('actor_id'),
    actorName: text('actor_name').notNull(),
    action: text('action').notNull(), // e.g. "user.create", "auth.login"
    targetType: text('target_type'),
    targetId: text('target_id'),
    details: jsonb('details').$type<Record<string, unknown>>().notNull().default({}),
    ip: inet('ip'),
  },
  (t) => [
    index('audit_at_idx').on(t.at),
    index('audit_actor_idx').on(t.actorId),
    index('audit_action_idx').on(t.action),
  ],
);

// ---------------------------------------------------------------- devices

export const deviceGroups = pgTable('device_groups', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull().unique(),
  description: text('description').notNull().default(''),
  kind: text('kind').notNull().default('static'), // static | dynamic
  /** filter expression for dynamic groups (M2) */
  filter: jsonb('filter').$type<Record<string, unknown>>(),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const devices = pgTable(
  'devices',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    hostname: text('hostname').notNull(),
    os: text('os').notNull(), // windows | linux | macos
    osVersion: text('os_version').notNull().default(''),
    arch: text('arch').notNull().default(''),
    agentVersion: text('agent_version'),
    /** stable hardware/OS id reported by the agent; unique – a registered machine cannot enroll again until its device is deleted */
    machineId: text('machine_id'),
    status: text('status').notNull().default('active'), // active | revoked
    certFingerprint: text('cert_fingerprint'), // sha256 hex of the client cert DER
    certSerial: text('cert_serial'),
    certExpiresAt: ts('cert_expires_at'),
    manufacturer: text('manufacturer'),
    model: text('model'),
    serialNumber: text('serial_number'),
    loggedOnUser: text('logged_on_user'),
    lastIp: inet('last_ip'),
    inventoryRequested: boolean('inventory_requested').notNull().default(true),
    lastInventoryAt: ts('last_inventory_at'),
    agentStartedAt: ts('agent_started_at'),
    lastSeenAt: ts('last_seen_at'),
    enrolledAt: ts('enrolled_at').notNull().defaultNow(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('devices_hostname_idx').on(t.hostname),
    uniqueIndex('devices_machine_id_uq').on(t.machineId),
    uniqueIndex('devices_cert_fp_uq').on(t.certFingerprint),
  ],
);

export const enrollmentTokens = pgTable('enrollment_tokens', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  tokenHash: text('token_hash').notNull().unique(),
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  deviceGroupId: uuid('device_group_id').references(() => deviceGroups.id, { onDelete: 'set null' }),
  maxUses: integer('max_uses'), // null = unlimited
  uses: integer('uses').notNull().default(0),
  expiresAt: ts('expires_at'), // null = never expires
  revokedAt: ts('revoked_at'),
  createdAt: createdAt(),
});

/** Latest full inventory snapshot per device (software lives in device_software). */
export const deviceInventory = pgTable('device_inventory', {
  deviceId: uuid('device_id')
    .primaryKey()
    .references(() => devices.id, { onDelete: 'cascade' }),
  collectedAt: ts('collected_at').notNull(),
  receivedAt: ts('received_at').notNull().defaultNow(),
  data: jsonb('data').$type<Record<string, unknown>>().notNull(),
});

export const deviceSoftware = pgTable(
  'device_software',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    deviceId: uuid('device_id')
      .notNull()
      .references(() => devices.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    version: text('version').notNull().default(''),
    publisher: text('publisher').notNull().default(''),
    installDate: text('install_date'),
    source: text('source').notNull().default(''),
    arch: text('arch').notNull().default(''),
    /** dpkg: source package / version; rpm: source RPM name / epoch:version-release (M7, OSV) */
    sourceName: text('source_name'),
    sourceVersion: text('source_version'),
  },
  (t) => [index('device_software_device_idx').on(t.deviceId), index('device_software_name_idx').on(t.name)],
);

export const deviceHistory = pgTable(
  'device_history',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    deviceId: uuid('device_id')
      .notNull()
      .references(() => devices.id, { onDelete: 'cascade' }),
    at: ts('at').notNull().defaultNow(),
    category: text('category').notNull(), // software | hardware | os | service | user | group | autostart | patch | disk | device
    change: text('change').notNull(), // added | removed | changed
    itemKey: text('item_key').notNull(),
    oldValue: jsonb('old_value'),
    newValue: jsonb('new_value'),
  },
  (t) => [index('device_history_device_at_idx').on(t.deviceId, t.at)],
);

// ---------------------------------------------------------------- custom fields (M2)

export const customFields = pgTable('custom_fields', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull().unique(), // slug, used in filters: custom:<name>
  label: text('label').notNull(),
  type: text('type').notNull().default('string'), // string | number | boolean | date
  description: text('description').notNull().default(''),
  createdAt: createdAt(),
});

export const deviceCustomValues = pgTable(
  'device_custom_values',
  {
    deviceId: uuid('device_id')
      .notNull()
      .references(() => devices.id, { onDelete: 'cascade' }),
    fieldId: uuid('field_id')
      .notNull()
      .references(() => customFields.id, { onDelete: 'cascade' }),
    value: text('value').notNull(),
    source: text('source').notNull().default('manual'), // manual | script
    updatedAt: updatedAt(),
  },
  (t) => [primaryKey({ columns: [t.deviceId, t.fieldId] })],
);

// ---------------------------------------------------------------- scripts & jobs (M2)

export const scripts = pgTable('scripts', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull().unique(),
  description: text('description').notNull().default(''),
  interpreter: text('interpreter').notNull(), // powershell | cmd | bash | zsh | python
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export interface ScriptParameter {
  name: string;
  label?: string;
  type: 'string' | 'number' | 'boolean';
  required: boolean;
  default?: string | number | boolean | null;
}

/** Immutable once created; status moves draft → approved → retired. */
export const scriptVersions = pgTable(
  'script_versions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    scriptId: uuid('script_id')
      .notNull()
      .references(() => scripts.id, { onDelete: 'cascade' }),
    version: integer('version').notNull(),
    content: text('content').notNull(),
    sha256: text('sha256').notNull(),
    /** HMAC over id + sha256 with PKI_DIR/integrity.key – detects joint changes of content and hash */
    seal: text('seal'),
    parameters: jsonb('parameters').$type<ScriptParameter[]>().notNull().default([]),
    changeNote: text('change_note').notNull().default(''),
    status: text('status').notNull().default('draft'),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    approvedBy: uuid('approved_by').references(() => users.id, { onDelete: 'set null' }),
    approvedAt: ts('approved_at'),
  },
  (t) => [uniqueIndex('script_versions_script_version_uq').on(t.scriptId, t.version)],
);

export interface JobTargets {
  deviceIds: string[];
  groupIds: string[];
  allDevices: boolean;
}

export interface MaintenanceWindow {
  days: number[]; // 0 = Sunday … 6 = Saturday (day the window starts)
  start: string; // HH:MM
  end: string; // HH:MM (may be < start → window crosses midnight)
}

export interface JobOptions {
  timeoutSeconds: number;
  maxRetries: number;
  retryDelaySeconds: number;
  stopOnError: boolean;
  maintenanceWindow: MaintenanceWindow | null;
}

export const jobs = pgTable('jobs', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description').notNull().default(''),
  enabled: boolean('enabled').notNull().default(true),
  trigger: text('trigger').notNull(), // manual | once | cron | agent_start | user_login
  runAt: ts('run_at'),
  cron: text('cron'),
  timezone: text('timezone').notNull().default('UTC'),
  nextRunAt: ts('next_run_at'),
  lastRunAt: ts('last_run_at'),
  targets: jsonb('targets').$type<JobTargets>().notNull(),
  options: jsonb('options').$type<JobOptions>().notNull(),
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const jobSteps = pgTable(
  'job_steps',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    jobId: uuid('job_id')
      .notNull()
      .references(() => jobs.id, { onDelete: 'cascade' }),
    position: integer('position').notNull(),
    scriptVersionId: uuid('script_version_id')
      .notNull()
      .references(() => scriptVersions.id, { onDelete: 'restrict' }),
    params: jsonb('params').$type<Record<string, string | number | boolean>>().notNull().default({}),
    continueOnError: boolean('continue_on_error').notNull().default(false),
    customFieldId: uuid('custom_field_id').references(() => customFields.id, { onDelete: 'set null' }),
  },
  (t) => [uniqueIndex('job_steps_job_position_uq').on(t.jobId, t.position)],
);

/** A file the agent downloads (mTLS, SHA-256 verified) before the step runs. */
export interface RunFile {
  sha256: string;
  name: string;
  sizeBytes: number;
}

export interface RunStep {
  position: number;
  /** empty for generated steps (packages, patches) */
  scriptId: string;
  scriptName: string;
  scriptVersionId: string;
  version: number;
  interpreter: string;
  content: string;
  sha256: string;
  params: Record<string, string | number | boolean>;
  continueOnError: boolean;
  customFieldId: string | null;
  /** script (default) | package | patch_scan | patch_install */
  kind?: 'script' | 'package' | 'patch_scan' | 'patch_install';
  /** HMAC seal over sha256 (+ file hashes), see integrity.ts */
  seal?: string;
  files?: RunFile[];
  packageVersionId?: string;
}

export const jobRuns = pgTable(
  'job_runs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    jobId: uuid('job_id').references(() => jobs.id, { onDelete: 'cascade' }), // null for script test runs
    name: text('name').notNull(),
    trigger: text('trigger').notNull(), // manual | once | cron | agent_start | user_login | test | rerun
    triggeredBy: uuid('triggered_by').references(() => users.id, { onDelete: 'set null' }),
    steps: jsonb('steps').$type<RunStep[]>().notNull(),
    options: jsonb('options').$type<JobOptions>().notNull(),
    status: text('status').notNull().default('running'), // running | completed | cancelled
    createdAt: createdAt(),
    finishedAt: ts('finished_at'),
    deploymentId: uuid('deployment_id').references((): AnyPgColumn => deployments.id, { onDelete: 'set null' }),
    ring: integer('ring'),
  },
  (t) => [index('job_runs_job_idx').on(t.jobId, t.createdAt), index('job_runs_deployment_idx').on(t.deploymentId, t.ring)],
);

export interface StepResult {
  position: number;
  status: 'succeeded' | 'failed' | 'skipped' | 'timeout' | 'cancelled';
  exitCode: number | null;
  durationMs: number;
}

export const tasks = pgTable(
  'tasks',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    runId: uuid('run_id')
      .notNull()
      .references(() => jobRuns.id, { onDelete: 'cascade' }),
    deviceId: uuid('device_id')
      .notNull()
      .references(() => devices.id, { onDelete: 'cascade' }),
    status: text('status').notNull().default('pending'), // pending | dispatched | running | succeeded | failed | timeout | cancelled | skipped
    attempt: integer('attempt').notNull().default(1),
    notBefore: ts('not_before').notNull().defaultNow(),
    dispatchedAt: ts('dispatched_at'),
    startedAt: ts('started_at'),
    finishedAt: ts('finished_at'),
    exitCode: integer('exit_code'),
    error: text('error'),
    cancelRequested: boolean('cancel_requested').notNull().default(false),
    stepResults: jsonb('step_results').$type<StepResult[]>().notNull().default([]),
    outputBytes: integer('output_bytes').notNull().default(0),
    outputTruncated: boolean('output_truncated').notNull().default(false),
    createdAt: createdAt(),
  },
  (t) => [index('tasks_device_status_idx').on(t.deviceId, t.status), index('tasks_run_idx').on(t.runId)],
);

// ---------------------------------------------------------------- vulnerabilities (M3)

export interface VulnReference {
  url: string;
  tags: string[];
}

export const vulnerabilities = pgTable(
  'vulnerabilities',
  {
    cveId: text('cve_id').primaryKey(),
    description: text('description').notNull().default(''),
    published: ts('published'),
    lastModified: ts('last_modified'),
    vulnStatus: text('vuln_status').notNull().default(''),
    cvssScore: real('cvss_score'),
    cvssSeverity: text('cvss_severity'), // CRITICAL | HIGH | MEDIUM | LOW | NONE
    cvssVersion: text('cvss_version'),
    cvssVector: text('cvss_vector'),
    cwes: text('cwes').array().notNull().default([]),
    refs: jsonb('refs').$type<VulnReference[]>().notNull().default([]),
    kev: boolean('kev').notNull().default(false),
    kevDateAdded: text('kev_date_added'),
    kevDueDate: text('kev_due_date'),
    kevRansomware: text('kev_ransomware'),
    kevRequiredAction: text('kev_required_action'),
    epss: real('epss'),
    epssPercentile: real('epss_percentile'),
    epssDate: text('epss_date'),
    acceptedAt: ts('accepted_at'),
    acceptedBy: uuid('accepted_by').references(() => users.id, { onDelete: 'set null' }),
    acceptedReason: text('accepted_reason'),
    updatedAt: updatedAt(),
  },
  (t) => [index('vulnerabilities_kev_idx').on(t.kev), index('vulnerabilities_severity_idx').on(t.cvssSeverity)],
);

export const vulnCpeMatches = pgTable(
  'vuln_cpe_matches',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    cveId: text('cve_id')
      .notNull()
      .references(() => vulnerabilities.cveId, { onDelete: 'cascade' }),
    vendor: text('vendor').notNull(),
    product: text('product').notNull(),
    version: text('version').notNull().default('*'),
    targetSw: text('target_sw').notNull().default('*'),
    versionStartIncluding: text('version_start_including'),
    versionStartExcluding: text('version_start_excluding'),
    versionEndIncluding: text('version_end_including'),
    versionEndExcluding: text('version_end_excluding'),
  },
  (t) => [index('vuln_cpe_matches_product_idx').on(t.product, t.vendor), index('vuln_cpe_matches_cve_idx').on(t.cveId)],
);

export const cpeRules = pgTable('cpe_rules', {
  id: uuid('id').primaryKey().defaultRandom(),
  namePattern: text('name_pattern').notNull(), // glob, case-insensitive, whole name
  publisherPattern: text('publisher_pattern'),
  source: text('source'), // registry | msi | appx | dpkg | rpm | app | null = any
  vendor: text('vendor'),
  product: text('product'),
  ignore: boolean('ignore').notNull().default(false),
  priority: integer('priority').notNull().default(100), // lower = earlier
  origin: text('origin').notNull().default('user'), // user | builtin
  enabled: boolean('enabled').notNull().default(true),
  note: text('note').notNull().default(''),
  createdAt: createdAt(),
});

export const deviceVulnerabilities = pgTable(
  'device_vulnerabilities',
  {
    deviceId: uuid('device_id')
      .notNull()
      .references(() => devices.id, { onDelete: 'cascade' }),
    cveId: text('cve_id')
      .notNull()
      .references(() => vulnerabilities.cveId, { onDelete: 'cascade' }),
    softwareName: text('software_name').notNull(),
    softwareVersion: text('software_version').notNull(),
    vendor: text('vendor').notNull(),
    product: text('product').notNull(),
    confidence: text('confidence').notNull(), // high | medium | low
    status: text('status').notNull().default('open'), // open | fixed
    firstSeen: ts('first_seen').notNull().defaultNow(),
    lastSeen: ts('last_seen').notNull().defaultNow(),
    fixedAt: ts('fixed_at'),
  },
  (t) => [
    primaryKey({ columns: [t.deviceId, t.cveId, t.softwareName] }),
    index('device_vulns_cve_idx').on(t.cveId, t.status),
    index('device_vulns_status_idx').on(t.status),
  ],
);

export const feedState = pgTable('feed_state', {
  name: text('name').primaryKey(), // nvd | kev | epss | evaluation
  lastSuccessAt: ts('last_success_at'),
  lastAttemptAt: ts('last_attempt_at'),
  cursor: jsonb('cursor').$type<Record<string, unknown>>().notNull().default({}),
  error: text('error'),
  lockedUntil: ts('locked_until'),
  requestedAt: ts('requested_at'),
  stats: jsonb('stats').$type<Record<string, unknown>>().notNull().default({}),
});

export const taskOutput = pgTable(
  'task_output',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    taskId: uuid('task_id')
      .notNull()
      .references(() => tasks.id, { onDelete: 'cascade' }),
    stream: text('stream').notNull(), // stdout | stderr | system
    data: text('data').notNull(),
    at: ts('at').notNull().defaultNow(),
  },
  (t) => [index('task_output_task_idx').on(t.taskId, t.id)],
);

export const deviceGroupMembers = pgTable(
  'device_group_members',
  {
    deviceGroupId: uuid('device_group_id')
      .notNull()
      .references(() => deviceGroups.id, { onDelete: 'cascade' }),
    deviceId: uuid('device_id').notNull().references(() => devices.id, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.deviceGroupId, t.deviceId] })],
);

// ---------------------------------------------------------------- software distribution & patches (M5)

export const packageFiles = pgTable('package_files', {
  sha256: text('sha256').primaryKey(),
  sizeBytes: bigint('size_bytes', { mode: 'number' }).notNull(),
  originalName: text('original_name').notNull(),
  uploadedBy: uuid('uploaded_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: createdAt(),
});

export const packages = pgTable('packages', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull().unique(),
  publisher: text('publisher').notNull().default(''),
  description: text('description').notNull().default(''),
  platform: text('platform').notNull(), // windows | linux | macos
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export type DetectionRule =
  | { type: 'software'; name: string; version?: string; operator?: 'eq' | 'gte' | 'lt' }
  | { type: 'file'; path: string; version?: string }
  | { type: 'registry'; key: string; value?: string; data?: string }
  | { type: 'command'; command: string };

/** Editable while draft; immutable once approved (status draft → approved → retired). */
export const packageVersions = pgTable(
  'package_versions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    packageId: uuid('package_id')
      .notNull()
      .references(() => packages.id, { onDelete: 'cascade' }),
    version: text('version').notNull(),
    type: text('type').notNull(), // msi | exe | winget | choco | deb | rpm | apt | dnf | pkg | brew | script
    fileSha256: text('file_sha256').references(() => packageFiles.sha256, { onDelete: 'restrict' }),
    fileName: text('file_name'),
    packageRef: text('package_ref'),
    installArgs: text('install_args').notNull().default(''),
    installCommand: text('install_command').notNull().default(''),
    uninstallCommand: text('uninstall_command').notNull().default(''),
    productCode: text('product_code'),
    detection: jsonb('detection').$type<DetectionRule[]>().notNull().default([]),
    successCodes: integer('success_codes').array().notNull().default([0]),
    rebootCodes: integer('reboot_codes').array().notNull().default([3010, 1641]),
    timeoutSeconds: integer('timeout_seconds').notNull().default(3600),
    changeNote: text('change_note').notNull().default(''),
    status: text('status').notNull().default('draft'),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
    approvedBy: uuid('approved_by').references(() => users.id, { onDelete: 'set null' }),
    approvedAt: ts('approved_at'),
  },
  (t) => [uniqueIndex('package_versions_pkg_version_uq').on(t.packageId, t.version)],
);

export interface DeploymentRing {
  name: string;
  targets: JobTargets;
  /** minimum hours after the ring started before the next ring may start */
  delayHours: number;
  /** success quota of this ring required for automatic promotion */
  minSuccessPercent: number;
}

export interface PatchFilter {
  classification: 'critical' | 'security' | 'all';
  /** optional: only these update ids / KBs / package names */
  include: string[];
  reboot: 'never' | 'if_required';
}

export const deployments = pgTable(
  'deployments',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    kind: text('kind').notNull(), // package | os_updates
    packageVersionId: uuid('package_version_id').references(() => packageVersions.id, { onDelete: 'restrict' }),
    action: text('action').notNull().default('install'), // install | uninstall
    patchFilter: jsonb('patch_filter').$type<PatchFilter>(),
    rings: jsonb('rings').$type<DeploymentRing[]>().notNull(),
    /** generated steps per OS, frozen at creation */
    steps: jsonb('steps').$type<Record<string, RunStep[]>>().notNull(),
    options: jsonb('options').$type<JobOptions & { timezone: string }>().notNull(),
    status: text('status').notNull().default('running'), // pending_approval | running | paused | completed | cancelled
    currentRing: integer('current_ring').notNull().default(-1),
    ringStartedAt: ts('ring_started_at'),
    pausedReason: text('paused_reason'),
    approvalId: uuid('approval_id').references(() => approvalRequests.id, { onDelete: 'set null' }),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
    finishedAt: ts('finished_at'),
  },
  (t) => [index('deployments_status_idx').on(t.status)],
);

export const devicePatches = pgTable(
  'device_patches',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    deviceId: uuid('device_id')
      .notNull()
      .references(() => devices.id, { onDelete: 'cascade' }),
    source: text('source').notNull(), // windows_update | apt | dnf | softwareupdate
    updateId: text('update_id').notNull(),
    title: text('title').notNull(),
    kb: text('kb'),
    classification: text('classification').notNull().default(''),
    severity: text('severity').notNull().default(''),
    security: boolean('security').notNull().default(false),
    version: text('version').notNull().default(''),
    rebootRequired: boolean('reboot_required').notNull().default(false),
    detectedAt: ts('detected_at').notNull().defaultNow(),
  },
  (t) => [uniqueIndex('device_patches_uq').on(t.deviceId, t.source, t.updateId), index('device_patches_update_idx').on(t.updateId)],
);

export const devicePatchState = pgTable('device_patch_state', {
  deviceId: uuid('device_id')
    .primaryKey()
    .references(() => devices.id, { onDelete: 'cascade' }),
  source: text('source'),
  lastScanAt: ts('last_scan_at'),
  lastScanStatus: text('last_scan_status'), // ok | failed
  lastError: text('last_error'),
  rebootPending: boolean('reboot_pending').notNull().default(false),
  scanRequestedAt: ts('scan_requested_at'),
});

// ---------------------------------------------------------------- reports, webhooks, licenses (M6)

export const webhooks = pgTable('webhooks', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  url: text('url').notNull(),
  events: text('events').array().notNull().default([]),
  /** HMAC secret, encrypted with the secretbox (PKI_DIR/secrets.key) */
  secretEnc: text('secret_enc').notNull(),
  enabled: boolean('enabled').notNull().default(true),
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const webhookDeliveries = pgTable(
  'webhook_deliveries',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    webhookId: uuid('webhook_id')
      .notNull()
      .references(() => webhooks.id, { onDelete: 'cascade' }),
    event: text('event').notNull(),
    payload: jsonb('payload').$type<Record<string, unknown>>().notNull(),
    status: text('status').notNull().default('pending'), // pending | succeeded | failed
    attempts: integer('attempts').notNull().default(0),
    nextAttemptAt: ts('next_attempt_at').notNull().defaultNow(),
    responseStatus: integer('response_status'),
    lastError: text('last_error'),
    createdAt: createdAt(),
    deliveredAt: ts('delivered_at'),
  },
  (t) => [index('webhook_deliveries_due_idx').on(t.status, t.nextAttemptAt), index('webhook_deliveries_hook_idx').on(t.webhookId, t.createdAt)],
);

export interface ReportFilter {
  field: string;
  op: 'eq' | 'ne' | 'contains' | 'starts' | 'gt' | 'gte' | 'lt' | 'lte' | 'in' | 'empty' | 'notempty';
  value?: string | number | boolean | (string | number)[] | null;
}

export const reports = pgTable('reports', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description').notNull().default(''),
  source: text('source').notNull(),
  columns: text('columns').array().notNull(),
  filters: jsonb('filters').$type<ReportFilter[]>().notNull().default([]),
  sort: jsonb('sort').$type<{ field: string; dir: 'asc' | 'desc' } | null>(),
  shared: boolean('shared').notNull().default(false),
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const metricsDaily = pgTable(
  'metrics_daily',
  {
    day: date('day', { mode: 'string' }).notNull(),
    key: text('key').notNull(),
    value: doublePrecision('value').notNull(),
    updatedAt: updatedAt(),
  },
  (t) => [primaryKey({ columns: [t.day, t.key] })],
);

export const licenses = pgTable('licenses', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  vendor: text('vendor').notNull().default(''),
  softwarePattern: text('software_pattern').notNull(),
  publisherPattern: text('publisher_pattern'),
  /** derived from the glob patterns on save (case-insensitive POSIX regex for SQL) */
  softwareRegex: text('software_regex').notNull(),
  publisherRegex: text('publisher_regex'),
  seats: integer('seats').notNull(),
  expiresAt: date('expires_at', { mode: 'string' }),
  cost: numeric('cost', { precision: 12, scale: 2 }),
  notes: text('notes').notNull().default(''),
  overused: boolean('overused').notNull().default(false),
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

// ---------------------------------------------------------------- OSV, security status, assets (M7)

/** OSV query cache: which advisories affect (ecosystem, package, version). */
export const osvPackages = pgTable(
  'osv_packages',
  {
    ecosystem: text('ecosystem').notNull(),
    name: text('name').notNull(),
    version: text('version').notNull(),
    vulnIds: text('vuln_ids').array().notNull().default([]),
    checkedAt: ts('checked_at').notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.ecosystem, t.name, t.version] }), index('osv_packages_checked_idx').on(t.checkedAt)],
);

export const osvVulns = pgTable('osv_vulns', {
  id: text('id').primaryKey(),
  summary: text('summary').notNull().default(''),
  cveIds: text('cve_ids').array().notNull().default([]),
  modified: ts('modified'),
  fetchedAt: ts('fetched_at').notNull().defaultNow(),
});

export const deviceSecurity = pgTable('device_security', {
  deviceId: uuid('device_id')
    .primaryKey()
    .references(() => devices.id, { onDelete: 'cascade' }),
  collectedAt: ts('collected_at').notNull(),
  encryption: text('encryption').notNull().default('unknown'), // encrypted | partial | unencrypted | unknown
  antivirus: text('antivirus').notNull().default('unknown'), // ok | outdated | disabled | missing | unknown
  firewall: text('firewall').notNull().default('unknown'), // on | partial | off | unknown
  secureBoot: boolean('secure_boot'),
  tpm: text('tpm').notNull().default('unknown'), // ready | present | missing | unknown
  compliant: boolean('compliant').notNull().default(false),
  issues: text('issues').array().notNull().default([]),
  details: jsonb('details').$type<Record<string, unknown>>().notNull().default({}),
  updatedAt: updatedAt(),
});

export const assets = pgTable(
  'assets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    type: text('type').notNull().default('other'),
    status: text('status').notNull().default('in_use'), // in_stock | in_use | repair | retired
    manufacturer: text('manufacturer').notNull().default(''),
    model: text('model').notNull().default(''),
    serialNumber: text('serial_number'),
    inventoryNumber: text('inventory_number'),
    location: text('location').notNull().default(''),
    assignedTo: text('assigned_to').notNull().default(''),
    ipAddress: text('ip_address'),
    macAddress: text('mac_address'),
    purchaseDate: date('purchase_date', { mode: 'string' }),
    warrantyUntil: date('warranty_until', { mode: 'string' }),
    cost: numeric('cost', { precision: 12, scale: 2 }),
    deviceId: uuid('device_id').references(() => devices.id, { onDelete: 'set null' }),
    notes: text('notes').notNull().default(''),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [index('assets_device_idx').on(t.deviceId), index('assets_type_idx').on(t.type, t.status)],
);
