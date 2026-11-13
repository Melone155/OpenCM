/**
 * Report engine: fixed data sources with whitelisted columns. Clients only send column
 * keys, operator names and values – values become bound parameters, never SQL.
 */
import { and, asc, eq, inArray, sql, type AnyColumn, type SQL } from 'drizzle-orm';
import type { Permission } from './auth/permissions.ts';
import type { DeviceScope } from './auth/scope.ts';
import { onlineThresholdSeconds, type Config } from './config.ts';
import type { Db } from './db/client.ts';
import { assets, devicePatches, deviceSecurity, deviceSoftware, devices, deviceVulnerabilities, jobRuns, licenses, tasks, vulnerabilities, type ReportFilter } from './db/schema.ts';
import { HttpError } from './http.ts';
import { usedExpr } from './licenses.ts';

export type ColumnType = 'string' | 'number' | 'date' | 'boolean';
interface ColumnDef {
  label: string;
  type: ColumnType;
  expr: SQL | AnyColumn;
}
export interface SourceDef {
  label: string;
  permission: Permission;
  /** device id column for scope filtering (null = not device related) */
  deviceId: AnyColumn | null;
  columns: Record<string, ColumnDef>;
  defaultColumns: string[];
  base: (db: Db, fields: Record<string, SQL | AnyColumn>) => DynamicSelect;
  where?: SQL;
}

// The dynamic query builder type of drizzle is very generic; the engine only needs these calls.
interface DynamicSelect {
  where(c: SQL | undefined): DynamicSelect;
  orderBy(...o: SQL[]): DynamicSelect;
  limit(n: number): Promise<Record<string, unknown>[]>;
}
const dyn = (q: unknown) => q as DynamicSelect;
type SelFields = NonNullable<Parameters<Db['select']>[0]>;

const str = (label: string, expr: SQL | AnyColumn): ColumnDef => ({ label, type: 'string', expr });
const num = (label: string, expr: SQL | AnyColumn): ColumnDef => ({ label, type: 'number', expr });
const dat = (label: string, expr: SQL | AnyColumn): ColumnDef => ({ label, type: 'date', expr });
const bool = (label: string, expr: SQL | AnyColumn): ColumnDef => ({ label, type: 'boolean', expr });

export function reportSources(config: Config): Record<string, SourceDef> {
  const online = sql<boolean>`(${devices.lastSeenAt} is not null and ${devices.lastSeenAt} > now() - make_interval(secs => ${onlineThresholdSeconds(config)}))`;
  const deviceCols = {
    hostname: str('Gerät', devices.hostname),
    os: str('Betriebssystem', devices.os),
  };
  return {
    devices: {
      label: 'Geräte',
      permission: 'devices:read',
      deviceId: devices.id,
      columns: {
        ...deviceCols,
        osVersion: str('OS-Version', devices.osVersion),
        arch: str('Architektur', devices.arch),
        manufacturer: str('Hersteller', devices.manufacturer),
        model: str('Modell', devices.model),
        serialNumber: str('Seriennummer', devices.serialNumber),
        agentVersion: str('Agent-Version', devices.agentVersion),
        loggedOnUser: str('Angemeldeter Benutzer', devices.loggedOnUser),
        lastIp: str('Letzte IP', sql`host(${devices.lastIp})`),
        online: bool('Online', online),
        lastSeenAt: dat('Zuletzt gesehen', devices.lastSeenAt),
        lastInventoryAt: dat('Letztes Inventar', devices.lastInventoryAt),
        enrolledAt: dat('Registriert', devices.enrolledAt),
        certExpiresAt: dat('Zertifikat gültig bis', devices.certExpiresAt),
      },
      defaultColumns: ['hostname', 'os', 'osVersion', 'manufacturer', 'model', 'online', 'lastSeenAt'],
      base: (db, f) => dyn(db.select(f as SelFields).from(devices).$dynamic()),
      where: eq(devices.status, 'active'),
    },
    software: {
      label: 'Installierte Software',
      permission: 'inventory:read',
      deviceId: devices.id,
      columns: {
        ...deviceCols,
        name: str('Software', deviceSoftware.name),
        version: str('Version', deviceSoftware.version),
        publisher: str('Herausgeber', deviceSoftware.publisher),
        installDate: str('Installationsdatum', deviceSoftware.installDate),
        source: str('Quelle', deviceSoftware.source),
        arch: str('Architektur', deviceSoftware.arch),
      },
      defaultColumns: ['hostname', 'name', 'version', 'publisher'],
      base: (db, f) => dyn(db.select(f as SelFields).from(deviceSoftware).innerJoin(devices, eq(devices.id, deviceSoftware.deviceId)).$dynamic()),
      where: eq(devices.status, 'active'),
    },
    vulnerabilities: {
      label: 'Schwachstellen-Befunde',
      permission: 'vulnerabilities:read',
      deviceId: devices.id,
      columns: {
        ...deviceCols,
        cveId: str('CVE', deviceVulnerabilities.cveId),
        severity: str('Schweregrad', vulnerabilities.cvssSeverity),
        cvss: num('CVSS', vulnerabilities.cvssScore),
        kev: bool('Aktiv ausgenutzt (KEV)', vulnerabilities.kev),
        epss: num('EPSS', vulnerabilities.epss),
        software: str('Software', deviceVulnerabilities.softwareName),
        softwareVersion: str('Software-Version', deviceVulnerabilities.softwareVersion),
        confidence: str('Konfidenz', deviceVulnerabilities.confidence),
        status: str('Status', deviceVulnerabilities.status),
        accepted: bool('Risiko akzeptiert', sql<boolean>`(${vulnerabilities.acceptedAt} is not null)`),
        firstSeen: dat('Erkannt', deviceVulnerabilities.firstSeen),
        fixedAt: dat('Behoben', deviceVulnerabilities.fixedAt),
      },
      defaultColumns: ['hostname', 'cveId', 'severity', 'cvss', 'kev', 'software', 'softwareVersion', 'status'],
      base: (db, f) =>
        dyn(
          db
            .select(f as SelFields)
            .from(deviceVulnerabilities)
            .innerJoin(devices, eq(devices.id, deviceVulnerabilities.deviceId))
            .innerJoin(vulnerabilities, eq(vulnerabilities.cveId, deviceVulnerabilities.cveId))
            .$dynamic(),
        ),
      where: eq(devices.status, 'active'),
    },
    patches: {
      label: 'Ausstehende Updates',
      permission: 'patches:read',
      deviceId: devices.id,
      columns: {
        ...deviceCols,
        title: str('Update', devicePatches.title),
        kb: str('KB', devicePatches.kb),
        source: str('Quelle', devicePatches.source),
        classification: str('Klassifikation', devicePatches.classification),
        severity: str('Schweregrad', devicePatches.severity),
        security: bool('Sicherheitsupdate', devicePatches.security),
        rebootRequired: bool('Neustart nötig', devicePatches.rebootRequired),
        detectedAt: dat('Erkannt', devicePatches.detectedAt),
      },
      defaultColumns: ['hostname', 'title', 'kb', 'classification', 'security', 'detectedAt'],
      base: (db, f) => dyn(db.select(f as SelFields).from(devicePatches).innerJoin(devices, eq(devices.id, devicePatches.deviceId)).$dynamic()),
      where: eq(devices.status, 'active'),
    },
    tasks: {
      label: 'Task-Ergebnisse',
      permission: 'jobs:read',
      deviceId: devices.id,
      columns: {
        ...deviceCols,
        run: str('Ausführung', jobRuns.name),
        trigger: str('Auslöser', jobRuns.trigger),
        status: str('Status', tasks.status),
        exitCode: num('Exitcode', tasks.exitCode),
        attempt: num('Versuch', tasks.attempt),
        error: str('Fehler', tasks.error),
        integrityViolation: bool('Hash-Prüfung fehlgeschlagen', sql<boolean>`coalesce(${tasks.error} like 'integrity:%', false)`),
        createdAt: dat('Angelegt', tasks.createdAt),
        finishedAt: dat('Beendet', tasks.finishedAt),
      },
      defaultColumns: ['hostname', 'run', 'status', 'exitCode', 'finishedAt'],
      base: (db, f) => dyn(db.select(f as SelFields).from(tasks).innerJoin(jobRuns, eq(jobRuns.id, tasks.runId)).innerJoin(devices, eq(devices.id, tasks.deviceId)).$dynamic()),
    },
    licenses: {
      label: 'Softwarelizenzen',
      permission: 'licenses:read',
      deviceId: null,
      columns: {
        name: str('Lizenz', licenses.name),
        vendor: str('Hersteller', licenses.vendor),
        softwarePattern: str('Software-Muster', licenses.softwarePattern),
        seats: num('Lizenzen', licenses.seats),
        used: num('Genutzt', usedExpr),
        available: num('Verfügbar', sql<number>`(${licenses.seats} - ${usedExpr})`),
        overused: bool('Überlizenziert', sql<boolean>`(${usedExpr} > ${licenses.seats})`),
        expiresAt: dat('Läuft ab', licenses.expiresAt),
        cost: num('Kosten', licenses.cost),
      },
      defaultColumns: ['name', 'vendor', 'seats', 'used', 'available', 'overused', 'expiresAt'],
      base: (db, f) => dyn(db.select(f as SelFields).from(licenses).$dynamic()),
    },
    security: {
      label: 'Sicherheitsstatus',
      permission: 'inventory:read',
      deviceId: devices.id,
      columns: {
        ...deviceCols,
        osVersion: str('OS-Version', devices.osVersion),
        compliant: bool('Konform', deviceSecurity.compliant),
        encryption: str('Verschlüsselung', deviceSecurity.encryption),
        antivirus: str('Virenschutz', deviceSecurity.antivirus),
        firewall: str('Firewall', deviceSecurity.firewall),
        secureBoot: bool('Secure Boot', deviceSecurity.secureBoot),
        tpm: str('TPM', deviceSecurity.tpm),
        issues: str('Probleme', sql<string>`array_to_string(${deviceSecurity.issues}, ', ')`),
        issueCount: num('Anzahl Probleme', sql<number>`cardinality(${deviceSecurity.issues})`),
        encryptionProduct: str('Verschlüsselungsprodukt', sql<string>`${deviceSecurity.details}->'encryption'->>'product'`),
        antivirusProducts: str('Virenschutzprodukte', sql<string>`(select string_agg(a->>'name', ', ') from jsonb_array_elements(${deviceSecurity.details}->'antivirus') a)`),
        collectedAt: dat('Erfasst', deviceSecurity.collectedAt),
      },
      defaultColumns: ['hostname', 'os', 'compliant', 'encryption', 'antivirus', 'firewall', 'issues'],
      base: (db, f) => dyn(db.select(f as SelFields).from(deviceSecurity).innerJoin(devices, eq(devices.id, deviceSecurity.deviceId)).$dynamic()),
      where: eq(devices.status, 'active'),
    },
    assets: {
      label: 'Assets (ohne Agent)',
      permission: 'assets:read',
      deviceId: null,
      columns: {
        name: str('Name', assets.name),
        type: str('Typ', assets.type),
        status: str('Status', assets.status),
        manufacturer: str('Hersteller', assets.manufacturer),
        model: str('Modell', assets.model),
        serialNumber: str('Seriennummer', assets.serialNumber),
        inventoryNumber: str('Inventarnummer', assets.inventoryNumber),
        location: str('Standort', assets.location),
        assignedTo: str('Zugeordnet', assets.assignedTo),
        ipAddress: str('IP-Adresse', assets.ipAddress),
        macAddress: str('MAC-Adresse', assets.macAddress),
        purchaseDate: dat('Kaufdatum', assets.purchaseDate),
        warrantyUntil: dat('Garantie bis', assets.warrantyUntil),
        warrantyDaysLeft: num('Garantie (Tage übrig)', sql<number>`(${assets.warrantyUntil} - current_date)`),
        cost: num('Kosten', assets.cost),
        device: str('Verwaltetes Gerät', sql<string>`(select d.hostname from devices d where d.id = ${assets.deviceId})`),
        updatedAt: dat('Geändert', assets.updatedAt),
      },
      defaultColumns: ['name', 'type', 'status', 'inventoryNumber', 'serialNumber', 'location', 'assignedTo', 'warrantyUntil'],
      base: (db, f) => dyn(db.select(f as SelFields).from(assets).$dynamic()),
    },
  };
}

const escapeLike = (s: string) => s.replace(/[\\%_]/g, (m) => `\\${m}`);

function coerce(type: ColumnType, v: unknown, field: string): string | number | boolean | Date {
  if (type === 'number') {
    const n = typeof v === 'number' ? v : Number(v);
    if (!Number.isFinite(n)) throw new HttpError(400, 'validation_error', `Filter ${field}: number expected`);
    return n;
  }
  if (type === 'date') {
    const d = new Date(String(v));
    if (Number.isNaN(d.getTime())) throw new HttpError(400, 'validation_error', `Filter ${field}: date expected (ISO 8601)`);
    return d;
  }
  if (type === 'boolean') {
    if (v === true || v === 'true' || v === 1 || v === '1') return true;
    if (v === false || v === 'false' || v === 0 || v === '0') return false;
    throw new HttpError(400, 'validation_error', `Filter ${field}: true/false expected`);
  }
  if (v === null || v === undefined || typeof v === 'object') throw new HttpError(400, 'validation_error', `Filter ${field}: text expected`);
  return String(v);
}

/** Compiles one filter of a whitelisted column into a parameterised condition. */
export function filterCondition(source: SourceDef, f: ReportFilter): SQL {
  const col = source.columns[f.field];
  if (!col) throw new HttpError(400, 'validation_error', `Unknown column "${f.field}"`);
  const e = col.expr;
  const isText = col.type === 'string';
  switch (f.op) {
    case 'empty':
      return isText ? sql`(${e} is null or ${e} = '')` : sql`(${e} is null)`;
    case 'notempty':
      return isText ? sql`(${e} is not null and ${e} <> '')` : sql`(${e} is not null)`;
    case 'in': {
      if (!Array.isArray(f.value) || !f.value.length || f.value.length > 500) throw new HttpError(400, 'validation_error', `Filter ${f.field}: list of 1–500 values expected`);
      const vals = f.value.map((v) => coerce(col.type, v, f.field));
      return isText ? sql`lower(${e}) in (${sql.join(vals.map((v) => sql`${String(v).toLowerCase()}`), sql`, `)})` : sql`${e} in (${sql.join(vals.map((v) => sql`${v}`), sql`, `)})`;
    }
    case 'contains':
    case 'starts': {
      if (!isText) throw new HttpError(400, 'validation_error', `Filter ${f.field}: "${f.op}" only works on text`);
      const v = escapeLike(String(coerce('string', f.value, f.field)));
      return sql`${e} ilike ${f.op === 'contains' ? `%${v}%` : `${v}%`}`;
    }
    case 'eq':
    case 'ne': {
      const v = coerce(col.type, f.value, f.field);
      if (isText) return f.op === 'eq' ? sql`lower(${e}) = ${String(v).toLowerCase()}` : sql`(${e} is null or lower(${e}) <> ${String(v).toLowerCase()})`;
      return f.op === 'eq' ? sql`${e} = ${v}` : sql`(${e} is null or ${e} <> ${v})`;
    }
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      if (col.type === 'boolean') throw new HttpError(400, 'validation_error', `Filter ${f.field}: comparison not possible on yes/no`);
      const v = coerce(col.type, f.value, f.field);
      const op = { gt: sql`>`, gte: sql`>=`, lt: sql`<`, lte: sql`<=` }[f.op];
      return sql`${e} ${op} ${v}`;
    }
  }
  throw new HttpError(400, 'validation_error', `Unknown operator "${(f as { op: string }).op}"`);
}

export interface ReportQuery {
  source: string;
  columns: string[];
  filters: ReportFilter[];
  sort?: { field: string; dir: 'asc' | 'desc' } | null;
  limit: number;
}

export async function runReport(db: Db, config: Config, q: ReportQuery, scope: DeviceScope | null) {
  const source = reportSources(config)[q.source];
  if (!source) throw new HttpError(400, 'validation_error', `Unknown source "${q.source}"`);
  const columns = q.columns.length ? q.columns : source.defaultColumns;
  for (const c of columns) if (!source.columns[c]) throw new HttpError(400, 'validation_error', `Unknown column "${c}"`);
  const fields = Object.fromEntries(columns.map((c) => [c, source.columns[c]!.expr]));
  const conds: (SQL | undefined)[] = [source.where, ...q.filters.map((f) => filterCondition(source, f))];
  if (source.deviceId && scope && !scope.all) conds.push(scope.ids.size ? inArray(source.deviceId, [...scope.ids]) : sql`false`);
  let order: SQL[] = [];
  if (q.sort) {
    const col = source.columns[q.sort.field];
    if (!col) throw new HttpError(400, 'validation_error', `Unknown sort column "${q.sort.field}"`);
    order = [q.sort.dir === 'desc' ? sql`${col.expr} desc nulls last` : sql`${col.expr} asc nulls last`];
  } else {
    const first = source.columns[columns[0]!]!;
    order = [asc(first.expr as AnyColumn)];
  }
  const rows = await source.base(db, fields).where(and(...conds)).orderBy(...order).limit(q.limit + 1);
  const truncated = rows.length > q.limit;
  return {
    source: q.source,
    columns: columns.map((c) => ({ key: c, label: source.columns[c]!.label, type: source.columns[c]!.type })),
    rows: (truncated ? rows.slice(0, q.limit) : rows).map((r) => {
      const out: Record<string, unknown> = {};
      for (const c of columns) {
        const v = r[c];
        out[c] = v instanceof Date ? v.toISOString() : typeof v === 'string' && source.columns[c]!.type === 'number' ? Number(v) : v;
      }
      return out;
    }),
    truncated,
  };
}

/** Catalogue for the UI / API (only sources the caller may read). */
export function describeSources(config: Config, mayRead: (p: Permission) => boolean) {
  return Object.entries(reportSources(config))
    .filter(([, s]) => mayRead(s.permission))
    .map(([key, s]) => ({
      key,
      label: s.label,
      permission: s.permission,
      defaultColumns: s.defaultColumns,
      columns: Object.entries(s.columns).map(([k, c]) => ({ key: k, label: c.label, type: c.type })),
    }));
}
