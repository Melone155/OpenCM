import { and, eq, inArray, or, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import type { Db } from '../db/client.ts';
import { deviceGroupMembers, deviceGroups, devices, type JobTargets } from '../db/schema.ts';

/**
 * Dynamic group filter, evaluated in SQL against the device list:
 *   { "match": "all", "rules": [ { "field": "os", "op": "eq", "value": "windows" },
 *                                 { "field": "software", "op": "installed", "value": "Firefox" },
 *                                 { "field": "custom:abteilung", "op": "eq", "value": "Buchhaltung" } ] }
 */
/** security posture (M7): state of the device, 'unknown' when the agent has not reported one */
const posture = (column: 'encryption' | 'antivirus' | 'firewall') =>
  sql`coalesce((select ds.${sql.raw(column)} from device_security ds where ds.device_id = ${devices.id}), 'unknown')`;

const TEXT_FIELDS = {
  hostname: devices.hostname,
  os: devices.os,
  osVersion: devices.osVersion,
  arch: devices.arch,
  manufacturer: devices.manufacturer,
  model: devices.model,
  serialNumber: devices.serialNumber,
  agentVersion: devices.agentVersion,
  loggedOnUser: devices.loggedOnUser,
  encryption: posture('encryption'),
  antivirus: posture('antivirus'),
  firewall: posture('firewall'),
} as const;

const TEXT_OPS = ['eq', 'ne', 'contains', 'startsWith', 'in', 'exists', 'notExists'] as const;
const CUSTOM_OPS = ['eq', 'ne', 'contains', 'gt', 'lt', 'exists', 'notExists'] as const;
const SOFTWARE_OPS = ['installed', 'notInstalled'] as const;

const FIELD_RE =
  /^(hostname|os|osVersion|arch|manufacturer|model|serialNumber|agentVersion|loggedOnUser|online|software|encryption|antivirus|firewall|securityCompliant|custom:[a-z][a-z0-9_]{0,62})$/;
const BOOL_FIELDS = ['online', 'securityCompliant'];

const RuleSchema = z
  .object({
    field: z.string().regex(FIELD_RE, 'unknown field'),
    op: z.string(),
    value: z.union([z.string().max(500), z.number(), z.boolean(), z.array(z.string().max(500)).max(200)]).optional(),
  })
  .superRefine((r, ctx) => {
    const allowed: readonly string[] =
      BOOL_FIELDS.includes(r.field) ? ['eq'] : r.field === 'software' ? SOFTWARE_OPS : r.field.startsWith('custom:') ? CUSTOM_OPS : TEXT_OPS;
    if (!allowed.includes(r.op)) return ctx.addIssue({ code: 'custom', path: ['op'], message: `op must be one of ${allowed.join(', ')}` });
    const needsValue = !['exists', 'notExists'].includes(r.op);
    if (needsValue && (r.value === undefined || r.value === '')) ctx.addIssue({ code: 'custom', path: ['value'], message: 'value required' });
    if (r.op === 'in' && !Array.isArray(r.value)) ctx.addIssue({ code: 'custom', path: ['value'], message: 'value must be an array' });
    if (r.op !== 'in' && Array.isArray(r.value)) ctx.addIssue({ code: 'custom', path: ['value'], message: 'array only allowed with op "in"' });
    if (BOOL_FIELDS.includes(r.field) && typeof r.value !== 'boolean') ctx.addIssue({ code: 'custom', path: ['value'], message: 'value must be true/false' });
    if (['gt', 'lt'].includes(r.op) && typeof r.value !== 'number') ctx.addIssue({ code: 'custom', path: ['value'], message: 'value must be a number' });
  });

export const FilterSchema = z.object({
  match: z.enum(['all', 'any']).default('all'),
  rules: z.array(RuleSchema).min(1).max(50),
});

export type GroupFilter = z.infer<typeof FilterSchema>;
type Rule = GroupFilter['rules'][number];

const like = (s: string) => `%${s.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
const prefix = (s: string) => `${s.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

function ruleSql(r: Rule, onlineSeconds: number): SQL {
  const v = r.value;
  if (r.field === 'online') {
    const online = sql`coalesce(${devices.lastSeenAt} > now() - make_interval(secs => ${onlineSeconds}), false)`;
    return v ? online : sql`not ${online}`;
  }
  if (r.field === 'securityCompliant') {
    // devices without a reported status count as not compliant
    const ok = sql`coalesce((select ds.compliant from device_security ds where ds.device_id = ${devices.id}), false)`;
    return v ? ok : sql`not ${ok}`;
  }
  if (r.field === 'software') {
    const exists = sql`exists (select 1 from device_software ds where ds.device_id = ${devices.id} and ds.name ilike ${like(String(v))})`;
    return r.op === 'installed' ? exists : sql`not ${exists}`;
  }
  if (r.field.startsWith('custom:')) {
    const name = r.field.slice(7);
    const base = sql`from device_custom_values cv join custom_fields cf on cf.id = cv.field_id where cv.device_id = ${devices.id} and cf.name = ${name}`;
    const num = sql`case when cv.value ~ '^-?[0-9]+(\\.[0-9]+)?$' then cv.value::numeric end`;
    switch (r.op) {
      case 'exists':
        return sql`exists (select 1 ${base})`;
      case 'notExists':
        return sql`not exists (select 1 ${base})`;
      case 'eq':
        return sql`exists (select 1 ${base} and lower(cv.value) = lower(${String(v)}))`;
      case 'ne':
        return sql`not exists (select 1 ${base} and lower(cv.value) = lower(${String(v)}))`;
      case 'contains':
        return sql`exists (select 1 ${base} and cv.value ilike ${like(String(v))})`;
      case 'gt':
        return sql`exists (select 1 ${base} and ${num} > ${Number(v)})`;
      case 'lt':
        return sql`exists (select 1 ${base} and ${num} < ${Number(v)})`;
    }
  }
  const col = TEXT_FIELDS[r.field as keyof typeof TEXT_FIELDS];
  switch (r.op) {
    case 'eq':
      return sql`lower(${col}) = lower(${String(v)})`;
    case 'ne':
      return sql`(${col} is null or lower(${col}) <> lower(${String(v)}))`;
    case 'contains':
      return sql`${col} ilike ${like(String(v))}`;
    case 'startsWith':
      return sql`${col} ilike ${prefix(String(v))}`;
    case 'in': {
      const vals = (v as string[]).map((x) => x.toLowerCase());
      return vals.length ? sql`lower(${col}) in (${sql.join(vals.map((x) => sql`${x}`), sql`, `)})` : sql`false`;
    }
    case 'exists':
      return sql`(${col} is not null and ${col} <> '')`;
    case 'notExists':
      return sql`(${col} is null or ${col} = '')`;
  }
  throw new Error(`unsupported rule ${r.field} ${r.op}`);
}

export function filterSql(filter: GroupFilter, onlineSeconds: number): SQL {
  const parts = filter.rules.map((r) => ruleSql(r, onlineSeconds));
  return (filter.match === 'any' ? or(...parts) : and(...parts))!;
}

/** Active device ids that are members of the given group (static or dynamic). */
export async function groupMemberIds(db: Db, groupId: string, onlineSeconds: number, onlyDeviceId?: string): Promise<string[]> {
  const [g] = await db.select().from(deviceGroups).where(eq(deviceGroups.id, groupId));
  if (!g) return [];
  const scope = onlyDeviceId ? eq(devices.id, onlyDeviceId) : undefined;
  if (g.kind === 'dynamic') {
    const filter = FilterSchema.safeParse(g.filter);
    if (!filter.success) return [];
    const rows = await db
      .select({ id: devices.id })
      .from(devices)
      .where(and(eq(devices.status, 'active'), filterSql(filter.data, onlineSeconds), scope));
    return rows.map((r) => r.id);
  }
  const rows = await db
    .select({ id: devices.id })
    .from(deviceGroupMembers)
    .innerJoin(devices, eq(devices.id, deviceGroupMembers.deviceId))
    .where(and(eq(deviceGroupMembers.deviceGroupId, groupId), eq(devices.status, 'active'), scope));
  return rows.map((r) => r.id);
}

/** Resolves job targets to the set of active device ids. */
export async function resolveTargets(db: Db, targets: JobTargets, onlineSeconds: number, onlyDeviceId?: string): Promise<string[]> {
  const ids = new Set<string>();
  const scope = onlyDeviceId ? eq(devices.id, onlyDeviceId) : undefined;
  if (targets.allDevices) {
    for (const r of await db.select({ id: devices.id }).from(devices).where(and(eq(devices.status, 'active'), scope))) ids.add(r.id);
    return [...ids];
  }
  if (targets.deviceIds.length) {
    const rows = await db
      .select({ id: devices.id })
      .from(devices)
      .where(and(inArray(devices.id, targets.deviceIds), eq(devices.status, 'active'), scope));
    for (const r of rows) ids.add(r.id);
  }
  for (const gid of targets.groupIds) for (const id of await groupMemberIds(db, gid, onlineSeconds, onlyDeviceId)) ids.add(id);
  return [...ids];
}
