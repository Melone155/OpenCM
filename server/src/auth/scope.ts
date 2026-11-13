import { inArray, sql, type AnyColumn, type SQL } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { groupMemberIds } from '../groups/filter.ts';
import { notFound } from '../http.ts';
import type { Principal } from '../plugins/auth.ts';
import { hasPermission, type Permission } from './permissions.ts';

/** Devices on which a principal holds a permission. */
export interface DeviceScope {
  all: boolean;
  ids: Set<string>;
}

export function hasAnyGrant(p: Principal, perm: Permission): boolean {
  return hasPermission(p.grants, perm) || p.scoped.some((s) => hasPermission(s.grants, perm));
}

/** Resolves (and caches per request) the devices the principal may act on with `perm`. */
export async function resolveDeviceScope(db: Db, p: Principal, perm: Permission, onlineSeconds: number): Promise<DeviceScope> {
  if (hasPermission(p.grants, perm)) return { all: true, ids: new Set() };
  const cached = p.scopeCache.get(perm);
  if (cached) return cached;
  const ids = new Set<string>();
  const groups = new Set(p.scoped.filter((s) => hasPermission(s.grants, perm)).flatMap((s) => s.deviceGroupIds));
  for (const g of groups) for (const id of await groupMemberIds(db, g, onlineSeconds)) ids.add(id);
  const scope = { all: false, ids };
  p.scopeCache.set(perm, scope);
  return scope;
}

/** SQL condition restricting `column` (a device id) to the scope; undefined = no restriction. */
export function scopeCondition(scope: DeviceScope, column: AnyColumn | SQL): SQL | undefined {
  if (scope.all) return undefined;
  if (!scope.ids.size) return sql`false`;
  return inArray(column as AnyColumn, [...scope.ids]);
}

export const inScope = (scope: DeviceScope, deviceId: string) => scope.all || scope.ids.has(deviceId);

/** 404 for devices outside the scope (existence is not revealed). */
export function assertInScope(scope: DeviceScope, deviceId: string): void {
  if (!inScope(scope, deviceId)) throw notFound('Device');
}
