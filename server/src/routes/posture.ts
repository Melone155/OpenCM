import { and, asc, count, eq, ilike, isNull, or, sql, type SQL } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { assertInScope, scopeCondition } from '../auth/scope.ts';
import { onlineThresholdSeconds, type Config } from '../config.ts';
import { devices, deviceSecurity } from '../db/schema.ts';
import { IdParams, notFound, Pagination, parse } from '../http.ts';
import { ANTIVIRUS_STATES, ENCRYPTION_STATES, FIREWALL_STATES, ISSUES, securityMetrics, type Issue } from '../security/posture.ts';
import { csvCell } from './security.ts';

const ISSUE_CODES = Object.keys(ISSUES) as [Issue, ...Issue[]];

const ListQuery = Pagination.extend({
  search: z.string().max(200).optional(),
  os: z.enum(['windows', 'linux', 'macos']).optional(),
  compliant: z.enum(['true', 'false']).optional(),
  /** false = devices whose agent has not reported a security status yet */
  reported: z.enum(['true', 'false']).optional(),
  encryption: z.enum(ENCRYPTION_STATES).optional(),
  antivirus: z.enum(ANTIVIRUS_STATES).optional(),
  firewall: z.enum(FIREWALL_STATES).optional(),
  issue: z.enum(ISSUE_CODES).optional(),
  format: z.enum(['json', 'csv']).default('json'),
});

const issueList = (codes: string[]) => codes.map((code) => ({ code, label: ISSUES[code as Issue] ?? code }));

export function postureRoutes(app: FastifyInstance, config: Config) {
  const online = sql<boolean>`coalesce(${devices.lastSeenAt} > now() - make_interval(secs => ${onlineThresholdSeconds(config)}), false)`;
  const ds = deviceSecurity;

  app.get('/security-status', { preHandler: app.requireScopedPermission('inventory:read') }, async (req, reply) => {
    const q = parse(ListQuery, req.query);
    const scope = await app.deviceScope(req, 'inventory:read');
    const conds: (SQL | undefined)[] = [eq(devices.status, 'active'), scopeCondition(scope, devices.id)];
    if (q.search) conds.push(or(ilike(devices.hostname, `%${q.search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`), ilike(devices.loggedOnUser, `%${q.search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`)));
    if (q.os) conds.push(eq(devices.os, q.os));
    if (q.compliant) conds.push(q.compliant === 'true' ? eq(ds.compliant, true) : and(sql`${ds.deviceId} is not null`, eq(ds.compliant, false)));
    if (q.reported === 'false') conds.push(isNull(ds.deviceId));
    if (q.reported === 'true') conds.push(sql`${ds.deviceId} is not null`);
    if (q.encryption) conds.push(eq(ds.encryption, q.encryption));
    if (q.antivirus) conds.push(eq(ds.antivirus, q.antivirus));
    if (q.firewall) conds.push(eq(ds.firewall, q.firewall));
    if (q.issue) conds.push(sql`${q.issue} = any(${ds.issues})`);
    const where = and(...conds);
    const base = app.db
      .select({
        deviceId: devices.id,
        hostname: devices.hostname,
        os: devices.os,
        osVersion: devices.osVersion,
        online,
        reported: sql<boolean>`(${ds.deviceId} is not null)`,
        compliant: sql<boolean>`coalesce(${ds.compliant}, false)`,
        encryption: sql<string>`coalesce(${ds.encryption}, 'unknown')`,
        antivirus: sql<string>`coalesce(${ds.antivirus}, 'unknown')`,
        firewall: sql<string>`coalesce(${ds.firewall}, 'unknown')`,
        secureBoot: ds.secureBoot,
        tpm: sql<string>`coalesce(${ds.tpm}, 'unknown')`,
        issues: sql<string[]>`coalesce(${ds.issues}, '{}')`,
        collectedAt: ds.collectedAt,
      })
      .from(devices)
      .leftJoin(ds, eq(ds.deviceId, devices.id))
      .where(where)
      // problems first: not compliant (reported) → not reported → compliant
      .orderBy(sql`case when ${ds.deviceId} is null then 1 when ${ds.compliant} then 2 else 0 end`, sql`cardinality(coalesce(${ds.issues}, '{}')) desc`, asc(devices.hostname));
    if (q.format === 'csv') {
      const rows = await base.limit(100_000);
      const header = ['hostname', 'os', 'compliant', 'encryption', 'antivirus', 'firewall', 'secureBoot', 'tpm', 'issues', 'collectedAt'];
      const lines = rows.map((r) =>
        [r.hostname, r.os, r.reported ? r.compliant : '', r.encryption, r.antivirus, r.firewall, r.secureBoot, r.tpm, r.issues.map((i) => ISSUES[i as Issue] ?? i).join(', '), r.collectedAt?.toISOString()].map(csvCell).join(';'),
      );
      return reply
        .header('content-type', 'text/csv; charset=utf-8')
        .header('content-disposition', `attachment; filename="opencm-sicherheitsstatus-${new Date().toISOString().slice(0, 10)}.csv"`)
        .send(`\uFEFF${header.join(';')}\r\n${lines.join('\r\n')}${lines.length ? '\r\n' : ''}`);
    }
    const items = await base.limit(q.limit).offset(q.offset);
    const [total] = await app.db.select({ n: count() }).from(devices).leftJoin(ds, eq(ds.deviceId, devices.id)).where(where);
    return {
      summary: await securityMetrics(app.db, scope),
      issueLabels: ISSUES,
      items: items.map((i) => ({ ...i, issues: issueList(i.issues) })),
      total: Number(total?.n ?? 0),
    };
  });

  app.get('/devices/:id/security', { preHandler: app.requireScopedPermission('inventory:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'inventory:read'), id);
    const [d] = await app.db.select({ id: devices.id }).from(devices).where(eq(devices.id, id));
    if (!d) throw notFound('Device');
    const [s] = await app.db.select().from(ds).where(eq(ds.deviceId, id));
    if (!s) throw notFound('Security status');
    const { deviceId: _d, issues, ...rest } = s;
    return { ...rest, deviceId: id, issues: issueList(issues) };
  });
}
