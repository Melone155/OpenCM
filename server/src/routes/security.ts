import { and, asc, desc, eq, gte, isNull, lte, type SQL } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { assertCanGrant, assertCanManageUser } from '../auth/escalation.ts';
import type { Directory } from '../auth/ldap.ts';
import { hasPermission, isValidGrant } from '../auth/permissions.ts';
import { generateToken, hashToken } from '../auth/tokens.ts';
import type { Config } from '../config.ts';
import { apiTokens, auditLog, sessions, users } from '../db/schema.ts';
import { forbidden, HttpError, IdParams, notFound, parse, Uuid } from '../http.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';
import { getSecurity, patchSecurity, SecurityPatchSchema } from '../settings.ts';

const TokenBody = z.object({
  name: z.string().trim().min(1).max(100),
  permissions: z.array(z.string().refine(isValidGrant, 'unknown permission')).max(200).default([]),
  expiresInDays: z.number().int().min(1).max(3650).default(90),
});
const TokenList = z.object({ all: z.enum(['true', 'false']).default('false') });
const LdapTest = z.object({ username: z.string().max(200).optional() });
const AuditExport = z.object({
  format: z.enum(['csv', 'json']).default('csv'),
  action: z.string().max(100).optional(),
  actorId: Uuid.optional(),
  targetType: z.string().max(50).optional(),
  targetId: z.string().max(100).optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
});

const EXPORT_LIMIT = 100_000;

/** CSV cell: quoted, and neutralised against spreadsheet formula injection. */
export function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

const tokenCols = {
  id: apiTokens.id,
  userId: apiTokens.userId,
  username: users.username,
  name: apiTokens.name,
  permissions: apiTokens.permissions,
  expiresAt: apiTokens.expiresAt,
  lastUsedAt: apiTokens.lastUsedAt,
  revokedAt: apiTokens.revokedAt,
  createdAt: apiTokens.createdAt,
};

export function securityRoutes(app: FastifyInstance, config: Config, directory: Directory | null) {
  // ------------------------------------------------------------ API tokens

  app.get('/api-tokens', { preHandler: app.requireAuth }, async (req) => {
    const p = principalOf(req);
    const q = parse(TokenList, req.query);
    if (q.all === 'true' && !hasPermission(p.grants, 'users:read')) throw forbidden('Missing permission users:read');
    const items = await app.db
      .select(tokenCols)
      .from(apiTokens)
      .innerJoin(users, eq(users.id, apiTokens.userId))
      .where(q.all === 'true' ? undefined : eq(apiTokens.userId, p.userId))
      .orderBy(desc(apiTokens.createdAt));
    return { items };
  });

  app.post('/api-tokens', { preHandler: app.requireAuth }, async (req, reply) => {
    const p = principalOf(req);
    if (p.via === 'token') throw forbidden('API tokens cannot create further tokens');
    const body = parse(TokenBody, req.body);
    if (body.expiresInDays > config.API_TOKEN_MAX_DAYS) throw new HttpError(400, 'validation_error', `Maximum lifetime is ${config.API_TOKEN_MAX_DAYS} days`);
    // a token may only narrow the owner's rights (global or scoped)
    if (body.permissions.length) {
      const own = [...p.grants, ...p.scoped.flatMap((s) => s.grants)];
      assertCanGrant(own, body.permissions);
    }
    const token = generateToken('oct');
    const [row] = await app.db
      .insert(apiTokens)
      .values({ userId: p.userId, name: body.name, tokenHash: hashToken(token), permissions: body.permissions, expiresAt: new Date(Date.now() + body.expiresInDays * 86_400_000) })
      .returning({ id: apiTokens.id, name: apiTokens.name, permissions: apiTokens.permissions, expiresAt: apiTokens.expiresAt, createdAt: apiTokens.createdAt });
    await writeAudit(app.db, actorOf(req), { action: 'api_token.create', targetType: 'api_token', targetId: row!.id, details: { name: body.name, permissions: body.permissions, expiresAt: row!.expiresAt }, ip: req.ip });
    return reply.code(201).send({ ...row, token });
  });

  app.delete('/api-tokens/:id', { preHandler: app.requireAuth }, async (req, reply) => {
    const p = principalOf(req);
    const { id } = parse(IdParams, req.params);
    const [t] = await app.db.select().from(apiTokens).where(eq(apiTokens.id, id));
    if (!t || (t.userId !== p.userId && !hasPermission(p.grants, 'users:update'))) throw notFound('API token');
    await app.db.update(apiTokens).set({ revokedAt: new Date() }).where(and(eq(apiTokens.id, id), isNull(apiTokens.revokedAt)));
    await writeAudit(app.db, actorOf(req), { action: 'api_token.revoke', targetType: 'api_token', targetId: id, details: { name: t.name, owner: t.userId }, ip: req.ip });
    return reply.code(204).send();
  });

  // ------------------------------------------------------------ settings

  app.get('/settings/security', { preHandler: app.requirePermission('settings:read') }, async () => ({
    ...(await getSecurity(app.db, config)),
    ldap: { enabled: !!directory, url: config.LDAP_URL ?? null, requireGroup: config.LDAP_REQUIRE_GROUP },
  }));

  app.patch('/settings/security', { preHandler: app.requirePermission('settings:update') }, async (req) => {
    const body = parse(SecurityPatchSchema, req.body);
    const before = await getSecurity(app.db, config);
    const after = await patchSecurity(app.db, config, body, principalOf(req).userId);
    await writeAudit(app.db, actorOf(req), { action: 'settings.security_update', details: { before, after }, ip: req.ip });
    return { ...after, ldap: { enabled: !!directory, url: config.LDAP_URL ?? null, requireGroup: config.LDAP_REQUIRE_GROUP } };
  });

  app.post('/settings/ldap/test', { preHandler: app.requirePermission('settings:update') }, async (req) => {
    const { username } = parse(LdapTest, req.body ?? {});
    if (!directory) throw new HttpError(409, 'ldap_disabled', 'LDAP is not configured (LDAP_URL)');
    const r = await directory.test(username);
    await writeAudit(app.db, actorOf(req), { action: 'settings.ldap_test', details: { username: username ?? null, ok: r.ok }, ip: req.ip });
    return r;
  });

  app.post('/users/:id/mfa/reset', { preHandler: app.requirePermission('users:update') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const [u] = await app.db.select({ id: users.id, username: users.username }).from(users).where(eq(users.id, id));
    if (!u) throw notFound('User');
    // resetting the second factor of someone else = control over that account (REV-002)
    if (id !== principalOf(req).userId) await assertCanManageUser(app.db, principalOf(req).grants, id);
    await app.db.update(users).set({ mfaEnabled: false, mfaSecretEnc: null, mfaRecoveryHashes: [], mfaLastCounter: null }).where(eq(users.id, id));
    await app.db.delete(sessions).where(eq(sessions.userId, id));
    await writeAudit(app.db, actorOf(req), { action: 'user.mfa_reset', targetType: 'user', targetId: id, details: { username: u.username }, ip: req.ip });
    return reply.code(204).send();
  });

  // ------------------------------------------------------------ audit export

  app.get('/audit-log/export', { preHandler: app.requirePermission('audit:read') }, async (req, reply) => {
    const q = parse(AuditExport, req.query);
    const conds: SQL[] = [];
    if (q.action) conds.push(eq(auditLog.action, q.action));
    if (q.actorId) conds.push(eq(auditLog.actorId, q.actorId));
    if (q.targetType) conds.push(eq(auditLog.targetType, q.targetType));
    if (q.targetId) conds.push(eq(auditLog.targetId, q.targetId));
    if (q.from) conds.push(gte(auditLog.at, q.from));
    if (q.to) conds.push(lte(auditLog.at, q.to));
    const rows = await app.db
      .select()
      .from(auditLog)
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(asc(auditLog.id))
      .limit(EXPORT_LIMIT);
    await writeAudit(app.db, actorOf(req), { action: 'audit.export', details: { format: q.format, rows: rows.length, filters: { ...q, format: undefined } }, ip: req.ip });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    if (q.format === 'json') {
      return reply.header('content-disposition', `attachment; filename="opencm-audit-${stamp}.json"`).send({ exportedAt: new Date().toISOString(), truncated: rows.length === EXPORT_LIMIT, items: rows });
    }
    const header = ['id', 'at', 'actorType', 'actorId', 'actorName', 'action', 'targetType', 'targetId', 'ip', 'details'];
    const lines = rows.map((r) => [r.id, r.at.toISOString(), r.actorType, r.actorId, r.actorName, r.action, r.targetType, r.targetId, r.ip, r.details].map(csvCell).join(';'));
    return reply
      .header('content-type', 'text/csv; charset=utf-8')
      .header('content-disposition', `attachment; filename="opencm-audit-${stamp}.csv"`)
      .send(`\uFEFF${header.join(';')}\r\n${lines.join('\r\n')}\r\n`);
  });
}
