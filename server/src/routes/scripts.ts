import { createHash, randomUUID } from 'node:crypto';
import { scriptVersionSeal } from '../integrity.ts';
import { and, asc, desc, eq, ilike, inArray, max, or, sql } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import type { Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import { devices, jobSteps, scripts, scriptVersions } from '../db/schema.ts';
import { conflict, forbidden, HttpError, IdParams, isUniqueViolation, notFound, parse, Uuid } from '../http.ts';
import { hasPermission } from '../auth/permissions.ts';
import { createRun, DEFAULT_OPTIONS } from '../jobs/engine.ts';
import { INTERPRETER_NAMES, INTERPRETERS, supportsOs } from '../jobs/interpreters.ts';
import { ParameterDefsSchema, resolveParams } from '../jobs/params.ts';
import { assertInScope } from '../auth/scope.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';

const MAX_SCRIPT_BYTES = 512 * 1024;
const Content = z
  .string()
  .min(1)
  .refine((s) => Buffer.byteLength(s, 'utf8') <= MAX_SCRIPT_BYTES, `script must not exceed ${MAX_SCRIPT_BYTES / 1024} KiB`);

const CreateScript = z.object({
  name: z.string().trim().min(1).max(150),
  description: z.string().max(2000).default(''),
  interpreter: z.enum(INTERPRETER_NAMES as [string, ...string[]]),
  content: Content,
  parameters: ParameterDefsSchema,
  changeNote: z.string().max(500).default(''),
});
const UpdateScript = z.object({ name: z.string().trim().min(1).max(150).optional(), description: z.string().max(2000).optional() });
const NewVersion = z.object({ content: Content, parameters: ParameterDefsSchema, changeNote: z.string().max(500).default('') });
const VersionParams = z.object({ id: Uuid, version: z.coerce.number().int().min(1) });
const ListQuery = z.object({ search: z.string().max(200).optional() });
const TestRun = z.object({
  deviceId: Uuid,
  params: z.record(z.string(), z.unknown()).default({}),
  timeoutSeconds: z.number().int().min(10).max(86_400).default(600),
});

/** A new version is released right away if its author may release scripts; otherwise it stays a draft. */
function releaseOnCreate(req: FastifyRequest) {
  const p = principalOf(req);
  return hasPermission(p.grants, 'scripts:approve') ? { status: 'approved', approvedBy: p.userId, approvedAt: new Date() } : {};
}

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

const versionMeta = {
  id: scriptVersions.id,
  version: scriptVersions.version,
  sha256: scriptVersions.sha256,
  status: scriptVersions.status,
  changeNote: scriptVersions.changeNote,
  parameters: scriptVersions.parameters,
  createdBy: scriptVersions.createdBy,
  createdAt: scriptVersions.createdAt,
  approvedBy: scriptVersions.approvedBy,
  approvedAt: scriptVersions.approvedAt,
};

export function scriptRoutes(app: FastifyInstance, config: Config) {
  async function loadScript(db: Db, id: string) {
    const [s] = await db.select().from(scripts).where(eq(scripts.id, id));
    if (!s) throw notFound('Script');
    const versions = await db.select(versionMeta).from(scriptVersions).where(eq(scriptVersions.scriptId, id)).orderBy(desc(scriptVersions.version));
    const approved = versions.find((v) => v.status === 'approved');
    return { ...s, latestVersion: versions[0]?.version ?? 0, approvedVersion: approved?.version ?? null, versions };
  }

  async function loadVersion(db: Db, scriptId: string, version: number) {
    const [v] = await db
      .select({ ...versionMeta, content: scriptVersions.content, scriptId: scriptVersions.scriptId })
      .from(scriptVersions)
      .where(and(eq(scriptVersions.scriptId, scriptId), eq(scriptVersions.version, version)));
    if (!v) throw notFound('Script version');
    return v;
  }

  app.get('/interpreters', { preHandler: app.requireAuth }, async () => ({
    items: INTERPRETER_NAMES.map((name) => ({ name, label: INTERPRETERS[name].label, os: INTERPRETERS[name].os, editorLanguage: INTERPRETERS[name].monaco })),
  }));

  app.get('/scripts', { preHandler: app.requirePermission('scripts:read') }, async (req) => {
    const q = parse(ListQuery, req.query);
    const where = q.search ? or(ilike(scripts.name, `%${q.search}%`), ilike(scripts.description, `%${q.search}%`)) : undefined;
    const rows = await app.db.select().from(scripts).where(where).orderBy(asc(scripts.name));
    if (!rows.length) return { items: [] };
    const stats = await app.db
      .select({
        scriptId: scriptVersions.scriptId,
        latest: max(scriptVersions.version),
        approved: sql<number | null>`max(${scriptVersions.version}) filter (where ${scriptVersions.status} = 'approved')`,
      })
      .from(scriptVersions)
      .where(inArray(scriptVersions.scriptId, rows.map((r) => r.id)))
      .groupBy(scriptVersions.scriptId);
    return {
      items: rows.map((r) => {
        const s = stats.find((x) => x.scriptId === r.id);
        return { ...r, latestVersion: s?.latest ?? 0, approvedVersion: s?.approved ?? null };
      }),
    };
  });

  app.post('/scripts', { preHandler: app.requirePermission('scripts:create') }, async (req, reply) => {
    const body = parse(CreateScript, req.body);
    const userId = principalOf(req).userId;
    const release = releaseOnCreate(req);
    let id: string;
    try {
      id = await app.db.transaction(async (tx) => {
        const [s] = await tx
          .insert(scripts)
          .values({ name: body.name, description: body.description, interpreter: body.interpreter, createdBy: userId })
          .returning({ id: scripts.id });
        const versionId = randomUUID();
        const hash = sha256(body.content);
        await tx.insert(scriptVersions).values({
          id: versionId,
          scriptId: s!.id,
          version: 1,
          content: body.content,
          sha256: hash,
          seal: scriptVersionSeal(versionId, hash),
          parameters: body.parameters,
          changeNote: body.changeNote,
          createdBy: userId,
          ...release,
        });
        return s!.id;
      });
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Script "${body.name}" already exists`);
      throw err;
    }
    await writeAudit(app.db, actorOf(req), { action: 'script.create', targetType: 'script', targetId: id, details: { name: body.name, interpreter: body.interpreter }, ip: req.ip });
    return reply.code(201).send(await loadScript(app.db, id));
  });

  app.get('/scripts/:id', { preHandler: app.requirePermission('scripts:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    return loadScript(app.db, id);
  });

  app.patch('/scripts/:id', { preHandler: app.requirePermission('scripts:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(UpdateScript, req.body);
    await loadScript(app.db, id);
    try {
      await app.db.update(scripts).set({ ...body, updatedAt: new Date() }).where(eq(scripts.id, id));
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Script "${body.name}" already exists`);
      throw err;
    }
    await writeAudit(app.db, actorOf(req), { action: 'script.update', targetType: 'script', targetId: id, details: body, ip: req.ip });
    return loadScript(app.db, id);
  });

  app.delete('/scripts/:id', { preHandler: app.requirePermission('scripts:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const s = await loadScript(app.db, id);
    const used = await app.db
      .select({ id: jobSteps.id })
      .from(jobSteps)
      .innerJoin(scriptVersions, eq(scriptVersions.id, jobSteps.scriptVersionId))
      .where(eq(scriptVersions.scriptId, id))
      .limit(1);
    if (used.length) throw conflict('Script is used by at least one job – remove it from the jobs first');
    await app.db.delete(scripts).where(eq(scripts.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'script.delete', targetType: 'script', targetId: id, details: { name: s.name }, ip: req.ip });
    return reply.code(204).send();
  });

  app.post('/scripts/:id/versions', { preHandler: app.requirePermission('scripts:update') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(NewVersion, req.body);
    const s = await loadScript(app.db, id);
    const version = s.latestVersion + 1;
    try {
      const versionId = randomUUID();
      const hash = sha256(body.content);
      await app.db.insert(scriptVersions).values({
        id: versionId,
        scriptId: id,
        version,
        content: body.content,
        sha256: hash,
        seal: scriptVersionSeal(versionId, hash),
        parameters: body.parameters,
        changeNote: body.changeNote,
        createdBy: principalOf(req).userId,
        ...releaseOnCreate(req),
      });
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict('Version was created concurrently – reload and try again');
      throw err;
    }
    await app.db.update(scripts).set({ updatedAt: new Date() }).where(eq(scripts.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'script.version_create', targetType: 'script', targetId: id, details: { version }, ip: req.ip });
    return reply.code(201).send(await loadVersion(app.db, id, version));
  });

  app.get('/scripts/:id/versions/:version', { preHandler: app.requirePermission('scripts:read') }, async (req) => {
    const { id, version } = parse(VersionParams, req.params);
    return loadVersion(app.db, id, version);
  });

  app.post('/scripts/:id/versions/:version/approve', { preHandler: app.requirePermission('scripts:approve') }, async (req) => {
    const { id, version } = parse(VersionParams, req.params);
    const v = await loadVersion(app.db, id, version);
    const me = principalOf(req).userId;
    if (v.status === 'approved') return v; // already released (new versions are released on creation)
    if (v.status !== 'draft') throw conflict(`Version is ${v.status}`);
    await app.db.update(scriptVersions).set({ status: 'approved', approvedBy: me, approvedAt: new Date() }).where(eq(scriptVersions.id, v.id));
    await writeAudit(app.db, actorOf(req), {
      action: 'script.version_approve',
      targetType: 'script',
      targetId: id,
      details: { version, sha256: v.sha256 },
      ip: req.ip,
    });
    return loadVersion(app.db, id, version);
  });

  app.post('/scripts/:id/versions/:version/retire', { preHandler: app.requirePermission('scripts:approve') }, async (req) => {
    const { id, version } = parse(VersionParams, req.params);
    const v = await loadVersion(app.db, id, version);
    if (v.status === 'retired') throw conflict('Version is already retired');
    await app.db.update(scriptVersions).set({ status: 'retired' }).where(eq(scriptVersions.id, v.id));
    await writeAudit(app.db, actorOf(req), { action: 'script.version_retire', targetType: 'script', targetId: id, details: { version }, ip: req.ip });
    return loadVersion(app.db, id, version);
  });

  // Test run of any version (incl. drafts) on a single device.
  app.post('/scripts/:id/versions/:version/test', { preHandler: app.requireScopedPermission('scripts:execute') }, async (req, reply) => {
    const { id, version } = parse(VersionParams, req.params);
    const body = parse(TestRun, req.body);
    assertInScope(await app.deviceScope(req, 'scripts:execute'), body.deviceId);
    const s = await loadScript(app.db, id);
    const v = await loadVersion(app.db, id, version);
    if (v.status === 'retired') throw conflict('Retired versions cannot be executed');
    // A draft is unreviewed code: only someone who could approve it may run it (REV-007).
    if (v.status !== 'approved' && !hasPermission(principalOf(req).grants, 'scripts:approve')) {
      throw forbidden('Only approved versions can be test-run without the permission scripts:approve');
    }
    const [d] = await app.db.select({ id: devices.id, os: devices.os, status: devices.status, hostname: devices.hostname }).from(devices).where(eq(devices.id, body.deviceId));
    if (!d) throw notFound('Device');
    if (d.status !== 'active') throw conflict('Device is revoked');
    if (!supportsOs(s.interpreter, d.os)) throw new HttpError(400, 'incompatible_device', `${INTERPRETERS[s.interpreter as keyof typeof INTERPRETERS].label} is not available on ${d.os}`);
    const { values, errors } = resolveParams(v.parameters, body.params);
    if (errors.length) throw new HttpError(400, 'invalid_parameters', errors.join('; '));
    const userId = principalOf(req).userId;
    const run = await createRun(app.db, {
      jobId: null,
      name: `Test: ${s.name} v${version}`,
      trigger: 'test',
      triggeredBy: userId,
      steps: [
        {
          position: 0,
          scriptId: s.id,
          scriptName: s.name,
          scriptVersionId: v.id,
          version,
          interpreter: s.interpreter,
          content: v.content,
          sha256: v.sha256,
          params: values,
          continueOnError: false,
          customFieldId: null,
        },
      ],
      options: { ...DEFAULT_OPTIONS, timeoutSeconds: body.timeoutSeconds, timezone: 'UTC' },
      deviceIds: [d.id],
    });
    await writeAudit(app.db, actorOf(req), {
      action: 'script.test_run',
      targetType: 'script',
      targetId: id,
      details: { version, status: v.status, deviceId: d.id, hostname: d.hostname, runId: run.id },
      ip: req.ip,
    });
    return reply.code(201).send(run);
  });
}
