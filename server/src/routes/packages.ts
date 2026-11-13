import type { Readable } from 'node:stream';
import { and, asc, count, desc, eq, ilike, inArray, or } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { scopeCondition } from '../auth/scope.ts';
import type { Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import { deployments, devices, deviceSoftware, jobRuns, packageFiles, packages, packageVersions, tasks, type DetectionRule } from '../db/schema.ts';
import { conflict, forbidden, HttpError, IdParams, isUniqueViolation, notFound, parse, Uuid } from '../http.ts';
import { versionInput } from '../packages/deploy.ts';
import { detectFromInventory } from '../packages/detect.ts';
import { PACKAGE_TYPES, packageScript, needsFile, validateAction, validatePackageVersion, type PackageType, type PackageVersionInput, type Platform } from '../packages/generate.ts';
import { PackageStore } from '../packages/storage.ts';
import { INTEGRITY_PREFIX, IntegrityError, reportIntegrityViolation } from '../integrity.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';

const PLATFORMS = ['windows', 'linux', 'macos'] as const;
const TYPES = Object.keys(PACKAGE_TYPES) as [PackageType, ...PackageType[]];

const DetectionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('software'), name: z.string().trim().min(1).max(200), version: z.string().trim().max(100).optional(), operator: z.enum(['eq', 'gte', 'lt']).optional() }),
  z.object({ type: z.literal('file'), path: z.string().trim().min(1).max(500), version: z.string().trim().max(100).optional() }),
  z.object({ type: z.literal('registry'), key: z.string().trim().min(1).max(500), value: z.string().max(200).optional(), data: z.string().max(500).optional() }),
  z.object({ type: z.literal('command'), command: z.string().min(1).max(20_000) }),
]);
const ExitCodes = z.array(z.number().int().min(-2147483648).max(4294967295)).max(50);

const PackageBody = z.object({
  name: z.string().trim().min(1).max(150),
  publisher: z.string().trim().max(150).default(''),
  description: z.string().max(4000).default(''),
  platform: z.enum(PLATFORMS),
});
const PackagePatch = z.object({
  name: z.string().trim().min(1).max(150).optional(),
  publisher: z.string().trim().max(150).optional(),
  description: z.string().max(4000).optional(),
});
const VersionBody = z.object({
  version: z.string().trim().min(1).max(50),
  type: z.enum(TYPES),
  packageRef: z.string().trim().max(200).nullable().default(null),
  installArgs: z.string().max(2000).default(''),
  installCommand: z.string().max(100_000).default(''),
  uninstallCommand: z.string().max(100_000).default(''),
  productCode: z.string().trim().max(40).nullable().default(null),
  detection: z.array(DetectionSchema).max(20).default([]),
  successCodes: ExitCodes.min(1).default([0]),
  rebootCodes: ExitCodes.default([3010, 1641]),
  timeoutSeconds: z.number().int().min(60).max(86_400).default(3600),
  changeNote: z.string().max(2000).default(''),
});
// explicit PATCH schema (zod 4: .partial() would apply defaults)
const VersionPatch = z.object({
  version: z.string().trim().min(1).max(50).optional(),
  packageRef: z.string().trim().max(200).nullable().optional(),
  installArgs: z.string().max(2000).optional(),
  installCommand: z.string().max(100_000).optional(),
  uninstallCommand: z.string().max(100_000).optional(),
  productCode: z.string().trim().max(40).nullable().optional(),
  detection: z.array(DetectionSchema).max(20).optional(),
  successCodes: ExitCodes.min(1).optional(),
  rebootCodes: ExitCodes.optional(),
  timeoutSeconds: z.number().int().min(60).max(86_400).optional(),
  changeNote: z.string().max(2000).optional(),
});
const VersionParams = z.object({ id: Uuid, versionId: Uuid });
const ListQuery = z.object({ search: z.string().max(100).optional(), platform: z.enum(PLATFORMS).optional() });
const UploadQuery = z.object({ name: z.string().trim().min(1).max(255) });
const ScriptQuery = z.object({ action: z.enum(['install', 'uninstall']).default('install') });

const fileNameOk = (n: string) => !/[\\/\0]/.test(n) && n !== '.' && n !== '..';

export function packageRoutes(app: FastifyInstance, config: Config) {
  const store = new PackageStore(config.PACKAGE_DIR);

  // raw uploads: the body stays a stream (no buffering of multi-GB installers)
  app.addContentTypeParser('application/octet-stream', (_req, payload, done) => done(null, payload));

  async function loadPackage(db: Db, id: string) {
    const [p] = await db.select().from(packages).where(eq(packages.id, id));
    if (!p) throw notFound('Package');
    return p;
  }

  async function loadVersion(db: Db, packageId: string, versionId: string) {
    const [row] = await db
      .select({ v: packageVersions, f: packageFiles })
      .from(packageVersions)
      .leftJoin(packageFiles, eq(packageFiles.sha256, packageVersions.fileSha256))
      .where(and(eq(packageVersions.id, versionId), eq(packageVersions.packageId, packageId)));
    if (!row) throw notFound('Package version');
    return row;
  }

  const versionOut = (v: typeof packageVersions.$inferSelect, f: typeof packageFiles.$inferSelect | null) => ({
    ...v,
    file: f ? { sha256: f.sha256, name: v.fileName ?? f.originalName, sizeBytes: f.sizeBytes } : null,
  });

  function check(platform: string, v: PackageVersionInput) {
    const problems = validatePackageVersion(platform as Platform, v);
    if (problems.length) throw new HttpError(400, 'validation_error', problems.join('; '), problems);
  }

  // ------------------------------------------------------------ packages

  app.get('/packages', { preHandler: app.requirePermission('software:read') }, async (req) => {
    const q = parse(ListQuery, req.query);
    const conds = [];
    if (q.search) conds.push(or(ilike(packages.name, `%${q.search}%`), ilike(packages.publisher, `%${q.search}%`)));
    if (q.platform) conds.push(eq(packages.platform, q.platform));
    const rows = await app.db
      .select()
      .from(packages)
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(asc(packages.name));
    const versions = rows.length
      ? await app.db
          .select({ packageId: packageVersions.packageId, version: packageVersions.version, status: packageVersions.status, type: packageVersions.type, createdAt: packageVersions.createdAt })
          .from(packageVersions)
          .where(inArray(packageVersions.packageId, rows.map((r) => r.id)))
          .orderBy(desc(packageVersions.createdAt))
      : [];
    return {
      items: rows.map((p) => {
        const mine = versions.filter((v) => v.packageId === p.id);
        return {
          ...p,
          versionCount: mine.length,
          latestVersion: mine[0]?.version ?? null,
          approvedVersion: mine.find((v) => v.status === 'approved')?.version ?? null,
          type: mine[0]?.type ?? null,
        };
      }),
    };
  });

  app.post('/packages', { preHandler: app.requirePermission('software:create') }, async (req, reply) => {
    const body = parse(PackageBody, req.body);
    try {
      const [p] = await app.db.insert(packages).values({ ...body, createdBy: principalOf(req).userId }).returning();
      await writeAudit(app.db, actorOf(req), { action: 'package.create', targetType: 'package', targetId: p!.id, details: body, ip: req.ip });
      return reply.code(201).send({ ...p, versions: [] });
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Package "${body.name}" already exists`);
      throw err;
    }
  });

  app.get('/packages/:id', { preHandler: app.requirePermission('software:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const p = await loadPackage(app.db, id);
    const versions = await app.db
      .select({ v: packageVersions, f: packageFiles })
      .from(packageVersions)
      .leftJoin(packageFiles, eq(packageFiles.sha256, packageVersions.fileSha256))
      .where(eq(packageVersions.packageId, id))
      .orderBy(desc(packageVersions.createdAt));
    return { ...p, versions: versions.map(({ v, f }) => versionOut(v, f)) };
  });

  app.patch('/packages/:id', { preHandler: app.requirePermission('software:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(PackagePatch, req.body);
    await loadPackage(app.db, id);
    try {
      const [p] = await app.db.update(packages).set({ ...body, updatedAt: new Date() }).where(eq(packages.id, id)).returning();
      await writeAudit(app.db, actorOf(req), { action: 'package.update', targetType: 'package', targetId: id, details: body, ip: req.ip });
      return p;
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Package "${body.name}" already exists`);
      throw err;
    }
  });

  app.delete('/packages/:id', { preHandler: app.requirePermission('software:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const p = await loadPackage(app.db, id);
    const [used] = await app.db
      .select({ n: count() })
      .from(deployments)
      .innerJoin(packageVersions, eq(packageVersions.id, deployments.packageVersionId))
      .where(eq(packageVersions.packageId, id));
    if ((used?.n ?? 0) > 0) throw conflict('The package was deployed – retire its versions instead of deleting it');
    await app.db.delete(packages).where(eq(packages.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'package.delete', targetType: 'package', targetId: id, details: { name: p.name }, ip: req.ip });
    return reply.code(204).send();
  });

  // ------------------------------------------------------------ versions

  app.post('/packages/:id/versions', { preHandler: app.requirePermission('software:create') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const p = await loadPackage(app.db, id);
    const body = parse(VersionBody, req.body);
    const vi = { ...body, fileSha256: null, fileName: null, detection: body.detection as DetectionRule[] };
    check(p.platform, vi);
    try {
      const [v] = await app.db
        .insert(packageVersions)
        .values({ ...body, detection: body.detection as DetectionRule[], packageId: id, createdBy: principalOf(req).userId })
        .returning();
      await app.db.update(packages).set({ updatedAt: new Date() }).where(eq(packages.id, id));
      await writeAudit(app.db, actorOf(req), { action: 'package.version_create', targetType: 'package', targetId: id, details: { version: body.version, type: body.type }, ip: req.ip });
      return reply.code(201).send(versionOut(v!, null));
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Version ${body.version} already exists`);
      throw err;
    }
  });

  app.patch('/packages/:id/versions/:versionId', { preHandler: app.requirePermission('software:update') }, async (req) => {
    const { id, versionId } = parse(VersionParams, req.params);
    const p = await loadPackage(app.db, id);
    const { v, f } = await loadVersion(app.db, id, versionId);
    if (v.status !== 'draft') throw conflict(`Version is ${v.status} – approved versions are immutable, create a new version`);
    const body = parse(VersionPatch, req.body);
    const next = { ...v, ...body, detection: (body.detection ?? v.detection) as DetectionRule[] };
    check(p.platform, versionInput(next, f?.sizeBytes));
    try {
      const [u] = await app.db
        .update(packageVersions)
        .set({ ...body, detection: next.detection, updatedAt: new Date() })
        .where(eq(packageVersions.id, versionId))
        .returning();
      await writeAudit(app.db, actorOf(req), { action: 'package.version_update', targetType: 'package', targetId: id, details: { version: u!.version, fields: Object.keys(body) }, ip: req.ip });
      return versionOut(u!, f);
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Version ${body.version} already exists`);
      throw err;
    }
  });

  app.put('/packages/:id/versions/:versionId/file', { preHandler: app.requirePermission('software:update'), bodyLimit: Number.MAX_SAFE_INTEGER }, async (req) => {
    const { id, versionId } = parse(VersionParams, req.params);
    const { name } = parse(UploadQuery, req.query);
    if (!fileNameOk(name)) throw new HttpError(400, 'validation_error', 'Invalid file name');
    if (req.headers['content-type'] !== 'application/octet-stream') throw new HttpError(415, 'unsupported_media_type', 'Upload the file as application/octet-stream');
    await loadPackage(app.db, id);
    const { v } = await loadVersion(app.db, id, versionId);
    if (v.status !== 'draft') throw conflict(`Version is ${v.status} – approved versions are immutable`);
    if (PACKAGE_TYPES[v.type as PackageType].file === 'none') throw conflict(`Type ${v.type} has no installer file`);
    const declared = Number(req.headers['content-length'] ?? 0);
    if (declared > config.PACKAGE_MAX_BYTES) throw new HttpError(413, 'file_too_large', `File exceeds ${config.PACKAGE_MAX_BYTES} bytes`);
    const saved = await store.save(req.body as Readable, config.PACKAGE_MAX_BYTES);
    await app.db
      .insert(packageFiles)
      .values({ sha256: saved.sha256, sizeBytes: saved.sizeBytes, originalName: name, uploadedBy: principalOf(req).userId })
      .onConflictDoNothing();
    const previous = v.fileSha256;
    const [u] = await app.db
      .update(packageVersions)
      .set({ fileSha256: saved.sha256, fileName: name, updatedAt: new Date() })
      .where(eq(packageVersions.id, versionId))
      .returning();
    if (previous && previous !== saved.sha256) await removeOrphan(previous);
    await writeAudit(app.db, actorOf(req), {
      action: 'package.file_upload',
      targetType: 'package',
      targetId: id,
      details: { version: v.version, name, sha256: saved.sha256, sizeBytes: saved.sizeBytes },
      ip: req.ip,
    });
    const [f] = await app.db.select().from(packageFiles).where(eq(packageFiles.sha256, saved.sha256));
    return versionOut(u!, f ?? null);
  });

  /** Deletes a file that no version references any more. */
  async function removeOrphan(sha256: string) {
    const [ref] = await app.db.select({ n: count() }).from(packageVersions).where(eq(packageVersions.fileSha256, sha256));
    if ((ref?.n ?? 0) > 0) return;
    await app.db.delete(packageFiles).where(eq(packageFiles.sha256, sha256));
    await store.remove(sha256);
  }

  app.post('/packages/:id/versions/:versionId/approve', { preHandler: app.requirePermission('software:approve') }, async (req) => {
    const { id, versionId } = parse(VersionParams, req.params);
    const p = await loadPackage(app.db, id);
    const { v, f } = await loadVersion(app.db, id, versionId);
    const me = principalOf(req).userId;
    if (v.status !== 'draft') throw conflict(`Version is ${v.status}`);
    if (!config.SCRIPT_SELF_APPROVAL && v.createdBy === me) throw forbidden('You cannot approve a version you created yourself');
    const problems = validatePackageVersion(p.platform as Platform, versionInput(v, f?.sizeBytes), { requireFile: true });
    if (problems.length) throw new HttpError(409, 'package_invalid', problems.join('; '), problems);
    if (v.fileSha256 && !(await store.exists(v.fileSha256))) throw conflict('The installer file is missing in the repository – upload it again');
    if (v.fileSha256 && !(await store.verify(v.fileSha256))) {
      const message = `${INTEGRITY_PREFIX} Installationsdatei von ${p.name} ${v.version} wurde im Repository verändert (SHA-256 stimmt nicht mehr)`;
      await reportIntegrityViolation(app.db, { message, source: 'repository' });
      throw new IntegrityError(message.slice(INTEGRITY_PREFIX.length + 1));
    }
    const [u] = await app.db.update(packageVersions).set({ status: 'approved', approvedBy: me, approvedAt: new Date() }).where(eq(packageVersions.id, versionId)).returning();
    await writeAudit(app.db, actorOf(req), { action: 'package.version_approve', targetType: 'package', targetId: id, details: { version: v.version, sha256: v.fileSha256 }, ip: req.ip });
    return versionOut(u!, f);
  });

  app.post('/packages/:id/versions/:versionId/retire', { preHandler: app.requirePermission('software:approve') }, async (req) => {
    const { id, versionId } = parse(VersionParams, req.params);
    const { v, f } = await loadVersion(app.db, id, versionId);
    if (v.status === 'retired') throw conflict('Version is already retired');
    const [u] = await app.db.update(packageVersions).set({ status: 'retired', updatedAt: new Date() }).where(eq(packageVersions.id, versionId)).returning();
    await writeAudit(app.db, actorOf(req), { action: 'package.version_retire', targetType: 'package', targetId: id, details: { version: v.version }, ip: req.ip });
    return versionOut(u!, f);
  });

  app.delete('/packages/:id/versions/:versionId', { preHandler: app.requirePermission('software:delete') }, async (req, reply) => {
    const { id, versionId } = parse(VersionParams, req.params);
    const { v } = await loadVersion(app.db, id, versionId);
    if (v.status !== 'draft') throw conflict('Only draft versions can be deleted – retire approved versions');
    await app.db.delete(packageVersions).where(eq(packageVersions.id, versionId));
    if (v.fileSha256) await removeOrphan(v.fileSha256);
    await writeAudit(app.db, actorOf(req), { action: 'package.version_delete', targetType: 'package', targetId: id, details: { version: v.version }, ip: req.ip });
    return reply.code(204).send();
  });

  app.get('/packages/:id/versions/:versionId/script', { preHandler: app.requirePermission('software:read') }, async (req) => {
    const { id, versionId } = parse(VersionParams, req.params);
    const { action } = parse(ScriptQuery, req.query);
    const p = await loadPackage(app.db, id);
    const { v, f } = await loadVersion(app.db, id, versionId);
    const vi = versionInput(v, f?.sizeBytes);
    const problems = [...validatePackageVersion(p.platform as Platform, vi), ...validateAction(vi, action)];
    if (problems.length) throw new HttpError(409, 'package_invalid', problems.join('; '), problems);
    return {
      interpreter: p.platform === 'windows' ? 'powershell' : 'bash',
      content: packageScript({ id: p.id, name: p.name, platform: p.platform as Platform }, v.version, vi, action),
      files: needsFile(vi, action) && f ? [{ sha256: f.sha256, name: v.fileName ?? f.originalName, sizeBytes: f.sizeBytes }] : [],
    };
  });

  // ------------------------------------------------------------ compliance

  app.get('/packages/:id/compliance', { preHandler: app.requireScopedPermission('software:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const p = await loadPackage(app.db, id);
    const [v] = await app.db
      .select()
      .from(packageVersions)
      .where(and(eq(packageVersions.packageId, id), eq(packageVersions.status, 'approved')))
      .orderBy(desc(packageVersions.approvedAt))
      .limit(1);
    const scope = await app.deviceScope(req, 'software:read');
    const devs = await app.db
      .select({ id: devices.id, hostname: devices.hostname, lastInventoryAt: devices.lastInventoryAt })
      .from(devices)
      .where(and(eq(devices.status, 'active'), eq(devices.os, p.platform), scopeCondition(scope, devices.id)))
      .orderBy(asc(devices.hostname));
    const ids = devs.map((d) => d.id);
    const software = ids.length && v ? await app.db.select({ deviceId: deviceSoftware.deviceId, name: deviceSoftware.name, version: deviceSoftware.version }).from(deviceSoftware).where(inArray(deviceSoftware.deviceId, ids)) : [];
    const byDevice = new Map<string, { name: string; version: string }[]>();
    for (const s of software) byDevice.set(s.deviceId, [...(byDevice.get(s.deviceId) ?? []), s]);
    // latest deployment task per device for any version of this package
    const last = ids.length
      ? await app.db
          .select({ deviceId: tasks.deviceId, status: tasks.status, finishedAt: tasks.finishedAt, action: deployments.action, version: packageVersions.version })
          .from(tasks)
          .innerJoin(jobRuns, eq(jobRuns.id, tasks.runId))
          .innerJoin(deployments, eq(deployments.id, jobRuns.deploymentId))
          .innerJoin(packageVersions, eq(packageVersions.id, deployments.packageVersionId))
          .where(and(eq(packageVersions.packageId, id), inArray(tasks.deviceId, ids)))
          .orderBy(desc(tasks.createdAt))
      : [];
    const lastBy = new Map<string, (typeof last)[number]>();
    for (const t of last) if (!lastBy.has(t.deviceId)) lastBy.set(t.deviceId, t);
    const items = devs.map((d) => {
      const detected = v && d.lastInventoryAt ? detectFromInventory(v.detection, byDevice.get(d.id) ?? []) : null;
      const t = lastBy.get(d.id) ?? null;
      return {
        deviceId: d.id,
        hostname: d.hostname,
        installed: detected,
        lastDeployment: t ? { status: t.status, action: t.action, version: t.version, finishedAt: t.finishedAt } : null,
      };
    });
    return {
      packageId: id,
      version: v?.version ?? null,
      summary: {
        devices: items.length,
        installed: items.filter((i) => i.installed === true).length,
        missing: items.filter((i) => i.installed === false).length,
        unknown: items.filter((i) => i.installed === null).length,
        failed: items.filter((i) => i.lastDeployment && ['failed', 'timeout'].includes(i.lastDeployment.status)).length,
      },
      items,
    };
  });
}
