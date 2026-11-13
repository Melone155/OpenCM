import { and, asc, count, desc, eq, ilike, inArray, isNotNull, lte, ne, or, sql, type SQL } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  ASSET_STATUSES,
  ASSET_TYPES,
  CSV_EXPORT_ORDER,
  mapCsvHeader,
  normalizeMac,
  parseAssetStatus,
  parseAssetType,
  parseDay,
  parseMoney,
  STATUS_LABELS,
  TYPE_LABELS,
  unguard,
  validIp,
  type CsvKey,
} from '../assets.ts';
import { writeAudit } from '../audit.ts';
import { assertInScope } from '../auth/scope.ts';
import { parseCsv } from '../csv.ts';
import type { Db } from '../db/client.ts';
import { assets, devices } from '../db/schema.ts';
import { conflict, HttpError, IdParams, notFound, Pagination, parse, Uuid } from '../http.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';
import { csvCell } from './security.ts';

const Day = z.string().refine((v) => parseDay(v) !== null, 'date expected (YYYY-MM-DD)').transform((v) => parseDay(v)!);
const Ip = z.string().trim().max(64).refine(validIp, 'invalid IP address');
const Mac = z.string().trim().max(32).refine((v) => normalizeMac(v) !== null, 'invalid MAC address').transform((v) => normalizeMac(v)!);
const Text = (max: number) => z.string().trim().max(max);
const OptKey = (max: number) => z.string().trim().max(max).nullable().transform((v) => (v ? v : null));

const AssetBody = z.object({
  name: Text(200).min(1),
  type: z.enum(ASSET_TYPES).default('other'),
  status: z.enum(ASSET_STATUSES).default('in_use'),
  manufacturer: Text(200).default(''),
  model: Text(200).default(''),
  serialNumber: OptKey(200).default(null),
  inventoryNumber: OptKey(100).default(null),
  location: Text(200).default(''),
  assignedTo: Text(200).default(''),
  ipAddress: Ip.nullable().default(null),
  macAddress: Mac.nullable().default(null),
  purchaseDate: Day.nullable().default(null),
  warrantyUntil: Day.nullable().default(null),
  cost: z.number().min(0).max(1e10).nullable().default(null),
  deviceId: Uuid.nullable().default(null),
  notes: z.string().max(10_000).default(''),
});
// PATCH without defaults: never .partial() on a schema with .default() (zod 4 would silently reset omitted fields)
const AssetPatch = z.object({
  name: Text(200).min(1).optional(),
  type: z.enum(ASSET_TYPES).optional(),
  status: z.enum(ASSET_STATUSES).optional(),
  manufacturer: Text(200).optional(),
  model: Text(200).optional(),
  serialNumber: OptKey(200).optional(),
  inventoryNumber: OptKey(100).optional(),
  location: Text(200).optional(),
  assignedTo: Text(200).optional(),
  ipAddress: Ip.nullable().optional(),
  macAddress: Mac.nullable().optional(),
  purchaseDate: Day.nullable().optional(),
  warrantyUntil: Day.nullable().optional(),
  cost: z.number().min(0).max(1e10).nullable().optional(),
  deviceId: Uuid.nullable().optional(),
  notes: z.string().max(10_000).optional(),
});
const ListQuery = Pagination.extend({
  search: z.string().max(200).optional(),
  type: z.enum(ASSET_TYPES).optional(),
  status: z.enum(ASSET_STATUSES).optional(),
  deviceId: Uuid.optional(),
  /** only assets whose warranty ends within N days (already expired included) */
  warrantyDays: z.coerce.number().int().min(0).max(3650).optional(),
  includeRetired: z.enum(['true', 'false']).default('true'),
  sort: z.enum(['name', 'type', 'warrantyUntil', 'updatedAt', 'inventoryNumber']).default('name'),
  format: z.enum(['json', 'csv']).default('json'),
});
const ImportBody = z.object({
  csv: z.string().min(1).max(5 * 1024 * 1024),
  dryRun: z.boolean().default(false),
});

const MAX_IMPORT_ROWS = 10_000;

type AssetRow = typeof assets.$inferSelect;
type AssetInput = z.infer<typeof AssetBody>;

const cols = {
  id: assets.id,
  name: assets.name,
  type: assets.type,
  status: assets.status,
  manufacturer: assets.manufacturer,
  model: assets.model,
  serialNumber: assets.serialNumber,
  inventoryNumber: assets.inventoryNumber,
  location: assets.location,
  assignedTo: assets.assignedTo,
  ipAddress: assets.ipAddress,
  macAddress: assets.macAddress,
  purchaseDate: assets.purchaseDate,
  warrantyUntil: assets.warrantyUntil,
  cost: assets.cost,
  deviceId: assets.deviceId,
  deviceHostname: devices.hostname,
  notes: assets.notes,
  createdAt: assets.createdAt,
  updatedAt: assets.updatedAt,
};

const out = <T extends { cost: string | null }>(r: T) => ({ ...r, cost: r.cost === null ? null : Number(r.cost) });
const money = (n: number | null | undefined) => (n === null || n === undefined ? n : String(n));
const escapeLike = (s: string) => s.replace(/[\\%_]/g, (c) => `\\${c}`);

export function assetRoutes(app: FastifyInstance) {
  async function load(id: string) {
    const [a] = await app.db.select(cols).from(assets).leftJoin(devices, eq(devices.id, assets.deviceId)).where(eq(assets.id, id));
    if (!a) throw notFound('Asset');
    return out(a);
  }

  async function assertUniqueInventoryNumber(db: Db, inv: string | null | undefined, exceptId?: string) {
    if (!inv) return;
    const [dup] = await db
      .select({ id: assets.id })
      .from(assets)
      .where(and(sql`lower(${assets.inventoryNumber}) = lower(${inv})`, exceptId ? ne(assets.id, exceptId) : undefined));
    if (dup) throw conflict(`Inventory number "${inv}" is already used by another asset`);
  }

  async function assertDevice(id: string | null | undefined) {
    if (!id) return;
    const [d] = await app.db.select({ id: devices.id }).from(devices).where(eq(devices.id, id));
    if (!d) throw new HttpError(400, 'validation_error', 'deviceId: device not found');
  }

  app.get('/asset-types', { preHandler: app.requirePermission('assets:read') }, async () => ({
    types: ASSET_TYPES.map((key) => ({ key, label: TYPE_LABELS[key] })),
    statuses: ASSET_STATUSES.map((key) => ({ key, label: STATUS_LABELS[key] })),
  }));

  app.get('/assets', { preHandler: app.requirePermission('assets:read') }, async (req, reply) => {
    const q = parse(ListQuery, req.query);
    const conds: (SQL | undefined)[] = [];
    if (q.search) {
      const p = `%${escapeLike(q.search)}%`;
      conds.push(
        or(
          ilike(assets.name, p),
          ilike(assets.serialNumber, p),
          ilike(assets.inventoryNumber, p),
          ilike(assets.model, p),
          ilike(assets.manufacturer, p),
          ilike(assets.assignedTo, p),
          ilike(assets.location, p),
          ilike(assets.ipAddress, p),
          ilike(devices.hostname, p),
        ),
      );
    }
    if (q.type) conds.push(eq(assets.type, q.type));
    if (q.status) conds.push(eq(assets.status, q.status));
    else if (q.includeRetired === 'false') conds.push(ne(assets.status, 'retired'));
    if (q.deviceId) conds.push(eq(assets.deviceId, q.deviceId));
    if (q.warrantyDays !== undefined) {
      conds.push(isNotNull(assets.warrantyUntil), lte(assets.warrantyUntil, sql`(current_date + ${q.warrantyDays}::int)`), ne(assets.status, 'retired'));
    }
    const where = and(...conds);
    const order =
      q.sort === 'warrantyUntil'
        ? sql`${assets.warrantyUntil} asc nulls last`
        : q.sort === 'updatedAt'
          ? desc(assets.updatedAt)
          : q.sort === 'type'
            ? asc(assets.type)
            : q.sort === 'inventoryNumber'
              ? sql`${assets.inventoryNumber} asc nulls last`
              : sql`lower(${assets.name})`;
    const base = app.db.select(cols).from(assets).leftJoin(devices, eq(devices.id, assets.deviceId)).where(where).orderBy(order, asc(assets.id));
    if (q.format === 'csv') {
      const rows = (await base.limit(100_000)).map(out);
      const lines = rows.map((r) => CSV_EXPORT_ORDER.map((k) => csvCell((r as Record<string, unknown>)[k])).join(';'));
      return reply
        .header('content-type', 'text/csv; charset=utf-8')
        .header('content-disposition', `attachment; filename="opencm-assets-${new Date().toISOString().slice(0, 10)}.csv"`)
        .send(`﻿${CSV_EXPORT_ORDER.join(';')}\r\n${lines.join('\r\n')}${lines.length ? '\r\n' : ''}`);
    }
    const items = (await base.limit(q.limit).offset(q.offset)).map(out);
    const [total] = await app.db.select({ n: count() }).from(assets).leftJoin(devices, eq(devices.id, assets.deviceId)).where(where);
    return { items, total: Number(total?.n ?? 0) };
  });

  app.get('/assets/:id', { preHandler: app.requirePermission('assets:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    return load(id);
  });

  app.post('/assets', { preHandler: app.requirePermission('assets:create') }, async (req, reply) => {
    const body = parse(AssetBody, req.body);
    await assertUniqueInventoryNumber(app.db, body.inventoryNumber);
    await assertDevice(body.deviceId);
    const [a] = await app.db
      .insert(assets)
      .values({ ...body, cost: money(body.cost) ?? null, createdBy: principalOf(req).userId })
      .returning({ id: assets.id });
    await writeAudit(app.db, actorOf(req), { action: 'asset.create', targetType: 'asset', targetId: a!.id, details: { name: body.name, type: body.type, inventoryNumber: body.inventoryNumber }, ip: req.ip });
    return reply.code(201).send(await load(a!.id));
  });

  app.patch('/assets/:id', { preHandler: app.requirePermission('assets:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(AssetPatch, req.body);
    await load(id);
    await assertUniqueInventoryNumber(app.db, body.inventoryNumber, id);
    await assertDevice(body.deviceId);
    const { cost, ...rest } = body;
    await app.db
      .update(assets)
      .set({ ...rest, ...(cost !== undefined && { cost: money(cost) ?? null }), updatedAt: new Date() })
      .where(eq(assets.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'asset.update', targetType: 'asset', targetId: id, details: body, ip: req.ip });
    return load(id);
  });

  app.delete('/assets/:id', { preHandler: app.requirePermission('assets:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const a = await load(id);
    await app.db.delete(assets).where(eq(assets.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'asset.delete', targetType: 'asset', targetId: id, details: { name: a.name, inventoryNumber: a.inventoryNumber }, ip: req.ip });
    return reply.code(204).send();
  });

  app.get('/devices/:id/assets', { preHandler: app.requirePermission('assets:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'devices:read'), id);
    const items = await app.db.select(cols).from(assets).leftJoin(devices, eq(devices.id, assets.deviceId)).where(eq(assets.deviceId, id)).orderBy(sql`lower(${assets.name})`);
    return { items: items.map(out) };
  });

  // ------------------------------------------------------------ CSV import

  app.post('/assets/import', { preHandler: [app.requirePermission('assets:create'), app.requirePermission('assets:update')], bodyLimit: 6 * 1024 * 1024 }, async (req) => {
    const body = parse(ImportBody, req.body);
    const result = await importAssets(app.db, body.csv, body.dryRun, principalOf(req).userId);
    if (!body.dryRun) {
      await writeAudit(app.db, actorOf(req), { action: 'asset.import', targetType: 'asset', details: { created: result.created, updated: result.updated, errors: result.errors.length }, ip: req.ip });
    }
    return result;
  });
}

export interface ImportResult {
  dryRun: boolean;
  rows: number;
  created: number;
  updated: number;
  skipped: number;
  errors: { line: number; message: string }[];
  warnings: { line: number; message: string }[];
  unknownColumns: string[];
}

/**
 * Imports assets from CSV. Matching: inventory number (case-insensitive), otherwise
 * serial number; unmatched rows are created. Invalid rows are reported and skipped,
 * valid rows are imported (in one transaction). dryRun only validates.
 */
export async function importAssets(db: Db, csv: string, dryRun: boolean, userId: string | null): Promise<ImportResult> {
  const rows = parseCsv(csv);
  const res: ImportResult = { dryRun, rows: Math.max(rows.length - 1, 0), created: 0, updated: 0, skipped: 0, errors: [], warnings: [], unknownColumns: [] };
  if (rows.length < 2) throw new HttpError(400, 'validation_error', 'CSV needs a header line and at least one data row');
  if (rows.length - 1 > MAX_IMPORT_ROWS) throw new HttpError(400, 'validation_error', `At most ${MAX_IMPORT_ROWS} rows per import`);
  const { index, unknown } = mapCsvHeader(rows[0]!);
  res.unknownColumns = unknown;
  if (index.name === undefined) throw new HttpError(400, 'validation_error', 'Column "name" (or "Bezeichnung") is required');

  // lookups: existing assets by inventory number / serial, devices by hostname
  const existing = await db.select({ id: assets.id, inventoryNumber: assets.inventoryNumber, serialNumber: assets.serialNumber }).from(assets);
  const byInv = new Map(existing.filter((e) => e.inventoryNumber).map((e) => [e.inventoryNumber!.toLowerCase(), e.id]));
  const bySerial = new Map<string, string>();
  for (const e of existing) if (e.serialNumber && !bySerial.has(e.serialNumber.toLowerCase())) bySerial.set(e.serialNumber.toLowerCase(), e.id);
  const hostnames = [...new Set(rows.slice(1).map((r) => (index.deviceHostname !== undefined ? (r[index.deviceHostname] ?? '').trim().toLowerCase() : '')).filter(Boolean))];
  const deviceByHost = new Map<string, string>();
  if (hostnames.length) {
    for (const d of await db
      .select({ id: devices.id, hostname: devices.hostname })
      .from(devices)
      .where(and(eq(devices.status, 'active'), inArray(sql`lower(${devices.hostname})`, hostnames)))) {
      deviceByHost.set(d.hostname.toLowerCase(), d.id);
    }
  }

  const creates: (typeof assets.$inferInsert)[] = [];
  const updates: { id: string; set: Partial<typeof assets.$inferInsert> }[] = [];
  const seenInv = new Set<string>();

  rows.slice(1).forEach((r, i) => {
    const line = i + 2;
    const cell = (k: CsvKey) => (index[k] === undefined ? undefined : unguard((r[index[k]!] ?? '').trim()));
    const errs: string[] = [];
    const v: Partial<AssetInput> = {};
    const name = cell('name');
    if (!name) errs.push('Name fehlt');
    else v.name = name.slice(0, 200);
    const t = cell('type');
    if (t) {
      const p = parseAssetType(t);
      if (p) v.type = p;
      else errs.push(`Unbekannter Typ "${t}"`);
    }
    const s = cell('status');
    if (s) {
      const p = parseAssetStatus(s);
      if (p) v.status = p;
      else errs.push(`Unbekannter Status "${s}"`);
    }
    for (const k of ['manufacturer', 'model', 'location', 'assignedTo'] as const) {
      const c = cell(k);
      if (c !== undefined) v[k] = c.slice(0, 200);
    }
    const notes = cell('notes');
    if (notes !== undefined) v.notes = notes.slice(0, 10_000);
    const serial = cell('serialNumber');
    if (serial !== undefined) v.serialNumber = serial ? serial.slice(0, 200) : null;
    const inv = cell('inventoryNumber');
    if (inv !== undefined) v.inventoryNumber = inv ? inv.slice(0, 100) : null;
    const ip = cell('ipAddress');
    if (ip) {
      if (validIp(ip)) v.ipAddress = ip;
      else errs.push(`Ungültige IP-Adresse "${ip}"`);
    }
    const mac = cell('macAddress');
    if (mac) {
      const m = normalizeMac(mac);
      if (m) v.macAddress = m;
      else errs.push(`Ungültige MAC-Adresse "${mac}"`);
    }
    for (const k of ['purchaseDate', 'warrantyUntil'] as const) {
      const c = cell(k);
      if (c) {
        const d = parseDay(c);
        if (d) v[k] = d;
        else errs.push(`Ungültiges Datum "${c}" (${k === 'purchaseDate' ? 'Kaufdatum' : 'Garantie bis'}; erwartet JJJJ-MM-TT oder TT.MM.JJJJ)`);
      }
    }
    const cost = cell('cost');
    if (cost) {
      const n = parseMoney(cost);
      if (n !== null) v.cost = n;
      else errs.push(`Ungültiger Betrag "${cost}"`);
    }
    const host = cell('deviceHostname');
    if (host) {
      const id = deviceByHost.get(host.toLowerCase());
      if (id) v.deviceId = id;
      else res.warnings.push({ line, message: `Gerät "${host}" nicht gefunden – Zuordnung übersprungen` });
    }
    if (v.inventoryNumber) {
      const k = v.inventoryNumber.toLowerCase();
      if (seenInv.has(k)) errs.push(`Inventarnummer "${v.inventoryNumber}" kommt in der Datei mehrfach vor`);
      seenInv.add(k);
    }
    if (errs.length) {
      res.errors.push({ line, message: errs.join('; ') });
      res.skipped++;
      return;
    }
    const match = (v.inventoryNumber && byInv.get(v.inventoryNumber.toLowerCase())) || (v.serialNumber && bySerial.get(v.serialNumber.toLowerCase())) || null;
    const { cost: c, ...rest } = v;
    const row = { ...rest, ...(c !== undefined && { cost: money(c) ?? null }) };
    if (match) {
      // the inventory number must stay unique when a row matched by serial number brings a new one
      if (v.inventoryNumber) {
        const owner = byInv.get(v.inventoryNumber.toLowerCase());
        if (owner && owner !== match) {
          res.errors.push({ line, message: `Inventarnummer "${v.inventoryNumber}" gehört bereits zu einem anderen Asset` });
          res.skipped++;
          return;
        }
      }
      updates.push({ id: match, set: { ...row, updatedAt: new Date() } });
      res.updated++;
    } else {
      creates.push({ ...(row as Omit<typeof assets.$inferInsert, 'name'>), name: v.name!, createdBy: userId });
      res.created++;
    }
  });

  if (!dryRun && (creates.length || updates.length)) {
    await db.transaction(async (tx) => {
      for (let i = 0; i < creates.length; i += 500) await tx.insert(assets).values(creates.slice(i, i + 500));
      for (const u of updates) await tx.update(assets).set(u.set).where(eq(assets.id, u.id));
    });
  }
  return res;
}

export type { AssetRow };
