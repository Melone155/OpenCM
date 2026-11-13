import { fileURLToPath } from 'node:url';
import type { PgDatabase, PgQueryResultHKT } from 'drizzle-orm/pg-core';
import * as schema from './schema.ts';

export { schema };

/** Driver-agnostic Drizzle handle (postgres-js in production, PGlite in tests). */
export type Db = PgDatabase<PgQueryResultHKT, typeof schema>;

export const MIGRATIONS_FOLDER = fileURLToPath(new URL('../../drizzle', import.meta.url));

export interface DbHandle {
  db: Db;
  migrate(): Promise<void>;
  close(): Promise<void>;
}

export async function connectPostgres(url: string): Promise<DbHandle> {
  const { default: postgres } = await import('postgres');
  const { drizzle } = await import('drizzle-orm/postgres-js');
  const { migrate } = await import('drizzle-orm/postgres-js/migrator');
  const sql = postgres(url, { max: 10, onnotice: () => {} });
  const db = drizzle(sql, { schema });
  return {
    db: db as unknown as Db,
    migrate: () => migrate(db, { migrationsFolder: MIGRATIONS_FOLDER }),
    close: () => sql.end({ timeout: 5 }),
  };
}

/** In-process Postgres (WASM). Used by tests and for zero-dependency local dev. */
export async function connectPglite(dataDir?: string): Promise<DbHandle> {
  const { PGlite } = await import('@electric-sql/pglite');
  const { drizzle } = await import('drizzle-orm/pglite');
  const { migrate } = await import('drizzle-orm/pglite/migrator');
  // Return json/jsonb as raw text: drizzle parses it itself. Otherwise a jsonb string
  // like "131.0" would be parsed twice (→ number 131), unlike with postgres-js.
  const raw = (v: string) => v;
  // (single options object: PGlite ignores the 2nd argument when dataDir is undefined)
  const client = new PGlite({ dataDir, parsers: { 114: raw, 3802: raw } });
  const db = drizzle(client, { schema });
  return {
    db: db as unknown as Db,
    migrate: () => migrate(db, { migrationsFolder: MIGRATIONS_FOLDER }),
    close: () => client.close(),
  };
}
