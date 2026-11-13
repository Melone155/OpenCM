import { z } from 'zod';

export class HttpError extends Error {
  statusCode: number;
  code: string;
  details?: unknown;
  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export const notFound = (what = 'Resource') => new HttpError(404, 'not_found', `${what} not found`);
export const conflict = (message: string) => new HttpError(409, 'conflict', message);
export const forbidden = (message = 'Insufficient permissions') => new HttpError(403, 'forbidden', message);

export const Uuid = z.string().uuid();
export const IdParams = z.object({ id: Uuid });

export const Pagination = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

/** Parse with zod; ZodError is mapped to HTTP 400 by the global error handler. */
export function parse<T extends z.ZodType>(schema: T, data: unknown): z.infer<T> {
  return schema.parse(data);
}

/** Postgres unique_violation → 409 */
export function isUniqueViolation(err: unknown): boolean {
  const e = err as { code?: string; cause?: { code?: string } };
  return e?.code === '23505' || e?.cause?.code === '23505';
}
