import createClient, { type Middleware } from 'openapi-fetch';
import type { components, paths } from './schema';

/**
 * Typed client generated from server/openapi.yaml (`npm run api:generate -w web`).
 * Auth uses the httpOnly session cookie set by POST /auth/login – the token is never
 * stored in JS-accessible storage.
 */
export const api = createClient<paths>({ baseUrl: '/api/v1', credentials: 'same-origin' });

export type Schemas = components['schemas'];
export type Me = Schemas['Me'];
export type ApiError = Schemas['Error'];

let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

const authMiddleware: Middleware = {
  onResponse({ response, request }) {
    if (response.status === 401 && !request.url.endsWith('/auth/login')) onUnauthorized();
    return response;
  },
};
api.use(authMiddleware);

export function errorMessage(err: unknown): string {
  const e = err as Partial<ApiError> | undefined;
  return e?.error?.message ?? 'Unbekannter Fehler';
}

/** For endpoints that also offer text/csv: the UI always requests JSON. */
export function jsonOnly<T>(p: Promise<T>): Promise<Exclude<T, string>> {
  return p as Promise<Exclude<T, string>>;
}

/** Unwrap an openapi-fetch result or throw the API error message. */
export async function unwrap<T>(p: Promise<{ data?: T; error?: unknown }>): Promise<T> {
  const { data, error } = await p;
  if (error !== undefined) throw new Error(errorMessage(error));
  return data as T;
}
