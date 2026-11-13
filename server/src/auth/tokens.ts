import { createHash, randomBytes } from 'node:crypto';

/**
 * Opaque bearer token. Only its SHA-256 hash is stored server-side.
 * Prefixes: ocs = session, oct = API token, oce = enrollment token.
 */
export function generateToken(prefix: 'ocs' | 'oct' | 'oce'): string {
  return `${prefix}_${randomBytes(32).toString('base64url')}`;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
