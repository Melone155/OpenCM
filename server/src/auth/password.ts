import { randomBytes } from 'node:crypto';
import { argon2id, argon2Verify } from 'hash-wasm';

// OWASP 2024 recommendation for Argon2id: m=19 MiB, t=2, p=1.
// hash-wasm is pure WASM, so it runs anywhere without native build tooling.
const PARAMS = { memorySize: 19456, iterations: 2, parallelism: 1, hashLength: 32 } as const;

export async function hashPassword(password: string): Promise<string> {
  return argon2id({ ...PARAMS, password, salt: randomBytes(16), outputType: 'encoded' });
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2Verify({ password, hash });
  } catch {
    return false;
  }
}

/** A valid hash of a random value; verified against for unknown users to equalise timing. */
let dummyHash: Promise<string> | undefined;
export function getDummyHash(): Promise<string> {
  dummyHash ??= hashPassword(randomBytes(16).toString('hex'));
  return dummyHash;
}

export const PASSWORD_MIN_LENGTH = 12;
