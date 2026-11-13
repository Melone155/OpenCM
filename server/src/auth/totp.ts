import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** RFC 6238 TOTP (HMAC-SHA1, 30 s, 6 digits) – compatible with all authenticator apps. */
export const TOTP_STEP = 30;
export const TOTP_DIGITS = 6;

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('invalid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20)); // 160 bit, as recommended by RFC 4226
}

export function hotp(secret: Buffer, counter: number, digits = TOTP_DIGITS, algorithm = 'sha1'): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac(algorithm, secret).update(msg).digest();
  const offset = h[h.length - 1]! & 0x0f;
  const bin = ((h[offset]! & 0x7f) << 24) | (h[offset + 1]! << 16) | (h[offset + 2]! << 8) | h[offset + 3]!;
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export const counterAt = (time: Date) => Math.floor(time.getTime() / 1000 / TOTP_STEP);

/**
 * Verifies a code within ±1 time step. Returns the matched counter (store it and
 * reject codes with counter <= last accepted one to prevent replay) or null.
 */
export function verifyTotp(secretB32: string, code: string, now = new Date(), lastCounter: number | null = null): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const secret = base32Decode(secretB32);
  const c = counterAt(now);
  for (const counter of [c - 1, c, c + 1]) {
    if (lastCounter !== null && counter <= lastCounter) continue;
    const expected = Buffer.from(hotp(secret, counter));
    if (timingSafeEqual(expected, Buffer.from(code))) return counter;
  }
  return null;
}

export function otpauthUri(secretB32: string, account: string, issuer = 'OpenCM'): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP}`;
}

// ---------------------------------------------------------------- recovery codes

export function generateRecoveryCodes(n = 10): string[] {
  return Array.from({ length: n }, () => {
    const s = base32Encode(randomBytes(8)).slice(0, 10).toLowerCase();
    return `${s.slice(0, 5)}-${s.slice(5)}`;
  });
}

export const normalizeRecoveryCode = (code: string) => code.trim().toLowerCase().replace(/[^a-z2-7]/g, '');
export const hashRecoveryCode = (code: string) => createHash('sha256').update(normalizeRecoveryCode(code)).digest('hex');
