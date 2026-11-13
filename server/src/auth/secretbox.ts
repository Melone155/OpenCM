import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Symmetric encryption for secrets stored in the database (e.g. TOTP secrets).
 * AES-256-GCM, key in PKI_DIR/secrets.key (never in the DB): a database dump alone
 * does not reveal the secrets. Format: v1:<iv b64>:<tag b64>:<ciphertext b64>
 */
export interface SecretBox {
  seal(plain: string): string;
  open(sealed: string): string;
}

export async function initSecretBox(dir: string): Promise<SecretBox> {
  const keyPath = join(dir, 'secrets.key');
  let key: Buffer;
  try {
    key = Buffer.from((await readFile(keyPath, 'utf8')).trim(), 'base64');
    if (key.length !== 32) throw new Error('invalid key length');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error(`secrets.key is unreadable: ${(err as Error).message}`);
    key = randomBytes(32);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const tmp = `${keyPath}.tmp`;
    await writeFile(tmp, key.toString('base64'), { mode: 0o600 });
    await chmod(tmp, 0o600).catch(() => {});
    await rename(tmp, keyPath);
  }
  return {
    seal(plain) {
      const iv = randomBytes(12);
      const c = createCipheriv('aes-256-gcm', key, iv);
      const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
      return `v1:${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${enc.toString('base64')}`;
    },
    open(sealed) {
      const [v, iv, tag, data] = sealed.split(':');
      if (v !== 'v1' || !iv || !tag || data === undefined) throw new Error('unsupported secret format');
      const d = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
      d.setAuthTag(Buffer.from(tag, 'base64'));
      return Buffer.concat([d.update(Buffer.from(data, 'base64')), d.final()]).toString('utf8');
    },
  };
}
