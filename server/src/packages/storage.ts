import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, rename, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { Transform, type Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { HttpError } from '../http.ts';

const SHA256 = /^[0-9a-f]{64}$/;

/** Content-addressed file store for installer files: <dir>/<sha256>. */
export class PackageStore {
  readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
  }

  path(sha256: string): string {
    if (!SHA256.test(sha256)) throw new HttpError(400, 'validation_error', 'Invalid file hash');
    return join(this.dir, sha256);
  }

  async exists(sha256: string): Promise<boolean> {
    try {
      return (await stat(this.path(sha256))).isFile();
    } catch {
      return false;
    }
  }

  /** Streams an upload to disk while hashing; enforces maxBytes. Deduplicates by hash. */
  async save(input: Readable, maxBytes: number): Promise<{ sha256: string; sizeBytes: number }> {
    await mkdir(this.dir, { recursive: true });
    const tmp = join(this.dir, `.upload-${randomBytes(8).toString('hex')}`);
    const hash = createHash('sha256');
    let size = 0;
    const meter = new Transform({
      transform(chunk: Buffer, _enc, cb) {
        size += chunk.length;
        if (size > maxBytes) return cb(new HttpError(413, 'file_too_large', `File exceeds ${maxBytes} bytes`));
        hash.update(chunk);
        cb(null, chunk);
      },
    });
    try {
      await pipeline(input, meter, createWriteStream(tmp, { mode: 0o640 }));
    } catch (err) {
      await rm(tmp, { force: true });
      throw err;
    }
    if (size === 0) {
      await rm(tmp, { force: true });
      throw new HttpError(400, 'validation_error', 'Empty file');
    }
    const sha256 = hash.digest('hex');
    if (await this.exists(sha256)) await rm(tmp, { force: true });
    else await rename(tmp, this.path(sha256));
    return { sha256, sizeBytes: size };
  }

  /** Re-hashes the stored file: true only if it still matches its name (= hash at upload). */
  async verify(sha256: string): Promise<boolean> {
    if (!(await this.exists(sha256))) return false;
    const hash = createHash('sha256');
    await pipeline(createReadStream(this.path(sha256)), hash);
    return hash.digest('hex') === sha256;
  }

  async remove(sha256: string): Promise<void> {
    await rm(this.path(sha256), { force: true });
  }
}
