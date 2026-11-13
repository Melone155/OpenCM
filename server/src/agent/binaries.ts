import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

export const AGENT_OS = ['windows', 'linux', 'macos'] as const;
export const AGENT_ARCH = ['amd64', 'arm64'] as const;
export type AgentOs = (typeof AGENT_OS)[number];
export type AgentArch = (typeof AGENT_ARCH)[number];

const FILE_RE = /^opencm-agent-(windows|linux|darwin|macos)-(amd64|arm64)(\.exe)?$/;

export interface AgentBinary {
  os: AgentOs;
  arch: AgentArch;
  file: string;
  path: string;
  sizeBytes: number;
  sha256: string;
}

/**
 * Agent binaries placed in AGENT_DOWNLOAD_DIR by the release pipeline
 * (opencm-agent-<goos>-<goarch>[.exe], optional version.txt).
 */
export class AgentBinaries {
  private shaCache = new Map<string, { mtimeMs: number; sha256: string }>();
  private dir: string;
  constructor(dir: string) {
    this.dir = dir;
  }

  private async sha256(path: string, mtimeMs: number): Promise<string> {
    const hit = this.shaCache.get(path);
    if (hit && hit.mtimeMs === mtimeMs) return hit.sha256;
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
    const sha = hash.digest('hex');
    this.shaCache.set(path, { mtimeMs, sha256: sha });
    return sha;
  }

  async scan(): Promise<{ version: string | null; items: AgentBinary[] }> {
    let names: string[];
    try {
      names = await readdir(this.dir);
    } catch {
      return { version: null, items: [] };
    }
    const version = await readFile(join(this.dir, 'version.txt'), 'utf8').then((s) => s.trim() || null, () => null);
    const items: AgentBinary[] = [];
    for (const file of names) {
      const m = FILE_RE.exec(file);
      if (!m) continue;
      const path = join(this.dir, file);
      const st = await stat(path);
      items.push({
        os: m[1] === 'darwin' ? 'macos' : (m[1] as AgentOs),
        arch: m[2] as AgentArch,
        file,
        path,
        sizeBytes: st.size,
        sha256: await this.sha256(path, st.mtimeMs),
      });
    }
    items.sort((a, b) => `${a.os}${a.arch}`.localeCompare(`${b.os}${b.arch}`));
    return { version, items };
  }

  async find(os: string, arch: string): Promise<{ version: string | null; binary: AgentBinary | null }> {
    const { version, items } = await this.scan();
    return { version, binary: items.find((b) => b.os === os && b.arch === arch) ?? null };
  }
}
