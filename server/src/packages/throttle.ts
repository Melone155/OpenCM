import { Transform, type TransformCallback } from 'node:stream';

export interface Clock {
  now(): number;
  sleep(ms: number): Promise<void>;
}

export const realClock: Clock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

/**
 * Token bucket in bytes. rate 0 = unlimited. Burst is one second worth of tokens,
 * so a fresh bucket does not send unlimited data at once.
 */
export class TokenBucket {
  private tokens: number;
  private last: number;
  readonly rate: number;
  private readonly clock: Clock;
  constructor(bytesPerSecond: number, clock: Clock = realClock) {
    this.rate = bytesPerSecond;
    this.clock = clock;
    this.tokens = bytesPerSecond;
    this.last = clock.now();
  }

  private refill() {
    const now = this.clock.now();
    this.tokens = Math.min(this.rate, this.tokens + ((now - this.last) / 1000) * this.rate);
    this.last = now;
  }

  /** Waits until `n` bytes may be sent (n is capped to the burst size by the caller). */
  async take(n: number): Promise<void> {
    if (this.rate <= 0) return;
    for (;;) {
      this.refill();
      if (this.tokens >= n) {
        this.tokens -= n;
        return;
      }
      await this.clock.sleep(Math.max(1, Math.ceil(((n - this.tokens) / this.rate) * 1000)));
    }
  }
}

/** Throttles a stream through all given buckets (e.g. global + per device). */
export function throttle(buckets: TokenBucket[]): Transform {
  const active = buckets.filter((b) => b.rate > 0);
  const slice = active.length ? Math.max(1024, Math.min(64 * 1024, ...active.map((b) => Math.floor(b.rate / 4)))) : Infinity;
  return new Transform({
    transform(chunk: Buffer, _enc, cb: TransformCallback) {
      if (!active.length) return cb(null, chunk);
      void (async () => {
        try {
          for (let off = 0; off < chunk.length; off += slice) {
            const part = chunk.subarray(off, Math.min(chunk.length, off + slice));
            for (const b of active) await b.take(Math.min(part.length, b.rate));
            this.push(part);
          }
          cb();
        } catch (err) {
          cb(err as Error);
        }
      })();
    },
  });
}

/** Shared buckets: one global, one per device (created lazily, dropped when idle). */
export class BandwidthLimiter {
  readonly global: TokenBucket;
  private readonly perDeviceRate: number;
  private readonly devices = new Map<string, { bucket: TokenBucket; users: number }>();
  private readonly clock: Clock;
  constructor(globalKbps: number, perDeviceKbps: number, clock: Clock = realClock) {
    this.clock = clock;
    this.global = new TokenBucket(globalKbps * 1024, clock);
    this.perDeviceRate = perDeviceKbps * 1024;
  }

  /** Returns a throttling transform for one download and a release function. */
  acquire(deviceId: string): { stream: Transform; release: () => void } {
    let entry = this.devices.get(deviceId);
    if (!entry) {
      entry = { bucket: new TokenBucket(this.perDeviceRate, this.clock), users: 0 };
      this.devices.set(deviceId, entry);
    }
    entry.users++;
    const e = entry;
    let released = false;
    return {
      stream: throttle([this.global, e.bucket]),
      release: () => {
        if (released) return;
        released = true;
        e.users--;
        if (e.users <= 0) this.devices.delete(deviceId);
      },
    };
  }
}
