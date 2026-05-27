import type { RedisAdapter } from '../types/index.js';
import { RateLimitError } from '../errors/index.js';

// ─── Rate Limiter ────────────────────────────────────────────
// Sliding window algorithm. Supports:
//   - In-memory (single server, dev/test)
//   - Redis (distributed, production)

export interface RateLimitConfig {
  maxAttempts: number;
  windowSeconds: number;
  blockDurationSeconds: number;
}

interface MemoryRecord {
  attempts: number;
  windowStart: number;
  blockedUntil: number;
}

export class RateLimiter {
  private readonly redis: RedisAdapter | null;
  private readonly memStore = new Map<string, MemoryRecord>();
  private readonly config: RateLimitConfig;

  constructor(config: RateLimitConfig, redis?: RedisAdapter) {
    this.config = config;
    this.redis = redis ?? null;
  }

  /**
   * Check and record a rate-limit hit for a given key.
   * Throws RateLimitError if the limit is exceeded.
   */
  async check(key: string): Promise<void> {
    if (this.redis) {
      await this.checkRedis(key);
    } else {
      this.checkMemory(key);
    }
  }

  /**
   * Reset the rate limit counter for a key (e.g. after successful login).
   */
  async reset(key: string): Promise<void> {
    if (this.redis) {
      await this.redis.del(`rl:${key}`);
      await this.redis.del(`rl:block:${key}`);
    } else {
      this.memStore.delete(key);
    }
  }

  // ─── Redis (distributed) ─────────────────────────────────

  private async checkRedis(key: string): Promise<void> {
    const blockKey = `rl:block:${key}`;
    const countKey = `rl:${key}`;

    // Check if blocked
    const blocked = await this.redis!.exists(blockKey);
    if (blocked) {
      const ttlRaw = await this.redis!.get(blockKey);
      const retryAfter = ttlRaw ? parseInt(ttlRaw, 10) : this.config.blockDurationSeconds;
      throw new RateLimitError(retryAfter);
    }

    // Sliding window: increment counter
    const count = await this.redis!.incr(countKey);

    if (count === 1) {
      // First hit — set window expiry
      await this.redis!.expire(countKey, this.config.windowSeconds);
    }

    if (count > this.config.maxAttempts) {
      // Block the key
      await this.redis!.set(
        blockKey,
        String(this.config.blockDurationSeconds),
        this.config.blockDurationSeconds,
      );
      throw new RateLimitError(this.config.blockDurationSeconds);
    }
  }

  // ─── Memory (single server) ──────────────────────────────

  private checkMemory(key: string): void {
    const now = Date.now();
    let record = this.memStore.get(key);

    // Check if blocked
    if (record && record.blockedUntil > now) {
      const retryAfter = Math.ceil((record.blockedUntil - now) / 1000);
      throw new RateLimitError(retryAfter);
    }

    // Reset if window expired
    if (!record || now - record.windowStart > this.config.windowSeconds * 1000) {
      record = { attempts: 0, windowStart: now, blockedUntil: 0 };
    }

    record.attempts++;

    if (record.attempts > this.config.maxAttempts) {
      record.blockedUntil = now + this.config.blockDurationSeconds * 1000;
      this.memStore.set(key, record);
      throw new RateLimitError(this.config.blockDurationSeconds);
    }

    this.memStore.set(key, record);
  }
}
