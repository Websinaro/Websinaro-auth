import type { RedisAdapter } from '../types/index.js';

// ─── IoRedis Adapter ─────────────────────────────────────────
// Wraps ioredis into the RedisAdapter interface.
// Recommended for all production deployments.

// Lightweight interface so we don't hard-depend on ioredis types
interface IoRedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  set(key: string, value: string, ex: 'EX', seconds: number): Promise<unknown>;
  del(key: string): Promise<number>;
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  exists(key: string): Promise<number>;
  keys(pattern: string): Promise<string[]>;
}

export class IoRedisAdapter implements RedisAdapter {
  private readonly client: IoRedisLike;

  constructor(client: IoRedisLike) {
    this.client = client;
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds !== undefined) {
      await this.client.set(key, value, 'EX', ttlSeconds);
    } else {
      await this.client.set(key, value);
    }
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async incr(key: string): Promise<number> {
    return this.client.incr(key);
  }

  async expire(key: string, ttlSeconds: number): Promise<void> {
    await this.client.expire(key, ttlSeconds);
  }

  async exists(key: string): Promise<boolean> {
    const count = await this.client.exists(key);
    return count > 0;
  }

  async keys(pattern: string): Promise<string[]> {
    return this.client.keys(pattern);
  }
}

export { type RedisAdapter };
