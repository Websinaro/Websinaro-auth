import argon2 from 'argon2';
import crypto from 'node:crypto';
import { AuthError } from '../errors/index.js';

// ─── Password Hasher ─────────────────────────────────────────
// Uses Argon2id — winner of the Password Hashing Competition.
// Argon2id is memory-hard, resistant to GPU attacks and side channels.

export interface HashOptions {
  memoryCost?: number;  // KiB, default 65536 (64 MiB)
  timeCost?: number;    // iterations, default 3
  parallelism?: number; // threads, default 4
}

const DEFAULTS: Required<HashOptions> = {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
};

// Common passwords — first line of breach detection
// In production, integrate with HaveIBeenPwned API
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '12345678', '123456789',
  'qwerty', 'qwerty123', 'letmein', 'letmein123', 'admin', 'admin123',
  'welcome', 'welcome1', 'monkey', 'dragon', 'master', 'sunshine',
]);

export class PasswordService {
  private readonly options: Required<HashOptions>;

  constructor(options: HashOptions = {}) {
    this.options = { ...DEFAULTS, ...options };
  }

  async hash(password: string): Promise<string> {
    // Argon2 generates a unique salt internally — no need to manage it separately
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: this.options.memoryCost,
      timeCost: this.options.timeCost,
      parallelism: this.options.parallelism,
    });
  }

  async verify(password: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }

  /**
   * Check if a password appears in the common-passwords list.
   * Extend this to call the HaveIBeenPwned k-anonymity API in production.
   */
  isBreached(password: string): boolean {
    return COMMON_PASSWORDS.has(password.toLowerCase());
  }

  /**
   * Timing-safe string comparison using Node's built-in.
   * Prevents timing attacks when comparing secrets.
   */
  safeCompare(a: string, b: string): boolean {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) {
      // Run the comparison anyway to keep timing constant
      crypto.timingSafeEqual(bufA, bufA);
      return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
  }

  /**
   * Validate password strength before hashing.
   * Returns null if valid, or an error message string.
   */
  validateStrength(password: string, minLength: number): string | null {
    if (password.length < minLength) {
      return `Password must be at least ${minLength} characters`;
    }
    if (password.length > 128) {
      return 'Password must not exceed 128 characters';
    }
    if (this.isBreached(password)) {
      return 'This password is too common and easily guessed. Please choose a stronger password.';
    }
    // Require at least one letter and one number for basic complexity
    if (!/[a-zA-Z]/.test(password)) {
      return 'Password must contain at least one letter';
    }
    if (!/[0-9]/.test(password)) {
      return 'Password must contain at least one number';
    }
    return null;
  }

  /**
   * Throw if strength validation fails.
   */
  assertStrength(password: string, minLength: number): void {
    const error = this.validateStrength(password, minLength);
    if (error) {
      throw new AuthError('PASSWORD_TOO_WEAK', error, 422);
    }
  }
}
