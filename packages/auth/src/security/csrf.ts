import crypto from 'node:crypto';
import { SecurityError } from '../errors/index.js';

// ─── CSRF Service ────────────────────────────────────────────
// Uses double-submit HMAC pattern.
// 1. Server generates a random secret stored in a HttpOnly cookie.
// 2. Server also gives the HMAC-SHA256(masterSecret, randomSecret) as the CSRF token.
// 3. Client sends the CSRF token in a header on each mutating request.
// 4. Server recomputes the HMAC and compares with timing-safe equal.

export class CsrfService {
  private readonly masterSecret: string;

  constructor(masterSecret: string) {
    if (!masterSecret || masterSecret.length < 32) {
      throw new Error('[CsrfService] masterSecret must be at least 32 characters');
    }
    this.masterSecret = masterSecret;
  }

  /**
   * Generate a new CSRF token pair.
   * - `secret`: store in a HttpOnly, Secure, SameSite=Strict cookie
   * - `token`: send in response body / header for the client to submit back
   */
  generate(): { token: string; secret: string } {
    const secret = crypto.randomBytes(32).toString('hex');
    const token = this.sign(secret);
    return { token, secret };
  }

  /**
   * Verify the submitted CSRF token against the stored cookie secret.
   * Throws SecurityError on failure.
   */
  verify(submittedToken: string, storedSecret: string): void {
    if (!submittedToken || !storedSecret) {
      throw new SecurityError('CSRF_INVALID', 'CSRF token missing or invalid.');
    }

    const expected = this.sign(storedSecret);

    // Both must be equal-length hex strings for timingSafeEqual
    let tokBuf: Buffer, expBuf: Buffer;
    try {
      tokBuf = Buffer.from(submittedToken, 'hex');
      expBuf = Buffer.from(expected, 'hex');
    } catch {
      throw new SecurityError('CSRF_INVALID', 'CSRF token format invalid.');
    }

    if (tokBuf.length !== expBuf.length) {
      // Maintain constant time
      crypto.timingSafeEqual(expBuf, expBuf);
      throw new SecurityError('CSRF_INVALID', 'CSRF token invalid.');
    }

    const valid = crypto.timingSafeEqual(tokBuf, expBuf);
    if (!valid) {
      throw new SecurityError('CSRF_INVALID', 'CSRF token invalid.');
    }
  }

  private sign(secret: string): string {
    return crypto.createHmac('sha256', this.masterSecret).update(secret).digest('hex');
  }
}
