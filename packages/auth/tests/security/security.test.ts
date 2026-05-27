import { describe, it, expect, beforeEach } from 'vitest';
import { AuthShield } from '../../src/core/auth-shield.js';
import { MemoryAdapter } from '../../src/adapters/memory.js';
import { PasswordService } from '../../src/security/password.js';
import { CsrfService } from '../../src/security/csrf.js';
import { RateLimiter } from '../../src/security/rate-limiter.js';
import { SecurityError, RateLimitError } from '../../src/errors/index.js';
import type { AuthShieldConfig } from '../../src/types/index.js';

const adapter = new MemoryAdapter();

const config: AuthShieldConfig = {
  accessTokenSecret: 'test-access-secret-must-be-at-least-32-chars-long',
  refreshTokenSecret: 'test-refresh-secret-must-be-at-least-32-chars-long',
  issuer: 'test-issuer',
  audience: 'test-audience',
  adapter,
  enableAuditLog: false,
  maxLoginAttempts: 5,
  lockDurationSeconds: 900,
};

const meta = { ip: '1.2.3.4', userAgent: 'test-agent' };

// ─── Password Security ───────────────────────────────────────

describe('PasswordService', () => {
  const svc = new PasswordService();

  it('hashes and verifies a password', async () => {
    const hash = await svc.hash('MySecurePass1');
    expect(await svc.verify('MySecurePass1', hash)).toBe(true);
    expect(await svc.verify('WrongPassword1', hash)).toBe(false);
  });

  it('produces different hashes for the same password (unique salt)', async () => {
    const h1 = await svc.hash('SamePassword1');
    const h2 = await svc.hash('SamePassword1');
    expect(h1).not.toBe(h2);
  });

  it('detects breached/common passwords', () => {
    expect(svc.isBreached('password123')).toBe(true);
    expect(svc.isBreached('qwerty')).toBe(true);
    expect(svc.isBreached('MyVery$ecureP@ss9')).toBe(false);
  });

  it('validates password strength', () => {
    expect(svc.validateStrength('abc', 8)).toMatch(/at least 8/);
    expect(svc.validateStrength('alllettersnodigits', 8)).toMatch(/number/);
    expect(svc.validateStrength('12345678', 8)).toMatch(/letter/);
    expect(svc.validateStrength('password123', 8)).toMatch(/common/);
    expect(svc.validateStrength('SecurePass1', 8)).toBeNull();
  });

  it('timing-safe compare returns correct result', () => {
    expect(svc.safeCompare('abc', 'abc')).toBe(true);
    expect(svc.safeCompare('abc', 'xyz')).toBe(false);
    expect(svc.safeCompare('short', 'much-longer-string')).toBe(false);
  });

  it('never exposes the original password in the hash', async () => {
    const plaintext = 'SuperSecret42';
    const hash = await svc.hash(plaintext);
    expect(hash).not.toContain(plaintext);
  });
});

// ─── CSRF ────────────────────────────────────────────────────

describe('CsrfService', () => {
  const csrf = new CsrfService('a-very-strong-master-secret-thats-32-chars');

  it('generates and verifies a valid CSRF token', () => {
    const { token, secret } = csrf.generate();
    expect(() => csrf.verify(token, secret)).not.toThrow();
  });

  it('rejects a tampered token', () => {
    const { secret } = csrf.generate();
    expect(() =>
      csrf.verify('0000000000000000000000000000000000000000000000000000000000000000', secret),
    ).toThrow(SecurityError);
  });

  it('rejects an empty token', () => {
    const { secret } = csrf.generate();
    expect(() => csrf.verify('', secret)).toThrow(SecurityError);
  });

  it('rejects token verified against wrong secret', () => {
    const { token } = csrf.generate();
    const { secret: otherSecret } = csrf.generate();
    expect(() => csrf.verify(token, otherSecret)).toThrow(SecurityError);
  });

  it('throws on short master secret', () => {
    expect(() => new CsrfService('short')).toThrow();
  });
});

// ─── Rate Limiter ────────────────────────────────────────────

describe('RateLimiter (memory)', () => {
  it('allows requests within the limit', async () => {
    const rl = new RateLimiter({ maxAttempts: 5, windowSeconds: 60, blockDurationSeconds: 300 });
    for (let i = 0; i < 5; i++) {
      await expect(rl.check('test-key')).resolves.not.toThrow();
    }
  });

  it('blocks after exceeding maxAttempts', async () => {
    const rl = new RateLimiter({ maxAttempts: 3, windowSeconds: 60, blockDurationSeconds: 300 });
    for (let i = 0; i < 3; i++) {
      await rl.check('block-key').catch(() => {});
    }
    await expect(rl.check('block-key')).rejects.toBeInstanceOf(RateLimitError);
  });

  it('resets the counter after reset()', async () => {
    const rl = new RateLimiter({ maxAttempts: 2, windowSeconds: 60, blockDurationSeconds: 300 });
    for (let i = 0; i < 2; i++) {
      await rl.check('reset-key').catch(() => {});
    }
    await rl.reset('reset-key');
    await expect(rl.check('reset-key')).resolves.not.toThrow();
  });
});

// ─── Token Reuse / Replay Protection ────────────────────────

describe('Token reuse protection', () => {
  beforeEach(() => adapter._clear());

  it('revokes all sessions on refresh token reuse detection', async () => {
    const auth = new AuthShield(config);

    await auth.register({ email: 'reuse@example.com', password: 'SecurePass1' }, meta);
    const loginResult = await auth.login({
      email: 'reuse@example.com',
      password: 'SecurePass1',
      ipAddress: '1.2.3.4',
      userAgent: 'agent',
    });
    expect(loginResult.success).toBe(true);
    if (!loginResult.success) return;

    const refreshInput = {
      refreshToken: loginResult.data.refreshToken,
      ipAddress: '1.2.3.4',
      userAgent: 'agent',
    };

    // First use is fine
    await auth.refresh(refreshInput);

    // Second use of the same token triggers reuse detection
    await expect(auth.refresh(refreshInput)).rejects.toMatchObject({
      code: 'TOKEN_REUSE_DETECTED',
    });

    // All sessions should now be revoked — even a fresh login followed by
    // an attempt to use the old refresh should fail
    const sessions = await auth.listSessions(loginResult.data.user.id);
    expect(sessions.length).toBe(0);
  });
});

// ─── Account Lockout ─────────────────────────────────────────

describe('Account lockout', () => {
  beforeEach(() => adapter._clear());

  it('locks account and emits event after max failed attempts', async () => {
    const auth = new AuthShield({ ...config, maxLoginAttempts: 3 });
    const events: string[] = [];

    auth.on('user.locked', () => events.push('locked'));
    auth.on('user.login_failed', () => events.push('failed'));

    await auth.register({ email: 'lock@example.com', password: 'SecurePass1' }, meta);

    for (let i = 0; i < 3; i++) {
      await auth
        .login({ email: 'lock@example.com', password: 'Bad1', ipAddress: '1.2.3.4', userAgent: 'a' })
        .catch(() => {});
    }

    expect(events).toContain('locked');
    expect(events.filter((e) => e === 'failed').length).toBe(3);
  });
});

// ─── Password Reset (no user enumeration) ───────────────────

describe('Password reset security', () => {
  beforeEach(() => adapter._clear());

  it('returns success even for non-existent email (no enumeration)', async () => {
    const auth = new AuthShield(config);
    // Should NOT throw — must not reveal whether user exists
    const result = await auth.requestPasswordReset({ email: 'ghost@example.com' }, meta);
    expect(result.success).toBe(true);
  });
});

// ─── Event System ────────────────────────────────────────────

describe('AuthShield event system', () => {
  beforeEach(() => adapter._clear());

  it('emits user.registered on successful registration', async () => {
    const auth = new AuthShield(config);
    let emitted = false;
    auth.on('user.registered', () => { emitted = true; });

    await auth.register({ email: 'event@example.com', password: 'SecurePass1' }, meta);
    expect(emitted).toBe(true);
  });

  it('emits user.login on successful login', async () => {
    const auth = new AuthShield(config);
    let sessionId: string | undefined;
    auth.on('user.login', (payload) => { sessionId = payload.sessionId; });

    await auth.register({ email: 'login-event@example.com', password: 'SecurePass1' }, meta);
    await auth.login({ email: 'login-event@example.com', password: 'SecurePass1', ipAddress: '1.2.3.4', userAgent: 'a' });

    expect(sessionId).toBeDefined();
  });

  it('emits user.login_failed on wrong password', async () => {
    const auth = new AuthShield(config);
    let reason: string | undefined;
    auth.on('user.login_failed', (p) => { reason = p.reason; });

    await auth.register({ email: 'fail@example.com', password: 'SecurePass1' }, meta);
    await auth.login({ email: 'fail@example.com', password: 'WrongPass1', ipAddress: '1.2.3.4', userAgent: 'a' }).catch(() => {});

    expect(reason).toBe('INVALID_CREDENTIALS');
  });
});
