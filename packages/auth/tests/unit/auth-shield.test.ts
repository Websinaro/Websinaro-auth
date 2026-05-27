import { describe, it, expect, beforeEach } from 'vitest';
import { AuthShield } from '../../src/core/auth-shield.js';
import { MemoryAdapter } from '../../src/adapters/memory.js';
import { AuthError, ValidationError, RateLimitError } from '../../src/errors/index.js';
import type { AuthShieldConfig } from '../../src/types/index.js';

// ─── Shared test config ──────────────────────────────────────

const adapter = new MemoryAdapter();

const config: AuthShieldConfig = {
  accessTokenSecret: 'test-access-secret-must-be-at-least-32-chars-long',
  refreshTokenSecret: 'test-refresh-secret-must-be-at-least-32-chars-long',
  issuer: 'test-issuer',
  audience: 'test-audience',
  adapter,
  requireEmailVerification: false,
  enableAuditLog: false,
  maxLoginAttempts: 3,
  lockDurationSeconds: 60,
};

const meta = { ip: '127.0.0.1', userAgent: 'vitest' };

function createAuth(overrides: Partial<AuthShieldConfig> = {}) {
  return new AuthShield({ ...config, ...overrides });
}

// ─── Register ────────────────────────────────────────────────

describe('AuthShield.register', () => {
  beforeEach(() => adapter._clear());

  it('registers a new user successfully', async () => {
    const auth = createAuth();
    const result = await auth.register(
      { email: 'user@example.com', password: 'SecurePass1' },
      meta,
    );
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data.user.email).toBe('user@example.com');
    expect((result.data.user as any).passwordHash).toBeUndefined();
  });

  it('normalizes email to lowercase', async () => {
    const auth = createAuth();
    const result = await auth.register(
      { email: 'User@EXAMPLE.COM', password: 'SecurePass1' },
      meta,
    );
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data.user.email).toBe('user@example.com');
  });

  it('rejects duplicate email', async () => {
    const auth = createAuth();
    await auth.register({ email: 'dup@example.com', password: 'SecurePass1' }, meta);
    await expect(
      auth.register({ email: 'dup@example.com', password: 'SecurePass1' }, meta),
    ).rejects.toMatchObject({ code: 'USER_ALREADY_EXISTS' });
  });

  it('rejects weak password', async () => {
    const auth = createAuth();
    await expect(
      auth.register({ email: 'w@example.com', password: 'password123' }, meta),
    ).rejects.toMatchObject({ code: 'PASSWORD_TOO_WEAK' });
  });

  it('rejects short password based on config', async () => {
    const auth = createAuth({ passwordMinLength: 12 });
    await expect(
      auth.register({ email: 'x@example.com', password: 'Short1' }, meta),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it('rejects invalid email', async () => {
    const auth = createAuth();
    await expect(
      auth.register({ email: 'not-an-email', password: 'SecurePass1' }, meta),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it('issues verification token when requireEmailVerification is true', async () => {
    const auth = createAuth({ requireEmailVerification: true });
    const result = await auth.register(
      { email: 'verify@example.com', password: 'SecurePass1' },
      meta,
    );
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data.verificationToken).toBeDefined();
    expect(typeof result.data.verificationToken).toBe('string');
  });
});

// ─── Login ───────────────────────────────────────────────────

describe('AuthShield.login', () => {
  beforeEach(() => adapter._clear());

  async function registerUser(auth: AuthShield) {
    return auth.register({ email: 'login@example.com', password: 'SecurePass1' }, meta);
  }

  it('logs in with correct credentials', async () => {
    const auth = createAuth();
    await registerUser(auth);

    const result = await auth.login({
      email: 'login@example.com',
      password: 'SecurePass1',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    });

    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data.accessToken).toBeDefined();
    expect(result.data.refreshToken).toBeDefined();
    expect(result.data.sessionId).toBeDefined();
  });

  it('rejects wrong password', async () => {
    const auth = createAuth();
    await registerUser(auth);

    await expect(
      auth.login({
        email: 'login@example.com',
        password: 'WrongPassword1',
        ipAddress: '127.0.0.1',
        userAgent: 'test',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });

  it('rejects non-existent user', async () => {
    const auth = createAuth();
    await expect(
      auth.login({
        email: 'ghost@example.com',
        password: 'SecurePass1',
        ipAddress: '127.0.0.1',
        userAgent: 'test',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });

  it('locks account after maxLoginAttempts failures', async () => {
    const auth = createAuth();
    await registerUser(auth);

    for (let i = 0; i < 3; i++) {
      await auth.login({
        email: 'login@example.com',
        password: 'WrongPassword1',
        ipAddress: '127.0.0.1',
        userAgent: 'test',
      }).catch(() => {});
    }

    await expect(
      auth.login({
        email: 'login@example.com',
        password: 'SecurePass1',
        ipAddress: '127.0.0.1',
        userAgent: 'test',
      }),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LOCKED' });
  });

  it('blocks unverified email if requireEmailVerification is true', async () => {
    const auth = createAuth({ requireEmailVerification: true });
    await registerUser(auth);

    await expect(
      auth.login({
        email: 'login@example.com',
        password: 'SecurePass1',
        ipAddress: '127.0.0.1',
        userAgent: 'test',
      }),
    ).rejects.toMatchObject({ code: 'EMAIL_NOT_VERIFIED' });
  });
});

// ─── Token Refresh ───────────────────────────────────────────

describe('AuthShield.refresh', () => {
  beforeEach(() => adapter._clear());

  async function loginUser(auth: AuthShield) {
    await auth.register({ email: 'refresh@example.com', password: 'SecurePass1' }, meta);
    return auth.login({
      email: 'refresh@example.com',
      password: 'SecurePass1',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    });
  }

  it('issues a new token pair from a valid refresh token', async () => {
    const auth = createAuth();
    const loginResult = await loginUser(auth);
    expect(loginResult.success).toBe(true);
    if (!loginResult.success) return;

    const refreshResult = await auth.refresh({
      refreshToken: loginResult.data.refreshToken,
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    });

    expect(refreshResult.success).toBe(true);
    if (!refreshResult.success) return;
    expect(refreshResult.data.accessToken).toBeDefined();
    expect(refreshResult.data.accessToken).not.toBe(loginResult.data.accessToken);
  });

  it('detects refresh token reuse', async () => {
    const auth = createAuth();
    const loginResult = await loginUser(auth);
    expect(loginResult.success).toBe(true);
    if (!loginResult.success) return;

    const refreshInput = {
      refreshToken: loginResult.data.refreshToken,
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    };

    // First refresh succeeds
    await auth.refresh(refreshInput);

    // Second refresh with same token should fail (TOKEN_REUSE_DETECTED)
    await expect(auth.refresh(refreshInput)).rejects.toMatchObject({
      code: 'TOKEN_REUSE_DETECTED',
    });
  });
});

// ─── Access Token Verification ───────────────────────────────

describe('AuthShield.verifyAccessToken', () => {
  beforeEach(() => adapter._clear());

  it('verifies a valid access token', async () => {
    const auth = createAuth();
    await auth.register({ email: 'verify@example.com', password: 'SecurePass1' }, meta);
    const loginResult = await auth.login({
      email: 'verify@example.com',
      password: 'SecurePass1',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    });
    expect(loginResult.success).toBe(true);
    if (!loginResult.success) return;

    const payload = await auth.verifyAccessToken(loginResult.data.accessToken);
    expect(payload.email).toBe('verify@example.com');
    expect(payload.sub).toBeDefined();
  });

  it('rejects invalid token', async () => {
    const auth = createAuth();
    await expect(auth.verifyAccessToken('invalid.token.here')).rejects.toMatchObject({
      code: 'TOKEN_INVALID',
    });
  });

  it('rejects token signed with wrong secret', async () => {
    const auth1 = createAuth();
    const auth2 = createAuth({
      accessTokenSecret: 'different-access-secret-must-be-at-least-32-chars',
    });

    await auth1.register({ email: 'cross@example.com', password: 'SecurePass1' }, meta);
    const loginResult = await auth1.login({
      email: 'cross@example.com',
      password: 'SecurePass1',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    });
    expect(loginResult.success).toBe(true);
    if (!loginResult.success) return;

    await expect(auth2.verifyAccessToken(loginResult.data.accessToken)).rejects.toMatchObject({
      code: 'TOKEN_INVALID',
    });
  });
});

// ─── RBAC ────────────────────────────────────────────────────

describe('AuthShield RBAC', () => {
  it('checks roles correctly', () => {
    const auth = createAuth({
      rbac: {
        roles: {
          admin: { name: 'admin', permissions: ['users.delete', 'posts.delete'] },
          editor: { name: 'editor', permissions: ['posts.edit'], inherits: [] },
          viewer: { name: 'viewer', permissions: ['posts.read'], inherits: [] },
        },
      },
    });

    expect(auth.hasRole(['admin'], 'admin')).toBe(true);
    expect(auth.hasRole(['editor'], 'admin')).toBe(false);
  });

  it('checks permissions via roles', () => {
    const auth = createAuth({
      rbac: {
        roles: {
          admin: { name: 'admin', permissions: ['users.delete', 'posts.delete'] },
          editor: { name: 'editor', permissions: ['posts.edit'], inherits: ['viewer'] },
          viewer: { name: 'viewer', permissions: ['posts.read'] },
        },
      },
    });

    // editor inherits viewer's posts.read
    expect(auth.hasPermission(['editor'], [], 'posts.read')).toBe(true);
    expect(auth.hasPermission(['editor'], [], 'users.delete')).toBe(false);
  });
});

// ─── Configuration Guard ─────────────────────────────────────

describe('AuthShield startup validation', () => {
  it('throws ConfigurationError if accessTokenSecret is missing', () => {
    expect(
      () =>
        new AuthShield({
          ...config,
          accessTokenSecret: '',
        }),
    ).toThrow();
  });

  it('throws ConfigurationError if refreshTokenSecret is missing', () => {
    expect(
      () =>
        new AuthShield({
          ...config,
          refreshTokenSecret: '',
        }),
    ).toThrow();
  });
});
