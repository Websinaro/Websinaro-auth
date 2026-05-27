import { describe, it, expect, beforeEach } from 'vitest';
import { AuthShield } from '../../src/core/auth-shield.js';
import { MemoryAdapter } from '../../src/adapters/memory.js';
import type { AuthShieldConfig } from '../../src/types/index.js';

// ─── Integration: Full Auth Lifecycle ────────────────────────
// Tests a realistic end-to-end flow: register → verify email →
// login → use token → refresh → logout → token invalid

const adapter = new MemoryAdapter();

const config: AuthShieldConfig = {
  accessTokenSecret: 'integration-access-secret-32-chars-minimum-length',
  refreshTokenSecret: 'integration-refresh-secret-32-chars-minimum-length',
  issuer: 'integration-tests',
  audience: ['api'],
  adapter,
  enableAuditLog: false,
  requireEmailVerification: false,
  rbac: {
    defaultRole: 'user',
    roles: {
      admin: {
        name: 'admin',
        permissions: ['users.manage', 'posts.delete'],
        inherits: ['user'],
      },
      user: {
        name: 'user',
        permissions: ['posts.read', 'posts.create'],
      },
    },
  },
};

const meta = { ip: '10.0.0.1', userAgent: 'integration-test/1.0' };

beforeEach(() => adapter._clear());

describe('Full auth lifecycle', () => {
  it('register → login → refresh → logout', async () => {
    const auth = new AuthShield(config);

    // 1. Register
    const reg = await auth.register({ email: 'alice@example.com', password: 'AlicePass1' }, meta);
    expect(reg.success).toBe(true);
    if (!reg.success) return;
    const userId = reg.data.user.id;
    expect(userId).toBeDefined();

    // 2. Login
    const login = await auth.login({
      email: 'alice@example.com',
      password: 'AlicePass1',
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
    });
    expect(login.success).toBe(true);
    if (!login.success) return;

    const { accessToken, refreshToken, sessionId } = login.data;

    // 3. Verify access token
    const payload = await auth.verifyAccessToken(accessToken);
    expect(payload.sub).toBe(userId);
    expect(payload.email).toBe('alice@example.com');
    expect(payload.roles).toContain('user');

    // 4. Check default role permissions
    expect(auth.hasPermission(payload.roles, payload.permissions, 'posts.read')).toBe(true);
    expect(auth.hasPermission(payload.roles, payload.permissions, 'users.manage')).toBe(false);

    // 5. Refresh tokens
    const refresh = await auth.refresh({
      refreshToken,
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
    });
    expect(refresh.success).toBe(true);
    if (!refresh.success) return;
    expect(refresh.data.accessToken).not.toBe(accessToken);

    // 6. Old access token still valid (not revoked — only refresh token is rotated)
    const oldPayload = await auth.verifyAccessToken(accessToken);
    expect(oldPayload.sub).toBe(userId);

    // 7. Logout
    const logout = await auth.logout({ sessionId, userId }, meta);
    expect(logout.success).toBe(true);

    // 8. Session list should be empty
    const sessions = await auth.listSessions(userId);
    expect(sessions.length).toBe(0);
  });
});

describe('Email verification flow', () => {
  it('blocks login until email is verified', async () => {
    const auth = new AuthShield({ ...config, requireEmailVerification: true });

    const reg = await auth.register({ email: 'bob@example.com', password: 'BobPass123' }, meta);
    expect(reg.success).toBe(true);
    if (!reg.success) return;

    const verificationToken = reg.data.verificationToken;
    expect(verificationToken).toBeDefined();

    // Login before verification should fail
    await expect(
      auth.login({
        email: 'bob@example.com',
        password: 'BobPass123',
        ipAddress: meta.ip,
        userAgent: meta.userAgent,
      }),
    ).rejects.toMatchObject({ code: 'EMAIL_NOT_VERIFIED' });

    // Verify email
    await auth.verifyEmail(verificationToken!, meta);

    // Login should now succeed
    const login = await auth.login({
      email: 'bob@example.com',
      password: 'BobPass123',
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
    });
    expect(login.success).toBe(true);
  });
});

describe('Password reset flow', () => {
  it('request → reset → login with new password', async () => {
    const auth = new AuthShield(config);

    await auth.register({ email: 'reset@example.com', password: 'OldPass1234' }, meta);

    // Login to create a session
    const loginResult = await auth.login({
      email: 'reset@example.com',
      password: 'OldPass1234',
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
    });
    expect(loginResult.success).toBe(true);
    if (!loginResult.success) return;
    const userId = loginResult.data.user.id;

    // Request reset
    const resetReq = await auth.requestPasswordReset({ email: 'reset@example.com' }, meta);
    expect(resetReq.success).toBe(true);
    if (!resetReq.success) return;
    const { resetToken } = resetReq.data;
    expect(resetToken).toBeTruthy();

    // Perform reset
    await auth.resetPassword({ token: resetToken, newPassword: 'NewPass5678' }, meta);

    // Old sessions should be revoked
    const sessions = await auth.listSessions(userId);
    expect(sessions.length).toBe(0);

    // Login with new password
    const newLogin = await auth.login({
      email: 'reset@example.com',
      password: 'NewPass5678',
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
    });
    expect(newLogin.success).toBe(true);

    // Login with old password should fail
    await expect(
      auth.login({
        email: 'reset@example.com',
        password: 'OldPass1234',
        ipAddress: meta.ip,
        userAgent: meta.userAgent,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });
});

describe('Password change flow', () => {
  it('changes password and revokes all sessions', async () => {
    const auth = new AuthShield(config);

    await auth.register({ email: 'change@example.com', password: 'BeforeChange1' }, meta);
    const login = await auth.login({
      email: 'change@example.com',
      password: 'BeforeChange1',
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
    });
    expect(login.success).toBe(true);
    if (!login.success) return;

    await auth.changePassword({
      userId: login.data.user.id,
      currentPassword: 'BeforeChange1',
      newPassword: 'AfterChange1',
    }, meta);

    const sessions = await auth.listSessions(login.data.user.id);
    expect(sessions.length).toBe(0);

    // Can log in with new password
    const newLogin = await auth.login({
      email: 'change@example.com',
      password: 'AfterChange1',
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
    });
    expect(newLogin.success).toBe(true);
  });
});

describe('Multi-device session management', () => {
  it('creates multiple sessions and revokes one', async () => {
    const auth = new AuthShield(config);

    await auth.register({ email: 'multi@example.com', password: 'MultiPass1' }, meta);

    const loginDeviceA = await auth.login({
      email: 'multi@example.com',
      password: 'MultiPass1',
      ipAddress: '192.168.1.1',
      userAgent: 'Chrome/Desktop',
    });
    const loginDeviceB = await auth.login({
      email: 'multi@example.com',
      password: 'MultiPass1',
      ipAddress: '192.168.1.2',
      userAgent: 'Safari/Mobile',
    });

    expect(loginDeviceA.success).toBe(true);
    expect(loginDeviceB.success).toBe(true);
    if (!loginDeviceA.success || !loginDeviceB.success) return;

    const userId = loginDeviceA.data.user.id;
    let sessions = await auth.listSessions(userId);
    expect(sessions.length).toBe(2);

    // Revoke device A's session
    await auth.revokeSession(loginDeviceA.data.sessionId, userId, meta);

    sessions = await auth.listSessions(userId);
    expect(sessions.length).toBe(1);
    expect(sessions[0]!.userAgent).toBe('Safari/Mobile');
  });

  it('revokes all sessions at once', async () => {
    const auth = new AuthShield(config);

    await auth.register({ email: 'all@example.com', password: 'AllPass1234' }, meta);

    for (let i = 0; i < 3; i++) {
      await auth.login({
        email: 'all@example.com',
        password: 'AllPass1234',
        ipAddress: `10.0.0.${i + 1}`,
        userAgent: `Agent-${i}`,
      });
    }

    const firstLogin = await auth.login({
      email: 'all@example.com',
      password: 'AllPass1234',
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
    });
    expect(firstLogin.success).toBe(true);
    if (!firstLogin.success) return;

    await auth.revokeAllSessions(firstLogin.data.user.id, meta);

    const sessions = await auth.listSessions(firstLogin.data.user.id);
    expect(sessions.length).toBe(0);
  });
});

describe('RBAC integration', () => {
  it('admin has inherited user permissions', async () => {
    const auth = new AuthShield(config);

    // Manually create admin user via adapter
    const user = await adapter.createUser({
      email: 'admin@example.com',
      passwordHash: 'will-be-overridden',
      roles: ['admin'],
      permissions: [],
    });

    expect(auth.hasPermission(['admin'], [], 'posts.read')).toBe(true);   // inherited
    expect(auth.hasPermission(['admin'], [], 'posts.delete')).toBe(true); // own
    expect(auth.hasPermission(['admin'], [], 'users.manage')).toBe(true); // own
  });
});

describe('Event system integration', () => {
  it('fires all relevant events in a register → login → logout flow', async () => {
    const auth = new AuthShield(config);
    const fired: string[] = [];

    auth.on('user.registered', () => fired.push('registered'));
    auth.on('user.login', () => fired.push('login'));
    auth.on('user.logout', () => fired.push('logout'));

    await auth.register({ email: 'events@example.com', password: 'EventPass1' }, meta);
    const login = await auth.login({
      email: 'events@example.com',
      password: 'EventPass1',
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
    });
    expect(login.success).toBe(true);
    if (!login.success) return;

    await auth.logout({ sessionId: login.data.sessionId, userId: login.data.user.id }, meta);

    expect(fired).toContain('registered');
    expect(fired).toContain('login');
    expect(fired).toContain('logout');
  });
});
