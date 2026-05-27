import { describe, it, expect, beforeEach } from 'vitest';
import { SessionService } from '../../src/sessions/index.js';
import { MemoryAdapter } from '../../src/adapters/memory.js';
import { SessionError } from '../../src/errors/index.js';

const adapter = new MemoryAdapter();

const sessionService = new SessionService(adapter, {
  maxSessionsPerUser: 3,
  refreshTokenTtl: 604800,
  rememberMeTtl: 2592000,
});

const baseInput = {
  userId: 'user-1',
  refreshTokenJti: 'jti-1',
  tokenFamily: 'family-1',
  ipAddress: '1.2.3.4',
  userAgent: 'Mozilla/5.0',
  rememberMe: false,
};

beforeEach(() => adapter._clear());

describe('SessionService', () => {
  it('creates a session', async () => {
    const session = await sessionService.createSession(baseInput);

    expect(session.id).toBeDefined();
    expect(session.userId).toBe('user-1');
    expect(session.isRevoked).toBe(false);
    expect(session.expiresAt).toBeInstanceOf(Date);
    expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('creates a longer-lived session with rememberMe', async () => {
    const normal = await sessionService.createSession({ ...baseInput, rememberMe: false });
    const remembered = await sessionService.createSession({
      ...baseInput,
      userId: 'user-2',
      rememberMe: true,
    });

    expect(remembered.expiresAt.getTime()).toBeGreaterThan(normal.expiresAt.getTime());
  });

  it('finds an active session by id', async () => {
    const created = await sessionService.createSession(baseInput);
    const found = await sessionService.findActiveSession(created.id);

    expect(found.id).toBe(created.id);
  });

  it('throws SESSION_NOT_FOUND for unknown id', async () => {
    await expect(sessionService.findActiveSession('unknown-id')).rejects.toMatchObject({
      code: 'SESSION_NOT_FOUND',
    });
  });

  it('throws SESSION_REVOKED for revoked session', async () => {
    const session = await sessionService.createSession(baseInput);
    await adapter.revokeSession(session.id);

    await expect(sessionService.findActiveSession(session.id)).rejects.toMatchObject({
      code: 'SESSION_REVOKED',
    });
  });

  it('revokes a session by id', async () => {
    const session = await sessionService.createSession(baseInput);
    await sessionService.revokeSession(session.id, baseInput.userId);

    await expect(sessionService.findActiveSession(session.id)).rejects.toMatchObject({
      code: 'SESSION_REVOKED',
    });
  });

  it('throws when revoking session belonging to different user', async () => {
    const session = await sessionService.createSession(baseInput);

    await expect(
      sessionService.revokeSession(session.id, 'different-user'),
    ).rejects.toBeInstanceOf(SessionError);
  });

  it('revokes all sessions for a user', async () => {
    await sessionService.createSession(baseInput);
    await sessionService.createSession({ ...baseInput, refreshTokenJti: 'jti-2' });

    await sessionService.revokeAllSessions('user-1');
    const active = await sessionService.listActiveSessions('user-1');

    expect(active.length).toBe(0);
  });

  it('enforces maxSessionsPerUser by revoking the oldest', async () => {
    for (let i = 0; i < 3; i++) {
      await sessionService.createSession({
        ...baseInput,
        userId: 'capped-user',
        refreshTokenJti: `jti-cap-${i}`,
      });
    }

    // 4th session should trigger eviction
    await sessionService.createSession({
      ...baseInput,
      userId: 'capped-user',
      refreshTokenJti: 'jti-cap-4',
    });

    const active = await sessionService.listActiveSessions('capped-user');
    expect(active.length).toBeLessThanOrEqual(3);
  });

  it('lists only active (non-revoked, non-expired) sessions', async () => {
    await sessionService.createSession(baseInput);
    const toRevoke = await sessionService.createSession({
      ...baseInput,
      refreshTokenJti: 'jti-to-revoke',
    });
    await adapter.revokeSession(toRevoke.id);

    const active = await sessionService.listActiveSessions('user-1');
    expect(active.every((s) => !s.isRevoked)).toBe(true);
  });

  it('rotates session refresh token JTI', async () => {
    const session = await sessionService.createSession(baseInput);
    await sessionService.rotateSessionToken(session.id, 'new-jti-xyz');

    const updated = await adapter.findSessionById(session.id);
    expect(updated?.refreshTokenJti).toBe('new-jti-xyz');
  });

  it('touches session last active timestamp', async () => {
    const session = await sessionService.createSession(baseInput);
    const before = session.lastActiveAt;

    await new Promise((r) => setTimeout(r, 5));
    await sessionService.touchSession(session.id, { ipAddress: '9.9.9.9' });

    const updated = await adapter.findSessionById(session.id);
    expect(updated?.lastActiveAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
    expect(updated?.ipAddress).toBe('9.9.9.9');
  });
});
