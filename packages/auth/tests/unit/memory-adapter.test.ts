import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryAdapter } from '../../src/adapters/memory.js';

const adapter = new MemoryAdapter();

const baseUser = {
  email: 'test@example.com',
  passwordHash: '$argon2id$...',
  roles: ['user'],
  permissions: [],
};

const baseSession = {
  userId: 'user-1',
  refreshTokenJti: 'jti-1',
  tokenFamily: 'family-1',
  ipAddress: '1.2.3.4',
  userAgent: 'agent',
  rememberMe: false,
};

beforeEach(() => adapter._clear());

describe('MemoryAdapter — Users', () => {
  it('creates and finds user by id', async () => {
    const user = await adapter.createUser(baseUser);
    const found = await adapter.findUserById(user.id);

    expect(found).not.toBeNull();
    expect(found!.email).toBe('test@example.com');
  });

  it('finds user by email', async () => {
    await adapter.createUser(baseUser);
    const found = await adapter.findUserByEmail('test@example.com');

    expect(found).not.toBeNull();
  });

  it('returns null for non-existent user', async () => {
    expect(await adapter.findUserById('ghost')).toBeNull();
    expect(await adapter.findUserByEmail('ghost@example.com')).toBeNull();
  });

  it('updates user fields', async () => {
    const user = await adapter.createUser(baseUser);
    const updated = await adapter.updateUser(user.id, { name: 'Alice' });

    expect(updated.name).toBe('Alice');
  });

  it('soft-deletes user (hidden from lookups)', async () => {
    const user = await adapter.createUser(baseUser);
    await adapter.softDeleteUser(user.id);

    expect(await adapter.findUserById(user.id)).toBeNull();
    expect(await adapter.findUserByEmail(baseUser.email)).toBeNull();
  });
});

describe('MemoryAdapter — Sessions', () => {
  it('creates and finds session by id', async () => {
    const session = await adapter.createSession(baseSession);
    const found = await adapter.findSessionById(session.id);

    expect(found).not.toBeNull();
    expect(found!.userId).toBe('user-1');
  });

  it('finds all sessions for a user', async () => {
    await adapter.createSession(baseSession);
    await adapter.createSession({ ...baseSession, refreshTokenJti: 'jti-2' });
    await adapter.createSession({ ...baseSession, userId: 'other-user', refreshTokenJti: 'jti-3' });

    const sessions = await adapter.findSessionsByUserId('user-1');
    expect(sessions.length).toBe(2);
  });

  it('revokes a session', async () => {
    const session = await adapter.createSession(baseSession);
    await adapter.revokeSession(session.id);

    const found = await adapter.findSessionById(session.id);
    expect(found!.isRevoked).toBe(true);
  });

  it('revokes all user sessions', async () => {
    await adapter.createSession(baseSession);
    await adapter.createSession({ ...baseSession, refreshTokenJti: 'jti-2' });

    await adapter.revokeAllUserSessions('user-1');
    const sessions = await adapter.findSessionsByUserId('user-1');

    expect(sessions.every((s) => s.isRevoked)).toBe(true);
  });
});

describe('MemoryAdapter — Token Blacklist', () => {
  it('blacklists and detects a token JTI', async () => {
    const exp = new Date(Date.now() + 3600 * 1000);
    await adapter.blacklistToken('jti-x', exp);

    expect(await adapter.isTokenBlacklisted('jti-x')).toBe(true);
  });

  it('returns false for non-blacklisted JTI', async () => {
    expect(await adapter.isTokenBlacklisted('not-blacklisted')).toBe(false);
  });

  it('auto-cleans expired blacklist entries', async () => {
    const pastExp = new Date(Date.now() - 1000);
    await adapter.blacklistToken('expired-jti', pastExp);

    expect(await adapter.isTokenBlacklisted('expired-jti')).toBe(false);
  });
});

describe('MemoryAdapter — Verification Tokens', () => {
  it('saves and retrieves a verification token', async () => {
    const exp = new Date(Date.now() + 3600 * 1000);
    await adapter.saveVerificationToken('tok-1', 'user-1', 'email-verification', exp);

    const record = await adapter.findVerificationToken('tok-1');
    expect(record).not.toBeNull();
    expect(record!.userId).toBe('user-1');
    expect(record!.purpose).toBe('email-verification');
  });

  it('deletes a verification token', async () => {
    const exp = new Date(Date.now() + 3600 * 1000);
    await adapter.saveVerificationToken('tok-2', 'user-2', 'password-reset', exp);
    await adapter.deleteVerificationToken('tok-2');

    expect(await adapter.findVerificationToken('tok-2')).toBeNull();
  });
});
