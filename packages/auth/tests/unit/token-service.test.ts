import { describe, it, expect } from 'vitest';
import { TokenService } from '../../src/tokens/index.js';
import { TokenError } from '../../src/errors/index.js';
import { ConfigurationError } from '../../src/errors/index.js';
import type { AuthUser, AuthSession } from '../../src/types/index.js';

const baseConfig = {
  accessTokenSecret: 'access-secret-that-is-at-least-32-characters-long',
  refreshTokenSecret: 'refresh-secret-that-is-at-least-32-characters-long',
  issuer: 'test-issuer',
  audience: ['test-audience'],
  accessTokenTtl: 900,
  refreshTokenTtl: 604800,
  rememberMeTtl: 2592000,
};

function makeUser(overrides: Partial<AuthUser> = {}): AuthUser {
  return {
    id: 'user-123',
    email: 'test@example.com',
    passwordHash: 'hash',
    roles: ['user'],
    permissions: ['posts.read'],
    isEmailVerified: true,
    isLocked: false,
    failedLoginAttempts: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

function makeSession(overrides: Partial<AuthSession> = {}): AuthSession {
  return {
    id: 'session-456',
    userId: 'user-123',
    refreshTokenJti: 'jti-abc',
    tokenFamily: 'family-xyz',
    ipAddress: '127.0.0.1',
    userAgent: 'test',
    isRevoked: false,
    expiresAt: new Date(Date.now() + 604800 * 1000),
    lastActiveAt: new Date(),
    createdAt: new Date(),
    rememberMe: false,
    ...overrides,
  };
}

describe('TokenService', () => {
  it('throws ConfigurationError with short accessTokenSecret', () => {
    expect(
      () => new TokenService({ ...baseConfig, accessTokenSecret: 'short' }),
    ).toThrow(ConfigurationError);
  });

  it('throws ConfigurationError with short refreshTokenSecret', () => {
    expect(
      () => new TokenService({ ...baseConfig, refreshTokenSecret: 'short' }),
    ).toThrow(ConfigurationError);
  });

  it('issues a valid token pair', async () => {
    const svc = new TokenService(baseConfig);
    const pair = await svc.issueTokenPair(makeUser(), makeSession());

    expect(pair.accessToken).toBeTruthy();
    expect(pair.refreshToken).toBeTruthy();
    expect(pair.accessTokenExpiresAt).toBeInstanceOf(Date);
    expect(pair.refreshTokenExpiresAt).toBeInstanceOf(Date);
  });

  it('verifies access token and returns payload', async () => {
    const svc = new TokenService(baseConfig);
    const pair = await svc.issueTokenPair(makeUser(), makeSession());
    const payload = await svc.verifyAccessToken(pair.accessToken);

    expect(payload.sub).toBe('user-123');
    expect(payload.email).toBe('test@example.com');
    expect(payload.roles).toEqual(['user']);
    expect(payload.permissions).toEqual(['posts.read']);
    expect(payload.sessionId).toBe('session-456');
    expect(payload.jti).toBeDefined();
  });

  it('verifies refresh token and returns payload', async () => {
    const svc = new TokenService(baseConfig);
    const pair = await svc.issueTokenPair(makeUser(), makeSession());
    const payload = await svc.verifyRefreshToken(pair.refreshToken);

    expect(payload.sub).toBe('user-123');
    expect(payload.sessionId).toBe('session-456');
    expect(payload.family).toBe('family-xyz');
  });

  it('rejects access token verified as refresh token', async () => {
    const svc = new TokenService(baseConfig);
    const pair = await svc.issueTokenPair(makeUser(), makeSession());

    await expect(svc.verifyRefreshToken(pair.accessToken)).rejects.toBeInstanceOf(TokenError);
  });

  it('rejects a tampered token', async () => {
    const svc = new TokenService(baseConfig);
    const pair = await svc.issueTokenPair(makeUser(), makeSession());
    const tampered = pair.accessToken.slice(0, -5) + 'XXXXX';

    await expect(svc.verifyAccessToken(tampered)).rejects.toMatchObject({
      code: 'TOKEN_INVALID',
    });
  });

  it('rejects token from different issuer', async () => {
    const svc1 = new TokenService(baseConfig);
    const svc2 = new TokenService({ ...baseConfig, issuer: 'other-issuer' });

    const pair = await svc2.issueTokenPair(makeUser(), makeSession());
    await expect(svc1.verifyAccessToken(pair.accessToken)).rejects.toMatchObject({
      code: 'TOKEN_INVALID',
    });
  });

  it('issues longer-lived tokens when rememberMe is true', async () => {
    const svc = new TokenService(baseConfig);
    const normalSession = makeSession({ rememberMe: false });
    const rememberSession = makeSession({ rememberMe: true });

    const normalPair = await svc.issueTokenPair(makeUser(), normalSession);
    const rememberPair = await svc.issueTokenPair(makeUser(), rememberSession);

    expect(rememberPair.refreshTokenExpiresAt.getTime()).toBeGreaterThan(
      normalPair.refreshTokenExpiresAt.getTime(),
    );
  });

  it('signs and verifies a verification token', async () => {
    const svc = new TokenService(baseConfig);
    const token = await svc.signVerificationToken('user-999', 'email-verification', 3600);
    const payload = await svc.verifyVerificationToken(token);

    expect(payload.sub).toBe('user-999');
    expect(payload.purpose).toBe('email-verification');
  });

  it('extracts JTI from token without verification', async () => {
    const svc = new TokenService(baseConfig);
    const pair = await svc.issueTokenPair(makeUser(), makeSession());
    const jti = svc.extractJti(pair.accessToken);

    expect(jti).toBeDefined();
    expect(typeof jti).toBe('string');
  });

  it('returns null for JTI of invalid token', () => {
    const svc = new TokenService(baseConfig);
    expect(svc.extractJti('not.a.token')).toBeNull();
  });

  it('access and refresh tokens have different JTIs', async () => {
    const svc = new TokenService(baseConfig);
    const pair = await svc.issueTokenPair(makeUser(), makeSession());

    const accessJti = svc.extractJti(pair.accessToken);
    const refreshJti = svc.extractJti(pair.refreshToken);

    expect(accessJti).not.toBe(refreshJti);
  });

  it('two calls produce unique JTIs', async () => {
    const svc = new TokenService(baseConfig);
    const pair1 = await svc.issueTokenPair(makeUser(), makeSession());
    const pair2 = await svc.issueTokenPair(makeUser(), makeSession());

    expect(svc.extractJti(pair1.accessToken)).not.toBe(svc.extractJti(pair2.accessToken));
  });
});
