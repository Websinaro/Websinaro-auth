import { SignJWT, jwtVerify, decodeJwt } from 'jose';
import crypto from 'node:crypto';
import type {
  AccessTokenPayload,
  RefreshTokenPayload,
  VerificationTokenPayload,
  TokenPair,
  AuthUser,
  AuthSession,
  StorageAdapter,
} from '../types/index.js';
import { TokenError, ConfigurationError } from '../errors/index.js';

// ─── Token Service ───────────────────────────────────────────
// Uses the `jose` library which supports both Node.js and browser
// environments, making this frontend-compatible.
//
// Token types:
//   - Access token  : Short-lived (15m default), contains user claims
//   - Refresh token : Long-lived (7d/30d), single-use + rotation
//   - Verification  : One-time tokens for email/password-reset flows

export interface TokenServiceConfig {
  accessTokenSecret: string;
  refreshTokenSecret: string;
  issuer: string;
  audience: string[];
  accessTokenTtl: number;    // seconds
  refreshTokenTtl: number;   // seconds
  rememberMeTtl: number;     // seconds
}

export class TokenService {
  private readonly accessKey: Uint8Array;
  private readonly refreshKey: Uint8Array;
  private readonly config: TokenServiceConfig;

  constructor(config: TokenServiceConfig) {
    // Enforce secrets — absolutely no fallbacks
    if (!config.accessTokenSecret || config.accessTokenSecret.length < 32) {
      throw new ConfigurationError('accessTokenSecret must be at least 32 characters');
    }
    if (!config.refreshTokenSecret || config.refreshTokenSecret.length < 32) {
      throw new ConfigurationError('refreshTokenSecret must be at least 32 characters');
    }

    this.config = config;
    this.accessKey = new TextEncoder().encode(config.accessTokenSecret);
    this.refreshKey = new TextEncoder().encode(config.refreshTokenSecret);
  }

  // ─── Issue Token Pair ─────────────────────────────────────

  async issueTokenPair(
    user: AuthUser,
    session: AuthSession,
  ): Promise<TokenPair> {
    const now = new Date();
    const ttl = session.rememberMe ? this.config.rememberMeTtl : this.config.refreshTokenTtl;

    const [accessToken, refreshToken] = await Promise.all([
      this.signAccessToken(user, session),
      this.signRefreshToken(user.id, session),
    ]);

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: new Date(now.getTime() + this.config.accessTokenTtl * 1000),
      refreshTokenExpiresAt: new Date(now.getTime() + ttl * 1000),
    };
  }

  // ─── Sign ─────────────────────────────────────────────────

  private async signAccessToken(user: AuthUser, session: AuthSession): Promise<string> {
    const jti = crypto.randomUUID();

    return new SignJWT({
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
      sessionId: session.id,
    } satisfies Omit<AccessTokenPayload, 'sub' | 'jti' | 'iss' | 'aud' | 'iat' | 'exp'>)
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(user.id)
      .setIssuedAt()
      .setIssuer(this.config.issuer)
      .setAudience(this.config.audience)
      .setJti(jti)
      .setExpirationTime(Math.floor(Date.now() / 1000) + this.config.accessTokenTtl)
      .sign(this.accessKey);
  }

  private async signRefreshToken(userId: string, session: AuthSession): Promise<string> {
    const jti = crypto.randomUUID();
    const ttl = session.rememberMe ? this.config.rememberMeTtl : this.config.refreshTokenTtl;

    return new SignJWT({
      sessionId: session.id,
      family: session.tokenFamily,
    } satisfies Omit<RefreshTokenPayload, 'sub' | 'jti' | 'iss' | 'iat' | 'exp'>)
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(userId)
      .setIssuedAt()
      .setIssuer(this.config.issuer)
      .setJti(jti)
      .setExpirationTime(Math.floor(Date.now() / 1000) + ttl)
      .sign(this.refreshKey);
  }

  async signVerificationToken(
    userId: string,
    purpose: VerificationTokenPayload['purpose'],
    ttlSeconds = 3600,
  ): Promise<string> {
    const jti = crypto.randomUUID();

    return new SignJWT({ purpose } satisfies Omit<
      VerificationTokenPayload,
      'sub' | 'jti' | 'iss' | 'iat' | 'exp'
    >)
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(userId)
      .setIssuedAt()
      .setIssuer(this.config.issuer)
      .setJti(jti)
      .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
      .sign(this.accessKey);
  }

  // ─── Verify ──────────────────────────────────────────────

  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    try {
      const { payload } = await jwtVerify(token, this.accessKey, {
        issuer: this.config.issuer,
        audience: this.config.audience,
        algorithms: ['HS256'],
      });
      return payload as unknown as AccessTokenPayload;
    } catch (err) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('expired')) {
        throw new TokenError('TOKEN_EXPIRED', 'Access token has expired.');
      }
      throw new TokenError('TOKEN_INVALID', 'Access token is invalid.', msg);
    }
  }

  async verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    try {
      const { payload } = await jwtVerify(token, this.refreshKey, {
        issuer: this.config.issuer,
        algorithms: ['HS256'],
      });
      return payload as unknown as RefreshTokenPayload;
    } catch (err) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('expired')) {
        throw new TokenError('TOKEN_EXPIRED', 'Refresh token has expired.');
      }
      throw new TokenError('TOKEN_INVALID', 'Refresh token is invalid.', msg);
    }
  }

  async verifyVerificationToken(token: string): Promise<VerificationTokenPayload> {
    try {
      const { payload } = await jwtVerify(token, this.accessKey, {
        issuer: this.config.issuer,
        algorithms: ['HS256'],
      });
      return payload as unknown as VerificationTokenPayload;
    } catch (err) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('expired')) {
        throw new TokenError('TOKEN_EXPIRED', 'Verification token has expired.');
      }
      throw new TokenError('TOKEN_INVALID', 'Verification token is invalid.', msg);
    }
  }

  /**
   * Decode a token WITHOUT verifying the signature.
   * Only use for extracting the JTI before blacklist checking.
   */
  decodeUnsafe(token: string): Record<string, unknown> | null {
    try {
      return decodeJwt(token) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  extractJti(token: string): string | null {
    const decoded = this.decodeUnsafe(token);
    return typeof decoded?.['jti'] === 'string' ? decoded['jti'] : null;
  }
}
