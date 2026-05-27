import crypto from 'node:crypto';
import type {
  AuthShieldConfig,
  RegisterInput,
  LoginInput,
  RefreshInput,
  LogoutInput,
  PasswordChangeInput,
  PasswordResetRequestInput,
  PasswordResetInput,
  AuthResponse,
  TokenPair,
  AuthUser,
  AuthSession,
  AccessTokenPayload,
} from '../types/index.js';
import { AuthError, TokenError, SessionError, ConfigurationError } from '../errors/index.js';
import { AuthValidator } from '../validation/index.js';
import { PasswordService } from '../security/password.js';
import { RateLimiter } from '../security/rate-limiter.js';
import { TokenService } from '../tokens/index.js';
import { SessionService } from '../sessions/index.js';
import { RBACService } from './rbac.js';
import { AuditLogger } from './audit.js';
import { AuthEventEmitter } from '../events/index.js';

// ─── Auth Service ────────────────────────────────────────────

export class AuthService {
  private readonly config: Required<AuthShieldConfig>;
  private readonly validator: AuthValidator;
  private readonly password: PasswordService;
  private readonly tokenService: TokenService;
  private readonly sessionService: SessionService;
  private readonly rateLimiter: RateLimiter;
  private readonly rbac: RBACService | null;
  private readonly audit: AuditLogger;
  readonly events: AuthEventEmitter;

  constructor(config: AuthShieldConfig, events: AuthEventEmitter) {
    // Validate required secrets at startup — fail fast
    if (!config.accessTokenSecret) {
      throw new ConfigurationError('accessTokenSecret is required. Never use fallback secrets.');
    }
    if (!config.refreshTokenSecret) {
      throw new ConfigurationError('refreshTokenSecret is required. Never use fallback secrets.');
    }
    if (!config.issuer) {
      throw new ConfigurationError('issuer is required.');
    }

    this.config = {
      accessTokenSecret: config.accessTokenSecret,
      refreshTokenSecret: config.refreshTokenSecret,
      issuer: config.issuer,
      audience: Array.isArray(config.audience) ? config.audience : [config.audience],
      accessTokenTtl: config.accessTokenTtl ?? 900,
      refreshTokenTtl: config.refreshTokenTtl ?? 604800,
      rememberMeTtl: config.rememberMeTtl ?? 2592000,
      passwordMinLength: config.passwordMinLength ?? 8,
      maxLoginAttempts: config.maxLoginAttempts ?? 5,
      lockDurationSeconds: config.lockDurationSeconds ?? 900,
      maxSessionsPerUser: config.maxSessionsPerUser ?? 5,
      adapter: config.adapter,
      redis: config.redis ?? undefined as any,
      rbac: config.rbac ?? undefined as any,
      requireEmailVerification: config.requireEmailVerification ?? false,
      enableCsrf: config.enableCsrf ?? false,
      enableAuditLog: config.enableAuditLog ?? true,
    };

    this.events = events;
    this.validator = new AuthValidator(this.config.passwordMinLength);
    this.password = new PasswordService();

    this.tokenService = new TokenService({
      accessTokenSecret: this.config.accessTokenSecret,
      refreshTokenSecret: this.config.refreshTokenSecret,
      issuer: this.config.issuer,
      audience: this.config.audience as string[],
      accessTokenTtl: this.config.accessTokenTtl,
      refreshTokenTtl: this.config.refreshTokenTtl,
      rememberMeTtl: this.config.rememberMeTtl,
    });

    this.sessionService = new SessionService(config.adapter, {
      maxSessionsPerUser: this.config.maxSessionsPerUser,
      refreshTokenTtl: this.config.refreshTokenTtl,
      rememberMeTtl: this.config.rememberMeTtl,
    });

    this.rateLimiter = new RateLimiter(
      {
        maxAttempts: this.config.maxLoginAttempts,
        windowSeconds: 300,           // 5-minute window
        blockDurationSeconds: this.config.lockDurationSeconds,
      },
      config.redis,
    );

    this.rbac = config.rbac ? new RBACService(config.rbac) : null;
    this.audit = new AuditLogger(this.config.enableAuditLog);
  }

  // ─── Register ───────────────────────────────────────────

  async register(
    input: RegisterInput,
    meta: { ip: string; userAgent?: string },
  ): Promise<AuthResponse<{ user: Omit<AuthUser, 'passwordHash'>; verificationToken?: string }>> {
    try {
      const validated = this.validator.validateRegister(input);

      // Check for existing user
      const existing = await this.config.adapter.findUserByEmail(validated.email);
      if (existing) {
        throw new AuthError('USER_ALREADY_EXISTS', 'An account with this email already exists.', 409);
      }

      // Strength check
      this.password.assertStrength(validated.password, this.config.passwordMinLength);

      const passwordHash = await this.password.hash(validated.password);

      const defaultRole = this.rbac?.getDefaultRole();

      const user = await this.config.adapter.createUser({
        email: validated.email,
        passwordHash,
        username: validated.username,
        name: validated.name,
        phone: validated.phone,
        roles: defaultRole ? [defaultRole] : [],
        permissions: [],
      });

      this.audit.log('USER_REGISTER', {
        userId: user.id,
        ip: meta.ip,
        userAgent: meta.userAgent,
      });

      this.events.emit('user.registered', {
        userId: user.id,
        email: user.email,
        ip: meta.ip,
      });

      let verificationToken: string | undefined;
      if (this.config.requireEmailVerification) {
        verificationToken = await this.tokenService.signVerificationToken(
          user.id,
          'email-verification',
        );
        await this.config.adapter.saveVerificationToken(
          verificationToken,
          user.id,
          'email-verification',
          new Date(Date.now() + 3600 * 1000),
        );
      }

      const { passwordHash: _, ...safeUser } = user;
      return {
        success: true,
        data: { user: safeUser, ...(verificationToken ? { verificationToken } : {}) },
      };
    } catch (err) {
      if (err instanceof AuthError) throw err;
      throw new AuthError('INTERNAL_ERROR', 'Registration failed.', 500, String(err));
    }
  }

  // ─── Login ──────────────────────────────────────────────

  async login(input: LoginInput): Promise<AuthResponse<TokenPair & { user: Omit<AuthUser, 'passwordHash'>; sessionId: string }>> {
    const validated = this.validator.validateLogin(input);

    // Rate limit by IP
    try {
      await this.rateLimiter.check(`login:${validated.ipAddress}`);
    } catch (err) {
      this.events.emit('security.rate_limit', {
        ip: validated.ipAddress,
        endpoint: 'login',
      });
      throw err;
    }

    const recordFailure = async (reason: string) => {
      this.audit.log('LOGIN_FAILED', {
        userId: null,
        ip: validated.ipAddress,
        userAgent: validated.userAgent,
        details: reason,
      });
      this.events.emit('user.login_failed', {
        email: validated.email,
        ip: validated.ipAddress,
        reason: 'INVALID_CREDENTIALS',
      });
    };

    const user = await this.config.adapter.findUserByEmail(validated.email);

    if (!user) {
      // Use a fake hash comparison to prevent user enumeration via timing
      await this.password.hash('__dummy_prevent_timing_attack__');
      await recordFailure('User not found');
      throw new AuthError('INVALID_CREDENTIALS', 'Invalid email or password.', 401);
    }

    if (user.isLocked) {
      if (user.lockUntil && user.lockUntil > new Date()) {
        throw new AuthError(
          'ACCOUNT_LOCKED',
          `Account is temporarily locked. Try again after ${user.lockUntil.toISOString()}`,
          403,
        );
      }
      // Lock expired — unlock
      await this.config.adapter.updateUser(user.id, {
        isLocked: false,
        failedLoginAttempts: 0,
        lockUntil: undefined,
        lockReason: undefined,
      });
    }

    if (this.config.requireEmailVerification && !user.isEmailVerified) {
      throw new AuthError('EMAIL_NOT_VERIFIED', 'Please verify your email before logging in.', 403);
    }

    const passwordValid = await this.password.verify(validated.password, user.passwordHash);

    if (!passwordValid) {
      const newAttempts = user.failedLoginAttempts + 1;
      const shouldLock = newAttempts >= this.config.maxLoginAttempts;

      await this.config.adapter.updateUser(user.id, {
        failedLoginAttempts: newAttempts,
        ...(shouldLock
          ? {
              isLocked: true,
              lockReason: 'Too many failed login attempts',
              lockUntil: new Date(Date.now() + this.config.lockDurationSeconds * 1000),
            }
          : {}),
      });

      if (shouldLock) {
        this.events.emit('user.locked', {
          userId: user.id,
          reason: 'Too many failed login attempts',
          until: new Date(Date.now() + this.config.lockDurationSeconds * 1000),
        });
      }

      await recordFailure('Invalid password');
      throw new AuthError('INVALID_CREDENTIALS', 'Invalid email or password.', 401);
    }

    // Reset failed attempts on success
    await this.config.adapter.updateUser(user.id, {
      failedLoginAttempts: 0,
      lastLoginAt: new Date(),
      lastLoginIp: validated.ipAddress,
    });

    await this.rateLimiter.reset(`login:${validated.ipAddress}`);

    // Create session
    const jti = crypto.randomUUID();
    const session = await this.sessionService.createSession({
      userId: user.id,
      refreshTokenJti: jti,
      tokenFamily: crypto.randomUUID(),
      ipAddress: validated.ipAddress,
      userAgent: validated.userAgent,
      rememberMe: validated.rememberMe ?? false,
    });

    const tokens = await this.tokenService.issueTokenPair(user, session);

    this.audit.log('USER_LOGIN', {
      userId: user.id,
      ip: validated.ipAddress,
      userAgent: validated.userAgent,
    });

    this.events.emit('user.login', {
      userId: user.id,
      sessionId: session.id,
      ip: validated.ipAddress,
      userAgent: validated.userAgent,
    });

    const { passwordHash: _, ...safeUser } = user;
    return {
      success: true,
      data: { ...tokens, user: safeUser, sessionId: session.id },
    };
  }

  // ─── Refresh ─────────────────────────────────────────────

  async refresh(input: RefreshInput): Promise<AuthResponse<TokenPair>> {
    const validated = this.validator.validateRefresh(input);

    let payload;
    try {
      payload = await this.tokenService.verifyRefreshToken(validated.refreshToken);
    } catch (err) {
      throw err;
    }

    // Check blacklist
    const isBlacklisted = await this.config.adapter.isTokenBlacklisted(payload.jti);
    if (isBlacklisted) {
      // Token reuse detected — revoke all sessions (security response)
      await this.sessionService.revokeAllSessions(payload.sub);
      this.events.emit('session.all_revoked', { userId: payload.sub });
      throw new TokenError('TOKEN_REUSE_DETECTED', 'Token reuse detected. All sessions have been revoked.');
    }

    const session = await this.sessionService.findActiveSession(payload.sessionId);

    // Validate token family to prevent replay attacks
    if (session.tokenFamily !== payload.family) {
      await this.sessionService.revokeAllSessions(payload.sub);
      throw new TokenError('TOKEN_REUSE_DETECTED', 'Token family mismatch. All sessions revoked.');
    }

    const user = await this.config.adapter.findUserById(payload.sub);
    if (!user || user.deletedAt) {
      throw new AuthError('USER_NOT_FOUND', 'User not found.', 401);
    }

    // Blacklist old refresh token
    await this.config.adapter.blacklistToken(
      payload.jti,
      new Date(payload.exp * 1000),
    );

    // Issue new token pair
    const tokens = await this.tokenService.issueTokenPair(user, session);

    // Update session with new JTI
    const newJti = this.tokenService.extractJti(tokens.refreshToken);
    if (newJti) {
      await this.sessionService.rotateSessionToken(session.id, newJti);
    }

    this.audit.log('TOKEN_REFRESH', {
      userId: user.id,
      ip: validated.ipAddress,
      userAgent: validated.userAgent,
    });

    this.events.emit('token.refreshed', { userId: user.id, sessionId: session.id });

    return { success: true, data: tokens };
  }

  // ─── Logout ──────────────────────────────────────────────

  async logout(input: LogoutInput, meta: { ip: string; userAgent?: string }): Promise<AuthResponse<void>> {
    await this.sessionService.revokeSession(input.sessionId, input.userId);

    this.audit.log('USER_LOGOUT', { userId: input.userId, ip: meta.ip, userAgent: meta.userAgent });
    this.events.emit('user.logout', { userId: input.userId, sessionId: input.sessionId });

    return { success: true, data: undefined };
  }

  // ─── Verify Access Token ─────────────────────────────────

  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    const payload = await this.tokenService.verifyAccessToken(token);

    // Check blacklist
    const isBlacklisted = await this.config.adapter.isTokenBlacklisted(payload.jti);
    if (isBlacklisted) {
      throw new TokenError('TOKEN_REVOKED', 'Access token has been revoked.');
    }

    return payload;
  }

  // ─── Email Verification ──────────────────────────────────

  async verifyEmail(token: string, meta: { ip: string }): Promise<AuthResponse<void>> {
    const payload = await this.tokenService.verifyVerificationToken(token);

    if (payload.purpose !== 'email-verification') {
      throw new TokenError('TOKEN_INVALID', 'Invalid verification token.');
    }

    const record = await this.config.adapter.findVerificationToken(token);
    if (!record) {
      throw new TokenError('TOKEN_INVALID', 'Verification token not found or already used.');
    }

    await this.config.adapter.updateUser(payload.sub, { isEmailVerified: true });
    await this.config.adapter.deleteVerificationToken(token);

    this.audit.log('EMAIL_VERIFIED', { userId: payload.sub, ip: meta.ip });
    this.events.emit('user.email_verified', { userId: payload.sub });

    return { success: true, data: undefined };
  }

  // ─── Password Reset Request ──────────────────────────────

  async requestPasswordReset(
    input: PasswordResetRequestInput,
    meta: { ip: string },
  ): Promise<AuthResponse<{ resetToken: string }>> {
    // Rate limit by IP
    await this.rateLimiter.check(`password-reset:${meta.ip}`);

    const validated = this.validator.validatePasswordResetRequest(input);

    // Always return success to prevent user enumeration
    const user = await this.config.adapter.findUserByEmail(validated.email);

    this.audit.log('PASSWORD_RESET_REQUEST', {
      userId: user?.id ?? null,
      ip: meta.ip,
      details: validated.email,
    });

    if (!user) {
      // Return a fake token — caller should send email if user exists
      return { success: true, data: { resetToken: '' } };
    }

    const resetToken = await this.tokenService.signVerificationToken(
      user.id,
      'password-reset',
      3600,
    );

    await this.config.adapter.saveVerificationToken(
      resetToken,
      user.id,
      'password-reset',
      new Date(Date.now() + 3600 * 1000),
    );

    this.events.emit('user.password_reset_requested', { email: user.email, ip: meta.ip });

    return { success: true, data: { resetToken } };
  }

  // ─── Password Reset ──────────────────────────────────────

  async resetPassword(input: PasswordResetInput, meta: { ip: string }): Promise<AuthResponse<void>> {
    const validated = this.validator.validatePasswordReset(input);

    const payload = await this.tokenService.verifyVerificationToken(validated.token);

    if (payload.purpose !== 'password-reset') {
      throw new TokenError('TOKEN_INVALID', 'Invalid reset token.');
    }

    const record = await this.config.adapter.findVerificationToken(validated.token);
    if (!record) {
      throw new TokenError('TOKEN_INVALID', 'Reset token not found or already used.');
    }

    this.password.assertStrength(validated.newPassword, this.config.passwordMinLength);

    const newHash = await this.password.hash(validated.newPassword);

    await this.config.adapter.updateUser(payload.sub, { passwordHash: newHash } as any);
    await this.config.adapter.deleteVerificationToken(validated.token);

    // Revoke all existing sessions on password reset
    await this.sessionService.revokeAllSessions(payload.sub);

    this.audit.log('PASSWORD_RESET', { userId: payload.sub, ip: meta.ip });
    this.events.emit('user.password_reset', { userId: payload.sub, ip: meta.ip });

    return { success: true, data: undefined };
  }

  // ─── Password Change ─────────────────────────────────────

  async changePassword(
    input: PasswordChangeInput,
    meta: { ip: string; userAgent?: string },
  ): Promise<AuthResponse<void>> {
    const validated = this.validator.validatePasswordChange(input);

    const user = await this.config.adapter.findUserById(validated.userId);
    if (!user) {
      throw new AuthError('USER_NOT_FOUND', 'User not found.', 404);
    }

    const currentValid = await this.password.verify(validated.currentPassword, user.passwordHash);
    if (!currentValid) {
      throw new AuthError('INVALID_CREDENTIALS', 'Current password is incorrect.', 401);
    }

    this.password.assertStrength(validated.newPassword, this.config.passwordMinLength);

    const newHash = await this.password.hash(validated.newPassword);
    await this.config.adapter.updateUser(user.id, { passwordHash: newHash } as any);

    // Revoke all sessions on password change
    await this.sessionService.revokeAllSessions(user.id);

    this.audit.log('PASSWORD_CHANGE', { userId: user.id, ip: meta.ip, userAgent: meta.userAgent });
    this.events.emit('user.password_changed', { userId: user.id, ip: meta.ip });

    return { success: true, data: undefined };
  }

  // ─── RBAC Helpers ────────────────────────────────────────

  hasRole(userRoles: string[], role: string): boolean {
    return this.rbac?.hasRole(userRoles, role) ?? false;
  }

  hasPermission(userRoles: string[], userPermissions: string[], permission: string): boolean {
    return this.rbac?.hasPermission(userRoles, userPermissions, permission) ?? false;
  }

  assertRole(userRoles: string[], role: string): void {
    this.rbac?.assertRole(userRoles, role);
  }

  assertPermission(userRoles: string[], userPermissions: string[], permission: string): void {
    this.rbac?.assertPermission(userRoles, userPermissions, permission);
  }

  // ─── Session Management ──────────────────────────────────

  async listSessions(userId: string): Promise<AuthSession[]> {
    return this.sessionService.listActiveSessions(userId);
  }

  async revokeSession(sessionId: string, userId: string, meta: { ip: string }): Promise<AuthResponse<void>> {
    await this.sessionService.revokeSession(sessionId, userId);
    this.audit.log('SESSION_REVOKED', { userId, ip: meta.ip });
    this.events.emit('session.revoked', { sessionId, userId });
    return { success: true, data: undefined };
  }

  async revokeAllSessions(userId: string, meta: { ip: string }): Promise<AuthResponse<void>> {
    await this.sessionService.revokeAllSessions(userId);
    this.audit.log('ALL_SESSIONS_REVOKED', { userId, ip: meta.ip });
    this.events.emit('session.all_revoked', { userId });
    return { success: true, data: undefined };
  }
}
