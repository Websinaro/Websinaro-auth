// ============================================================
// @websinaro/auth — Core Types
// ============================================================

// ─── User ───────────────────────────────────────────────────

export interface AuthUser {
  id: string;
  email: string;
  passwordHash: string;
  username?: string | undefined;
  name?: string | undefined;
  phone?: string | undefined;
  roles: string[];
  permissions: string[];
  isEmailVerified: boolean;
  isLocked: boolean;
  lockReason?: string | undefined;
  lockUntil?: Date | undefined;
  failedLoginAttempts: number;
  lastLoginAt?: Date | undefined;
  lastLoginIp?: string | undefined;
  createdAt: Date;
  updatedAt: Date;
  deletedAt?: Date | undefined;
  metadata?: Record<string, unknown> | undefined;
}

export type CreateUserInput = Pick<
  AuthUser,
  'email' | 'passwordHash'
> & {
  username?: string | undefined;
  name?: string | undefined;
  phone?: string | undefined;
  roles?: string[] | undefined;
  permissions?: string[] | undefined;
  metadata?: Record<string, unknown> | undefined;
};

export type UpdateUserInput = Partial<
  Pick<
    AuthUser,
    | 'name'
    | 'phone'
    | 'roles'
    | 'permissions'
    | 'isEmailVerified'
    | 'isLocked'
    | 'lockReason'
    | 'lockUntil'
    | 'failedLoginAttempts'
    | 'lastLoginAt'
    | 'lastLoginIp'
    | 'metadata'
  >
>;

// ─── Tokens ─────────────────────────────────────────────────

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
}

export interface AccessTokenPayload {
  sub: string;        // user id
  email: string;
  roles: string[];
  permissions: string[];
  sessionId: string;
  jti: string;        // JWT ID (unique per token)
  iss: string;        // issuer
  aud: string[];      // audience
  iat: number;
  exp: number;
}

export interface RefreshTokenPayload {
  sub: string;
  sessionId: string;
  jti: string;
  family: string;     // token family for rotation detection
  iss: string;
  iat: number;
  exp: number;
}

export interface VerificationTokenPayload {
  sub: string;
  purpose: 'email-verification' | 'password-reset';
  jti: string;
  iss: string;
  iat: number;
  exp: number;
}

// ─── Sessions ───────────────────────────────────────────────

export interface AuthSession {
  id: string;
  userId: string;
  refreshTokenJti: string;
  tokenFamily: string;
  ipAddress: string;
  userAgent: string;
  deviceName?: string | undefined;
  isRevoked: boolean;
  expiresAt: Date;
  lastActiveAt: Date;
  createdAt: Date;
  rememberMe: boolean;
}

export type CreateSessionInput = Pick<
  AuthSession,
  'userId' | 'refreshTokenJti' | 'tokenFamily' | 'ipAddress' | 'userAgent' | 'rememberMe'
> & {
  deviceName?: string | undefined;
};

// ─── Auth Requests / Responses ──────────────────────────────

export interface RegisterInput {
  email: string;
  password: string;
  username?: string | undefined;
  name?: string | undefined;
  phone?: string | undefined;
}

export interface LoginInput {
  email: string;
  password: string;
  rememberMe?: boolean | undefined;
  ipAddress: string;
  userAgent: string;
}

export interface RefreshInput {
  refreshToken: string;
  ipAddress: string;
  userAgent: string;
}

export interface LogoutInput {
  sessionId: string;
  userId: string;
}

export interface PasswordResetRequestInput {
  email: string;
}

export interface PasswordResetInput {
  token: string;
  newPassword: string;
}

export interface PasswordChangeInput {
  userId: string;
  currentPassword: string;
  newPassword: string;
}

export interface AuthResult<T = unknown> {
  success: true;
  data: T;
}

export interface AuthFailure {
  success: false;
  error: AuthErrorCode;
  message: string;
  details?: Record<string, string[]> | undefined;
}

export type AuthResponse<T = unknown> = AuthResult<T> | AuthFailure;

// ─── Errors ─────────────────────────────────────────────────

export type AuthErrorCode =
  | 'VALIDATION_ERROR'
  | 'USER_NOT_FOUND'
  | 'USER_ALREADY_EXISTS'
  | 'INVALID_CREDENTIALS'
  | 'ACCOUNT_LOCKED'
  | 'EMAIL_NOT_VERIFIED'
  | 'TOKEN_INVALID'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_REVOKED'
  | 'TOKEN_REUSE_DETECTED'
  | 'SESSION_NOT_FOUND'
  | 'SESSION_EXPIRED'
  | 'SESSION_REVOKED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'INSUFFICIENT_PERMISSIONS'
  | 'INSUFFICIENT_ROLE'
  | 'PASSWORD_BREACHED'
  | 'PASSWORD_TOO_WEAK'
  | 'CSRF_INVALID'
  | 'INTERNAL_ERROR';

// ─── Events ─────────────────────────────────────────────────

export interface AuthEventMap {
  'user.registered': { userId: string; email: string; ip: string };
  'user.login': { userId: string; sessionId: string; ip: string; userAgent: string };
  'user.logout': { userId: string; sessionId: string };
  'user.login_failed': { email: string; ip: string; reason: AuthErrorCode };
  'user.locked': { userId: string; reason: string; until?: Date | undefined };
  'user.unlocked': { userId: string };
  'user.email_verified': { userId: string };
  'user.password_changed': { userId: string; ip: string };
  'user.password_reset_requested': { email: string; ip: string };
  'user.password_reset': { userId: string; ip: string };
  'user.deleted': { userId: string; ip: string };
  'token.refreshed': { userId: string; sessionId: string };
  'token.revoked': { jti: string };
  'session.revoked': { sessionId: string; userId: string };
  'session.all_revoked': { userId: string };
  'security.suspicious_login': { userId: string; ip: string; reason: string };
  'security.rate_limit': { ip: string; endpoint: string };
}

export type AuthEventName = keyof AuthEventMap;
export type AuthEventPayload<K extends AuthEventName> = AuthEventMap[K];

// ─── RBAC ───────────────────────────────────────────────────

export interface Role {
  name: string;
  permissions: string[];
  inherits?: string[] | undefined;
}

export interface RBACConfig {
  roles: Record<string, Role>;
  defaultRole?: string | undefined;
}

// ─── Config ─────────────────────────────────────────────────

export interface AuthShieldConfig {
  // Required secrets — no fallbacks allowed
  accessTokenSecret: string;
  refreshTokenSecret: string;

  // JWT config
  issuer: string;
  audience: string | string[];
  accessTokenTtl?: number | undefined;     // seconds, default 900 (15m)
  refreshTokenTtl?: number | undefined;    // seconds, default 604800 (7d)
  rememberMeTtl?: number | undefined;      // seconds, default 2592000 (30d)

  // Password config
  passwordMinLength?: number | undefined;  // default 8
  maxLoginAttempts?: number | undefined;   // default 5
  lockDurationSeconds?: number | undefined; // default 900 (15m)

  // Session config
  maxSessionsPerUser?: number | undefined; // default 5

  // Storage adapter — required
  adapter: StorageAdapter;

  // Redis — optional but recommended
  redis?: RedisAdapter | undefined;

  // RBAC
  rbac?: RBACConfig | undefined;

  // Feature flags
  requireEmailVerification?: boolean | undefined;
  enableCsrf?: boolean | undefined;
  enableAuditLog?: boolean | undefined;
}

// ─── Storage Adapters ───────────────────────────────────────

export interface StorageAdapter {
  // Users
  createUser(input: CreateUserInput): Promise<AuthUser>;
  findUserById(id: string): Promise<AuthUser | null>;
  findUserByEmail(email: string): Promise<AuthUser | null>;
  updateUser(id: string, input: UpdateUserInput): Promise<AuthUser>;
  softDeleteUser(id: string): Promise<void>;

  // Sessions
  createSession(input: CreateSessionInput): Promise<AuthSession>;
  findSessionById(id: string): Promise<AuthSession | null>;
  findSessionsByUserId(userId: string): Promise<AuthSession[]>;
  updateSession(id: string, input: Partial<AuthSession>): Promise<AuthSession>;
  revokeSession(id: string): Promise<void>;
  revokeAllUserSessions(userId: string): Promise<void>;
  deleteExpiredSessions(): Promise<void>;

  // Token blacklist
  blacklistToken(jti: string, expiresAt: Date): Promise<void>;
  isTokenBlacklisted(jti: string): Promise<boolean>;

  // Verification tokens
  saveVerificationToken(token: string, userId: string, purpose: string, expiresAt: Date): Promise<void>;
  findVerificationToken(token: string): Promise<{ userId: string; purpose: string; expiresAt: Date } | null>;
  deleteVerificationToken(token: string): Promise<void>;
}

export interface RedisAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds?: number | undefined): Promise<void>;
  del(key: string): Promise<void>;
  incr(key: string): Promise<number>;
  expire(key: string, ttlSeconds: number): Promise<void>;
  exists(key: string): Promise<boolean>;
  keys(pattern: string): Promise<string[]>;
}

// ─── Audit Log ──────────────────────────────────────────────

export interface AuditLogEntry {
  id?: string | undefined;
  action: AuditAction;
  userId: string | null;
  ip: string;
  userAgent?: string | undefined;
  details?: string | undefined;
  metadata?: Record<string, unknown> | undefined;
  timestamp: Date;
}

export type AuditAction =
  | 'USER_REGISTER'
  | 'USER_LOGIN'
  | 'USER_LOGOUT'
  | 'LOGIN_FAILED'
  | 'TOKEN_REFRESH'
  | 'TOKEN_REVOKED'
  | 'SESSION_REVOKED'
  | 'ALL_SESSIONS_REVOKED'
  | 'PASSWORD_CHANGE'
  | 'PASSWORD_RESET_REQUEST'
  | 'PASSWORD_RESET'
  | 'EMAIL_VERIFIED'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_UNLOCKED'
  | 'USER_DELETED'
  | 'SUSPICIOUS_ACTIVITY';

// ─── Middleware ──────────────────────────────────────────────

export interface AuthenticatedRequest {
  authUser: AccessTokenPayload;
  sessionId: string;
}

export interface MiddlewareOptions {
  optional?: boolean | undefined;
}
