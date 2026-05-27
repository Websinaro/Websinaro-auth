// ============================================================
// @websinaro/auth — Public API
// ============================================================

// ─── Main Entry Point ────────────────────────────────────────

export { AuthShield } from './core/auth-shield.js';

// ─── Types (all exported for consumers) ─────────────────────

export type {
  // Config
  AuthShieldConfig,
  RBACConfig,
  Role,
  StorageAdapter,
  RedisAdapter,

  // User
  AuthUser,
  CreateUserInput,
  UpdateUserInput,

  // Sessions
  AuthSession,
  CreateSessionInput,

  // Tokens
  TokenPair,
  AccessTokenPayload,
  RefreshTokenPayload,
  VerificationTokenPayload,

  // Auth I/O
  RegisterInput,
  LoginInput,
  RefreshInput,
  LogoutInput,
  PasswordChangeInput,
  PasswordResetRequestInput,
  PasswordResetInput,
  AuthResponse,
  AuthResult,
  AuthFailure,

  // Events
  AuthEventMap,
  AuthEventName,
  AuthEventPayload,

  // Errors
  AuthErrorCode,

  // Audit
  AuditLogEntry,
  AuditAction,

  // Middleware
  AuthenticatedRequest,
  MiddlewareOptions,
} from './types/index.js';

// ─── Errors ──────────────────────────────────────────────────

export {
  AuthError,
  ValidationError,
  TokenError,
  SessionError,
  SecurityError,
  RateLimitError,
  ConfigurationError,
  isAuthError,
  isValidationError,
  isTokenError,
  isSessionError,
  toSafeError,
} from './errors/index.js';

// ─── Adapters ────────────────────────────────────────────────

export { MemoryAdapter, IoRedisAdapter } from './adapters/index.js';

// ─── Browser / Frontend Utilities ────────────────────────────

export {
  AuthClient,
  BrowserTokenStore,
  decodeAccessToken,
  isTokenExpired,
  getTokenExpiryDate,
  getTokenRoles,
  getTokenPermissions,
  hasTokenRole,
  hasTokenPermission,
} from './utils/browser.js';

// ─── Middleware Factories ─────────────────────────────────────

export { createExpressMiddleware, createFastifyPlugin } from './middleware/index.js';

// ─── Audit ───────────────────────────────────────────────────

export { AuditLogger } from './core/audit.js';
export type { AuditWriter } from './core/audit.js';

// ─── Version ─────────────────────────────────────────────────

export const VERSION = '1.0.0';
