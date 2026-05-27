import type { AuthErrorCode } from '../types/index.js';

// ─── Base Auth Error ─────────────────────────────────────────

export class AuthError extends Error {
  public readonly code: AuthErrorCode;
  public readonly statusCode: number;
  /** Safe message to expose to end users */
  public readonly publicMessage: string;
  /** Internal debug details — never expose to clients */
  public readonly internalDetails?: string | undefined;

  constructor(
    code: AuthErrorCode,
    publicMessage: string,
    statusCode = 400,
    internalDetails?: string,
  ) {
    super(publicMessage);
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = statusCode;
    this.publicMessage = publicMessage;
    this.internalDetails = internalDetails;
    // Maintains proper stack trace in V8 environments
    const E = Error as unknown as Record<string, unknown>;
    if (typeof E['captureStackTrace'] === 'function') {
      (E['captureStackTrace'] as (t: object, c?: unknown) => void)(this, this.constructor);
    }
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.publicMessage,
      statusCode: this.statusCode,
    };
  }
}

// ─── Specialised Errors ──────────────────────────────────────

export class ValidationError extends AuthError {
  public readonly fieldErrors: Record<string, string[]>;

  constructor(fieldErrors: Record<string, string[]>, message = 'Validation failed') {
    super('VALIDATION_ERROR', message, 422);
    this.name = 'ValidationError';
    this.fieldErrors = fieldErrors;
  }

  override toJSON() {
    return { ...super.toJSON(), fieldErrors: this.fieldErrors };
  }
}

export class TokenError extends AuthError {
  constructor(code: AuthErrorCode, message: string, internalDetails?: string) {
    super(code, message, 401, internalDetails);
    this.name = 'TokenError';
  }
}

export class SessionError extends AuthError {
  constructor(code: AuthErrorCode, message: string) {
    super(code, message, 401);
    this.name = 'SessionError';
  }
}

export class SecurityError extends AuthError {
  constructor(code: AuthErrorCode, message: string, internalDetails?: string) {
    super(code, message, 403, internalDetails);
    this.name = 'SecurityError';
  }
}

export class RateLimitError extends AuthError {
  public readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super('RATE_LIMIT_EXCEEDED', 'Too many requests. Please try again later.', 429);
    this.name = 'RateLimitError';
    this.retryAfterSeconds = retryAfterSeconds;
  }

  override toJSON() {
    return { ...super.toJSON(), retryAfterSeconds: this.retryAfterSeconds };
  }
}

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(`[AuthShield Configuration] ${message}`);
    this.name = 'ConfigurationError';
  }
}

// ─── Error Guards ────────────────────────────────────────────

export function isAuthError(err: unknown): err is AuthError {
  return err instanceof AuthError;
}

export function isValidationError(err: unknown): err is ValidationError {
  return err instanceof ValidationError;
}

export function isTokenError(err: unknown): err is TokenError {
  return err instanceof TokenError;
}

export function isSessionError(err: unknown): err is SessionError {
  return err instanceof SessionError;
}

// ─── Safe Error Response ─────────────────────────────────────
// Convert any error into a safe public response (no stack traces, no internals)

export function toSafeError(err: unknown): {
  code: AuthErrorCode;
  message: string;
  statusCode: number;
  details?: Record<string, string[]>;
} {
  if (err instanceof ValidationError) {
    return {
      code: err.code,
      message: err.publicMessage,
      statusCode: err.statusCode,
      details: err.fieldErrors,
    };
  }
  if (err instanceof AuthError) {
    return {
      code: err.code,
      message: err.publicMessage,
      statusCode: err.statusCode,
    };
  }
  // Generic/unknown error — never leak internals
  return {
    code: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred.',
    statusCode: 500,
  };
}
