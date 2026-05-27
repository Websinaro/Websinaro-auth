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
  AuthEventName,
  AuthEventPayload,
} from '../types/index.js';
import { AuthService } from './service.js';
import { CsrfService } from '../security/csrf.js';
import { AuthEventEmitter } from '../events/index.js';
import { ConfigurationError } from '../errors/index.js';

// ─── AuthShield ──────────────────────────────────────────────
//
// The primary entry-point to @websinaro/auth.
//
//   import { AuthShield } from "@websinaro/auth"
//   const auth = new AuthShield({ ... })
//
// Wraps AuthService with the event system and optional CSRF support.
// Designed to feel like Express / Prisma — simple, clean, extensible.

export class AuthShield {
  /** @internal — used by middleware factories */
  readonly service: AuthService;
  private readonly csrf: CsrfService | null;
  private readonly emitter: AuthEventEmitter;

  constructor(config: AuthShieldConfig) {
    this.emitter = new AuthEventEmitter();
    this.service = new AuthService(config, this.emitter);

    this.csrf = config.enableCsrf
      ? new CsrfService(config.accessTokenSecret)
      : null;
  }

  // ─── Auth Operations ─────────────────────────────────────

  async register(
    input: RegisterInput,
    meta: { ip: string; userAgent?: string },
  ) {
    return this.service.register(input, meta);
  }

  async login(input: LoginInput) {
    return this.service.login(input);
  }

  async refresh(input: RefreshInput) {
    return this.service.refresh(input);
  }

  async logout(input: LogoutInput, meta: { ip: string; userAgent?: string }) {
    return this.service.logout(input, meta);
  }

  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    return this.service.verifyAccessToken(token);
  }

  // ─── Email / Password Flows ──────────────────────────────

  async verifyEmail(token: string, meta: { ip: string }) {
    return this.service.verifyEmail(token, meta);
  }

  async requestPasswordReset(input: PasswordResetRequestInput, meta: { ip: string }) {
    return this.service.requestPasswordReset(input, meta);
  }

  async resetPassword(input: PasswordResetInput, meta: { ip: string }) {
    return this.service.resetPassword(input, meta);
  }

  async changePassword(input: PasswordChangeInput, meta: { ip: string; userAgent?: string }) {
    return this.service.changePassword(input, meta);
  }

  // ─── Session Management ──────────────────────────────────

  async listSessions(userId: string): Promise<AuthSession[]> {
    return this.service.listSessions(userId);
  }

  async revokeSession(sessionId: string, userId: string, meta: { ip: string }) {
    return this.service.revokeSession(sessionId, userId, meta);
  }

  async revokeAllSessions(userId: string, meta: { ip: string }) {
    return this.service.revokeAllSessions(userId, meta);
  }

  // ─── RBAC ────────────────────────────────────────────────

  hasRole(userRoles: string[], role: string): boolean {
    return this.service.hasRole(userRoles, role);
  }

  hasPermission(userRoles: string[], userPermissions: string[], permission: string): boolean {
    return this.service.hasPermission(userRoles, userPermissions, permission);
  }

  // ─── CSRF ────────────────────────────────────────────────

  generateCsrfToken(): { token: string; secret: string } {
    if (!this.csrf) {
      throw new ConfigurationError('CSRF is not enabled. Set enableCsrf: true in config.');
    }
    return this.csrf.generate();
  }

  verifyCsrfToken(token: string, secret: string): void {
    if (!this.csrf) {
      throw new ConfigurationError('CSRF is not enabled. Set enableCsrf: true in config.');
    }
    this.csrf.verify(token, secret);
  }

  // ─── Events ──────────────────────────────────────────────

  on<K extends AuthEventName>(
    event: K,
    listener: (payload: AuthEventPayload<K>) => void | Promise<void>,
  ): this {
    this.emitter.on(event, listener);
    return this;
  }

  off<K extends AuthEventName>(
    event: K,
    listener: (payload: AuthEventPayload<K>) => void | Promise<void>,
  ): this {
    this.emitter.off(event, listener);
    return this;
  }
}
