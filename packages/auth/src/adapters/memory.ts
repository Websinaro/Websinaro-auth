import crypto from 'node:crypto';
import type {
  StorageAdapter,
  AuthUser,
  AuthSession,
  CreateUserInput,
  CreateSessionInput,
  UpdateUserInput,
} from '../types/index.js';

// ─── In-Memory Adapter ───────────────────────────────────────
// Suitable for: testing, development, single-server prototypes.
// NOT suitable for production — data is lost on restart.
//
// For production, use a persistent adapter (Prisma, etc.)

export class MemoryAdapter implements StorageAdapter {
  private users = new Map<string, AuthUser>();
  private sessions = new Map<string, AuthSession>();
  private blacklist = new Map<string, Date>();
  private verificationTokens = new Map<string, { userId: string; purpose: string; expiresAt: Date }>();

  // ─── Users ──────────────────────────────────────────────

  async createUser(input: CreateUserInput): Promise<AuthUser> {
    const now = new Date();
    const user: AuthUser = {
      id: crypto.randomUUID(),
      email: input.email,
      passwordHash: input.passwordHash,
      username: input.username,
      name: input.name,
      phone: input.phone,
      roles: input.roles ?? [],
      permissions: input.permissions ?? [],
      isEmailVerified: false,
      isLocked: false,
      failedLoginAttempts: 0,
      createdAt: now,
      updatedAt: now,
      metadata: input.metadata,
    };
    this.users.set(user.id, user);
    return user;
  }

  async findUserById(id: string): Promise<AuthUser | null> {
    const user = this.users.get(id);
    return user && !user.deletedAt ? user : null;
  }

  async findUserByEmail(email: string): Promise<AuthUser | null> {
    for (const user of this.users.values()) {
      if (user.email === email && !user.deletedAt) return user;
    }
    return null;
  }

  async updateUser(id: string, input: UpdateUserInput & { passwordHash?: string }): Promise<AuthUser> {
    const user = this.users.get(id);
    if (!user) throw new Error(`User not found: ${id}`);

    const updated: AuthUser = {
      ...user,
      ...input,
      updatedAt: new Date(),
    };
    this.users.set(id, updated);
    return updated;
  }

  async softDeleteUser(id: string): Promise<void> {
    const user = this.users.get(id);
    if (user) {
      this.users.set(id, { ...user, deletedAt: new Date() });
    }
  }

  // ─── Sessions ────────────────────────────────────────────

  async createSession(input: CreateSessionInput): Promise<AuthSession> {
    const now = new Date();
    const ttl = input.rememberMe ? 30 * 24 * 3600 : 7 * 24 * 3600;

    const session: AuthSession = {
      id: crypto.randomUUID(),
      userId: input.userId,
      refreshTokenJti: input.refreshTokenJti,
      tokenFamily: input.tokenFamily,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      deviceName: input.deviceName,
      isRevoked: false,
      expiresAt: new Date(now.getTime() + ttl * 1000),
      lastActiveAt: now,
      createdAt: now,
      rememberMe: input.rememberMe,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  async findSessionById(id: string): Promise<AuthSession | null> {
    return this.sessions.get(id) ?? null;
  }

  async findSessionsByUserId(userId: string): Promise<AuthSession[]> {
    return [...this.sessions.values()].filter((s) => s.userId === userId);
  }

  async updateSession(id: string, input: Partial<AuthSession>): Promise<AuthSession> {
    const session = this.sessions.get(id);
    if (!session) throw new Error(`Session not found: ${id}`);
    const updated = { ...session, ...input };
    this.sessions.set(id, updated);
    return updated;
  }

  async revokeSession(id: string): Promise<void> {
    const session = this.sessions.get(id);
    if (session) this.sessions.set(id, { ...session, isRevoked: true });
  }

  async revokeAllUserSessions(userId: string): Promise<void> {
    for (const [id, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        this.sessions.set(id, { ...session, isRevoked: true });
      }
    }
  }

  async deleteExpiredSessions(): Promise<void> {
    const now = new Date();
    for (const [id, session] of this.sessions.entries()) {
      if (session.expiresAt < now) this.sessions.delete(id);
    }
  }

  // ─── Token Blacklist ─────────────────────────────────────

  async blacklistToken(jti: string, expiresAt: Date): Promise<void> {
    this.blacklist.set(jti, expiresAt);
  }

  async isTokenBlacklisted(jti: string): Promise<boolean> {
    const exp = this.blacklist.get(jti);
    if (!exp) return false;
    if (exp < new Date()) {
      this.blacklist.delete(jti); // auto-cleanup
      return false;
    }
    return true;
  }

  // ─── Verification Tokens ─────────────────────────────────

  async saveVerificationToken(
    token: string,
    userId: string,
    purpose: string,
    expiresAt: Date,
  ): Promise<void> {
    this.verificationTokens.set(token, { userId, purpose, expiresAt });
  }

  async findVerificationToken(token: string) {
    return this.verificationTokens.get(token) ?? null;
  }

  async deleteVerificationToken(token: string): Promise<void> {
    this.verificationTokens.delete(token);
  }

  // ─── Test Helpers ────────────────────────────────────────

  _clear(): void {
    this.users.clear();
    this.sessions.clear();
    this.blacklist.clear();
    this.verificationTokens.clear();
  }

  _getUserCount(): number {
    return this.users.size;
  }
}
