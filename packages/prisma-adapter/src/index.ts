import type { PrismaClient } from '@prisma/client';
import type {
  StorageAdapter,
  AuthUser,
  AuthSession,
  CreateUserInput,
  CreateSessionInput,
  UpdateUserInput,
} from '@websinaro/auth';

// ─── Prisma Storage Adapter ──────────────────────────────────
// Production-grade adapter using Prisma ORM.
// Supports PostgreSQL, MySQL, SQLite.
//
// Usage:
//   import { PrismaClient } from '@prisma/client'
//   import { PrismaAuthAdapter } from '@websinaro/auth-prisma'
//
//   const prisma = new PrismaClient()
//   const adapter = new PrismaAuthAdapter(prisma)
//   const auth = new AuthShield({ adapter, ... })

type PrismaWithAuthModels = PrismaClient & {
  authUser: any;
  authSession: any;
  authTokenBlacklist: any;
  authVerificationToken: any;
  authAuditLog: any;
};

export class PrismaAuthAdapter implements StorageAdapter {
  private readonly prisma: PrismaWithAuthModels;

  constructor(prisma: PrismaClient) {
    this.prisma = prisma as PrismaWithAuthModels;
  }

  // ─── Users ──────────────────────────────────────────────

  async createUser(input: CreateUserInput): Promise<AuthUser> {
    const user = await this.prisma.authUser.create({
      data: {
        email: input.email,
        passwordHash: input.passwordHash,
        username: input.username ?? null,
        name: input.name ?? null,
        phone: input.phone ?? null,
        roles: input.roles ?? [],
        permissions: input.permissions ?? [],
        metadata: input.metadata ?? undefined,
      },
    });
    return this.mapUser(user);
  }

  async findUserById(id: string): Promise<AuthUser | null> {
    const user = await this.prisma.authUser.findFirst({
      where: { id, deletedAt: null },
    });
    return user ? this.mapUser(user) : null;
  }

  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const user = await this.prisma.authUser.findFirst({
      where: { email, deletedAt: null },
    });
    return user ? this.mapUser(user) : null;
  }

  async updateUser(id: string, input: UpdateUserInput & { passwordHash?: string }): Promise<AuthUser> {
    const user = await this.prisma.authUser.update({
      where: { id },
      data: {
        ...input,
        updatedAt: new Date(),
      },
    });
    return this.mapUser(user);
  }

  async softDeleteUser(id: string): Promise<void> {
    await this.prisma.authUser.update({
      where: { id },
      data: { deletedAt: new Date() },
    });
  }

  // ─── Sessions ────────────────────────────────────────────

  async createSession(input: CreateSessionInput): Promise<AuthSession> {
    const now = new Date();
    const ttl = input.rememberMe ? 30 * 24 * 3600 : 7 * 24 * 3600;

    const session = await this.prisma.authSession.create({
      data: {
        userId: input.userId,
        refreshTokenJti: input.refreshTokenJti,
        tokenFamily: input.tokenFamily,
        ipAddress: input.ipAddress,
        userAgent: input.userAgent,
        deviceName: input.deviceName ?? null,
        rememberMe: input.rememberMe,
        expiresAt: new Date(now.getTime() + ttl * 1000),
        lastActiveAt: now,
      },
    });
    return this.mapSession(session);
  }

  async findSessionById(id: string): Promise<AuthSession | null> {
    const session = await this.prisma.authSession.findUnique({ where: { id } });
    return session ? this.mapSession(session) : null;
  }

  async findSessionsByUserId(userId: string): Promise<AuthSession[]> {
    const sessions = await this.prisma.authSession.findMany({ where: { userId } });
    return sessions.map(this.mapSession);
  }

  async updateSession(id: string, input: Partial<AuthSession>): Promise<AuthSession> {
    const session = await this.prisma.authSession.update({
      where: { id },
      data: input,
    });
    return this.mapSession(session);
  }

  async revokeSession(id: string): Promise<void> {
    await this.prisma.authSession.update({
      where: { id },
      data: { isRevoked: true },
    });
  }

  async revokeAllUserSessions(userId: string): Promise<void> {
    await this.prisma.authSession.updateMany({
      where: { userId },
      data: { isRevoked: true },
    });
  }

  async deleteExpiredSessions(): Promise<void> {
    await this.prisma.authSession.deleteMany({
      where: { expiresAt: { lt: new Date() } },
    });
  }

  // ─── Token Blacklist ─────────────────────────────────────

  async blacklistToken(jti: string, expiresAt: Date): Promise<void> {
    await this.prisma.authTokenBlacklist.upsert({
      where: { jti },
      create: { jti, expiresAt },
      update: { expiresAt },
    });
  }

  async isTokenBlacklisted(jti: string): Promise<boolean> {
    const record = await this.prisma.authTokenBlacklist.findUnique({ where: { jti } });
    if (!record) return false;
    if (record.expiresAt < new Date()) {
      // Cleanup expired blacklist entry
      await this.prisma.authTokenBlacklist.delete({ where: { jti } }).catch(() => {});
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
    await this.prisma.authVerificationToken.upsert({
      where: { token },
      create: { token, userId, purpose, expiresAt },
      update: { expiresAt },
    });
  }

  async findVerificationToken(token: string) {
    const record = await this.prisma.authVerificationToken.findUnique({ where: { token } });
    if (!record) return null;
    return {
      userId: record.userId as string,
      purpose: record.purpose as string,
      expiresAt: record.expiresAt as Date,
    };
  }

  async deleteVerificationToken(token: string): Promise<void> {
    await this.prisma.authVerificationToken.delete({ where: { token } }).catch(() => {});
  }

  // ─── Mappers ─────────────────────────────────────────────

  private mapUser(raw: any): AuthUser {
    return {
      id: raw.id,
      email: raw.email,
      passwordHash: raw.passwordHash,
      username: raw.username ?? undefined,
      name: raw.name ?? undefined,
      phone: raw.phone ?? undefined,
      roles: raw.roles ?? [],
      permissions: raw.permissions ?? [],
      isEmailVerified: raw.isEmailVerified,
      isLocked: raw.isLocked,
      lockReason: raw.lockReason ?? undefined,
      lockUntil: raw.lockUntil ?? undefined,
      failedLoginAttempts: raw.failedLoginAttempts,
      lastLoginAt: raw.lastLoginAt ?? undefined,
      lastLoginIp: raw.lastLoginIp ?? undefined,
      createdAt: raw.createdAt,
      updatedAt: raw.updatedAt,
      deletedAt: raw.deletedAt ?? undefined,
      metadata: raw.metadata ?? undefined,
    };
  }

  private mapSession(raw: any): AuthSession {
    return {
      id: raw.id,
      userId: raw.userId,
      refreshTokenJti: raw.refreshTokenJti,
      tokenFamily: raw.tokenFamily,
      ipAddress: raw.ipAddress,
      userAgent: raw.userAgent,
      deviceName: raw.deviceName ?? undefined,
      isRevoked: raw.isRevoked,
      expiresAt: raw.expiresAt,
      lastActiveAt: raw.lastActiveAt,
      createdAt: raw.createdAt,
      rememberMe: raw.rememberMe,
    };
  }
}
