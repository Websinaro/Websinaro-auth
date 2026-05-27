import crypto from 'node:crypto';
import type {
  AuthSession,
  StorageAdapter,
  CreateSessionInput,
} from '../types/index.js';
import { SessionError } from '../errors/index.js';

// ─── Session Service ─────────────────────────────────────────
// Handles multi-device session management.
// Sessions are stored in the adapter (DB or Redis).
// Each session tracks device, IP, user-agent, and token family.

export interface SessionServiceConfig {
  maxSessionsPerUser: number;
  refreshTokenTtl: number;   // seconds
  rememberMeTtl: number;     // seconds
}

export class SessionService {
  private readonly adapter: StorageAdapter;
  private readonly config: SessionServiceConfig;

  constructor(adapter: StorageAdapter, config: SessionServiceConfig) {
    this.adapter = adapter;
    this.config = config;
  }

  /**
   * Create a new session for a user.
   * Enforces maxSessionsPerUser by revoking the oldest session.
   */
  async createSession(input: CreateSessionInput): Promise<AuthSession> {
    // Enforce session cap
    const existingSessions = await this.adapter.findSessionsByUserId(input.userId);
    const activeSessions = existingSessions.filter(
      (s) => !s.isRevoked && s.expiresAt > new Date(),
    );

    if (activeSessions.length >= this.config.maxSessionsPerUser) {
      // Revoke the oldest active session
      const oldest = activeSessions.sort(
        (a, b) => a.createdAt.getTime() - b.createdAt.getTime(),
      )[0];
      if (oldest) {
        await this.adapter.revokeSession(oldest.id);
      }
    }

    const ttl = input.rememberMe ? this.config.rememberMeTtl : this.config.refreshTokenTtl;

    return this.adapter.createSession({
      ...input,
      tokenFamily: crypto.randomUUID(),
    });
  }

  /**
   * Find an active (non-revoked, non-expired) session.
   */
  async findActiveSession(sessionId: string): Promise<AuthSession> {
    const session = await this.adapter.findSessionById(sessionId);

    if (!session) {
      throw new SessionError('SESSION_NOT_FOUND', 'Session not found.');
    }
    if (session.isRevoked) {
      throw new SessionError('SESSION_REVOKED', 'Session has been revoked.');
    }
    if (session.expiresAt < new Date()) {
      throw new SessionError('SESSION_EXPIRED', 'Session has expired.');
    }

    return session;
  }

  /**
   * Update session activity timestamp and optionally IP/UA.
   */
  async touchSession(
    sessionId: string,
    meta?: { ipAddress?: string; userAgent?: string },
  ): Promise<void> {
    await this.adapter.updateSession(sessionId, {
      lastActiveAt: new Date(),
      ...(meta?.ipAddress ? { ipAddress: meta.ipAddress } : {}),
      ...(meta?.userAgent ? { userAgent: meta.userAgent } : {}),
    });
  }

  /**
   * Revoke a single session by ID.
   */
  async revokeSession(sessionId: string, userId: string): Promise<void> {
    const session = await this.adapter.findSessionById(sessionId);
    if (!session || session.userId !== userId) {
      throw new SessionError('SESSION_NOT_FOUND', 'Session not found.');
    }
    await this.adapter.revokeSession(sessionId);
  }

  /**
   * Revoke ALL sessions for a user (e.g. password change, suspected compromise).
   */
  async revokeAllSessions(userId: string): Promise<void> {
    await this.adapter.revokeAllUserSessions(userId);
  }

  /**
   * List all active sessions for a user (for "manage devices" UIs).
   */
  async listActiveSessions(userId: string): Promise<AuthSession[]> {
    const sessions = await this.adapter.findSessionsByUserId(userId);
    return sessions.filter((s) => !s.isRevoked && s.expiresAt > new Date());
  }

  /**
   * Update the refresh token JTI on rotation.
   */
  async rotateSessionToken(sessionId: string, newJti: string): Promise<void> {
    await this.adapter.updateSession(sessionId, {
      refreshTokenJti: newJti,
      lastActiveAt: new Date(),
    });
  }
}
