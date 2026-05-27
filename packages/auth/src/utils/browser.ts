// ─── Browser/Frontend Utilities ──────────────────────────────
// These utilities are safe to use in browser environments.
// They do NOT import any Node.js built-ins.
//
// Use for:
//   - Decoding access tokens to read claims (UI display)
//   - Storing/retrieving tokens from memory (NOT localStorage)
//   - Checking token expiry on the client side

import { decodeJwt } from 'jose';
import type { AccessTokenPayload } from '../types/index.js';

// ─── Token Storage ───────────────────────────────────────────
// SECURITY NOTE: Never store tokens in localStorage or sessionStorage.
// These are accessible to JavaScript and vulnerable to XSS.
//
// Recommended approach:
//   - Store access token in memory (JS variable)
//   - Store refresh token in an HttpOnly, Secure, SameSite=Strict cookie
//     (set by the server — JS cannot access it)
//
// This class implements in-memory storage for the access token.

export class BrowserTokenStore {
  private accessToken: string | null = null;
  private expiresAt: Date | null = null;

  set(token: string, expiresAt: Date): void {
    this.accessToken = token;
    this.expiresAt = expiresAt;
  }

  get(): string | null {
    if (!this.accessToken || !this.expiresAt) return null;
    if (new Date() >= this.expiresAt) {
      this.clear();
      return null;
    }
    return this.accessToken;
  }

  isExpired(): boolean {
    if (!this.expiresAt) return true;
    return new Date() >= this.expiresAt;
  }

  /**
   * Returns seconds until the token expires.
   * Returns 0 if already expired.
   */
  expiresInSeconds(): number {
    if (!this.expiresAt) return 0;
    return Math.max(0, Math.floor((this.expiresAt.getTime() - Date.now()) / 1000));
  }

  clear(): void {
    this.accessToken = null;
    this.expiresAt = null;
  }
}

// ─── Client Token Decoder ────────────────────────────────────
// Read claims from a JWT without verifying signature.
// Verification MUST happen on the server. This is for UI display only.

export function decodeAccessToken(token: string): AccessTokenPayload | null {
  try {
    return decodeJwt(token) as unknown as AccessTokenPayload;
  } catch {
    return null;
  }
}

export function isTokenExpired(token: string): boolean {
  const decoded = decodeAccessToken(token);
  if (!decoded) return true;
  return decoded.exp < Math.floor(Date.now() / 1000);
}

export function getTokenExpiryDate(token: string): Date | null {
  const decoded = decodeAccessToken(token);
  if (!decoded) return null;
  return new Date(decoded.exp * 1000);
}

export function getTokenRoles(token: string): string[] {
  return decodeAccessToken(token)?.roles ?? [];
}

export function getTokenPermissions(token: string): string[] {
  return decodeAccessToken(token)?.permissions ?? [];
}

export function hasTokenRole(token: string, role: string): boolean {
  return getTokenRoles(token).includes(role);
}

export function hasTokenPermission(token: string, permission: string): boolean {
  return getTokenPermissions(token).includes(permission);
}

// ─── Auth API Client ─────────────────────────────────────────
// Lightweight fetch-based client for interacting with auth endpoints.
// Works in browser and Node.js (Node 18+).

export interface AuthClientConfig {
  baseUrl: string;
  onTokenRefreshed?: (tokens: { accessToken: string; refreshTokenExpiresAt: Date }) => void;
  onAuthError?: () => void;
}

export class AuthClient {
  private readonly config: AuthClientConfig;
  private readonly store = new BrowserTokenStore();

  constructor(config: AuthClientConfig) {
    this.config = config;
  }

  async register(input: {
    email: string;
    password: string;
    username?: string;
    name?: string;
    phone?: string;
  }) {
    return this.post<{
      user: { id: string; email: string };
      verificationToken?: string;
    }>('/auth/register', input);
  }

  async login(input: {
    email: string;
    password: string;
    rememberMe?: boolean;
  }) {
    const response = await this.post<{
      accessToken: string;
      accessTokenExpiresAt: string;
      user: { id: string; email: string };
      sessionId: string;
    }>('/auth/login', input);

    if (response.success && response.data) {
      this.store.set(
        response.data.accessToken,
        new Date(response.data.accessTokenExpiresAt),
      );
    }

    return response;
  }

  async logout(sessionId: string) {
    const result = await this.post('/auth/logout', { sessionId });
    this.store.clear();
    return result;
  }

  async refresh() {
    const response = await this.post<{
      accessToken: string;
      accessTokenExpiresAt: string;
    }>('/auth/refresh', {});

    if (response.success && response.data) {
      this.store.set(
        response.data.accessToken,
        new Date(response.data.accessTokenExpiresAt),
      );
      this.config.onTokenRefreshed?.({
        accessToken: response.data.accessToken,
        refreshTokenExpiresAt: new Date(response.data.accessTokenExpiresAt),
      });
    } else {
      this.store.clear();
      this.config.onAuthError?.();
    }

    return response;
  }

  getAccessToken(): string | null {
    return this.store.get();
  }

  isAuthenticated(): boolean {
    return this.store.get() !== null;
  }

  getUser() {
    const token = this.store.get();
    return token ? decodeAccessToken(token) : null;
  }

  /**
   * Fetch wrapper that auto-refreshes the access token if expired.
   * Use this for all authenticated API calls.
   */
  async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    let token = this.store.get();

    // Auto-refresh if expired
    if (this.store.isExpired() && token === null) {
      const refreshed = await this.refresh();
      if (!refreshed.success) {
        throw new Error('Session expired. Please log in again.');
      }
      token = this.store.get();
    }

    const headers = new Headers(options.headers);
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    return fetch(url, { ...options, headers });
  }

  private async post<T>(path: string, body: unknown): Promise<{ success: boolean; data?: T; error?: string; message?: string }> {
    try {
      const res = await fetch(`${this.config.baseUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // Include cookies for refresh token
        body: JSON.stringify(body),
      });

      return res.json() as Promise<{ success: boolean; data?: T; error?: string; message?: string }>;
    } catch (err) {
      return { success: false, error: 'NETWORK_ERROR', message: 'Network request failed.' };
    }
  }
}
