# @websinaro/auth

**Production-grade, enterprise-quality authentication framework for Node.js.**

```ts
import { AuthShield } from '@websinaro/auth'

const auth = new AuthShield({ ...config })
await auth.login({ email, password, ipAddress, userAgent })
```

Simple API. Clean architecture. Secure by default. Ready for production.

---

## Features

| Feature | Status |
|---|---|
| Register / Login / Logout | ✅ |
| JWT Access + Refresh Tokens | ✅ |
| Token Rotation & Revocation | ✅ |
| Refresh Token Reuse Detection | ✅ |
| Multi-device Session Management | ✅ |
| Account Lockout (brute-force protection) | ✅ |
| Rate Limiting (memory + Redis) | ✅ |
| Email Verification | ✅ |
| Password Reset | ✅ |
| Password Change | ✅ |
| Argon2id Password Hashing | ✅ |
| RBAC (Roles + Permissions) | ✅ |
| Hierarchical Role Inheritance | ✅ |
| CSRF Protection | ✅ |
| Audit Logging | ✅ |
| Typed Event System | ✅ |
| Express Middleware | ✅ |
| Fastify Plugin | ✅ |
| Browser/Frontend Utilities | ✅ |
| In-Memory Adapter (dev/test) | ✅ |
| Prisma Adapter (production) | ✅ |
| Redis Support | ✅ |
| ESM + CJS | ✅ |
| Full TypeScript | ✅ |
| Zero fallback secrets | ✅ |

---

## Installation

```bash
# Core package
npm install @websinaro/auth

# Prisma adapter (production)
npm install @websinaro/auth-prisma @prisma/client

# Redis support (production)
npm install ioredis
```

---

## Quick Start

### 1. Create AuthShield

```ts
import { AuthShield, MemoryAdapter } from '@websinaro/auth'

const auth = new AuthShield({
  // Required — never use fallback secrets
  accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  issuer: 'my-app',
  audience: 'my-app-api',

  // Storage adapter
  adapter: new MemoryAdapter(), // use PrismaAuthAdapter in production

  // Optional features
  requireEmailVerification: false,
  enableAuditLog: true,
  maxLoginAttempts: 5,
})
```

### 2. Register & Login

```ts
// Register
await auth.register(
  { email: 'user@example.com', password: 'SecurePass1' },
  { ip: req.ip, userAgent: req.headers['user-agent'] }
)

// Login
const result = await auth.login({
  email: 'user@example.com',
  password: 'SecurePass1',
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
})

if (result.success) {
  const { accessToken, refreshToken, user } = result.data
}
```

### 3. Protect Routes (Express)

```ts
import { createExpressMiddleware } from '@websinaro/auth'

const { middleware, requireRole, requirePermission } = createExpressMiddleware(auth)

// Any authenticated user
app.get('/profile', middleware(), handler)

// Specific role
app.get('/admin', middleware(), requireRole('admin'), handler)

// Specific permission
app.delete('/posts/:id', middleware(), requirePermission('posts.delete'), handler)
```

### 4. Refresh Tokens

```ts
const result = await auth.refresh({
  refreshToken,
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
})
```

---

## Configuration

```ts
interface AuthShieldConfig {
  // ─── Required ──────────────────────────────────────────
  accessTokenSecret: string   // min 32 chars — NO FALLBACKS
  refreshTokenSecret: string  // min 32 chars — NO FALLBACKS
  issuer: string
  audience: string | string[]
  adapter: StorageAdapter

  // ─── Token TTLs (seconds) ──────────────────────────────
  accessTokenTtl?: number     // default: 900 (15 min)
  refreshTokenTtl?: number    // default: 604800 (7 days)
  rememberMeTtl?: number      // default: 2592000 (30 days)

  // ─── Password ─────────────────────────────────────────
  passwordMinLength?: number  // default: 8

  // ─── Account Lockout ──────────────────────────────────
  maxLoginAttempts?: number   // default: 5
  lockDurationSeconds?: number // default: 900 (15 min)

  // ─── Sessions ─────────────────────────────────────────
  maxSessionsPerUser?: number // default: 5

  // ─── Adapters ─────────────────────────────────────────
  redis?: RedisAdapter        // optional, recommended in production

  // ─── RBAC ─────────────────────────────────────────────
  rbac?: RBACConfig

  // ─── Feature Flags ────────────────────────────────────
  requireEmailVerification?: boolean  // default: false
  enableCsrf?: boolean                // default: false
  enableAuditLog?: boolean            // default: true
}
```

---

## RBAC

```ts
const auth = new AuthShield({
  ...config,
  rbac: {
    defaultRole: 'user',
    roles: {
      admin: {
        name: 'admin',
        permissions: ['users.manage'],
        inherits: ['editor'],   // inherits all editor permissions
      },
      editor: {
        name: 'editor',
        permissions: ['posts.create', 'posts.edit'],
        inherits: ['user'],
      },
      user: {
        name: 'user',
        permissions: ['posts.read'],
      },
    },
  },
})

// Check at runtime
auth.hasRole(['admin'], 'admin')                         // true
auth.hasPermission(['editor'], [], 'posts.read')         // true (inherited)
auth.hasPermission(['user'], [], 'posts.create')         // false
```

---

## Events

```ts
auth.on('user.registered', ({ userId, email, ip }) => {
  sendWelcomeEmail(email)
})

auth.on('user.locked', ({ userId, reason, until }) => {
  notifySecurityTeam(userId)
})

auth.on('token.refreshed', ({ userId, sessionId }) => {
  // Update last-seen
})
```

Available events: `user.registered`, `user.login`, `user.logout`, `user.login_failed`,
`user.locked`, `user.unlocked`, `user.email_verified`, `user.password_changed`,
`user.password_reset_requested`, `user.password_reset`, `user.deleted`,
`token.refreshed`, `token.revoked`, `session.revoked`, `session.all_revoked`,
`security.suspicious_login`, `security.rate_limit`

---

## Sessions

```ts
// List active sessions (for "Manage devices" UI)
const sessions = await auth.listSessions(userId)

// Revoke a single session (e.g. "Sign out this device")
await auth.revokeSession(sessionId, userId, { ip })

// Revoke all sessions (e.g. after password change)
await auth.revokeAllSessions(userId, { ip })
```

---

## Frontend / Browser Usage

```ts
import { AuthClient, decodeAccessToken, hasTokenRole } from '@websinaro/auth'

const client = new AuthClient({ baseUrl: 'https://api.myapp.com' })

// Login
await client.login({ email, password })

// Check auth state
client.isAuthenticated()  // boolean
client.getUser()          // decoded token payload

// Role check on frontend (for UI gating — NOT security enforcement)
hasTokenRole(token, 'admin')

// Authenticated fetch (auto-refreshes if expired)
const res = await client.fetch('/api/protected')
```

> **Important:** Token verification for security must always happen on the server.
> Frontend checks are only for UI convenience (show/hide buttons etc.).

---

## Production: Prisma Adapter

```ts
import { PrismaClient } from '@prisma/client'
import { PrismaAuthAdapter } from '@websinaro/auth-prisma'

const prisma = new PrismaClient()
const adapter = new PrismaAuthAdapter(prisma)

const auth = new AuthShield({ adapter, ...config })
```

Run migrations:

```bash
npx prisma migrate dev --schema=node_modules/@websinaro/auth-prisma/prisma/schema.prisma
```

Or copy the schema into your own `prisma/schema.prisma`.

---

## Production: Redis

```ts
import Redis from 'ioredis'
import { IoRedisAdapter } from '@websinaro/auth'

const redis = new Redis(process.env.REDIS_URL)
const redisAdapter = new IoRedisAdapter(redis)

const auth = new AuthShield({
  ...config,
  redis: redisAdapter,  // enables distributed rate limiting + token blacklist
})
```

---

## Secure Cookie Pattern (Recommended)

The recommended token storage strategy:

| Token | Storage | Why |
|---|---|---|
| Access token | JS memory only | Short-lived; never persisted |
| Refresh token | HttpOnly cookie | Invisible to JS; XSS-safe |

```ts
// Server: set refresh token as HttpOnly cookie
res.cookie('refresh_token', refreshToken, {
  httpOnly: true,
  secure: true,          // HTTPS only
  sameSite: 'strict',    // CSRF protection
  maxAge: 7 * 24 * 3600 * 1000,
  path: '/auth/refresh', // only sent to refresh endpoint
})

// Client: store access token in memory
let accessToken = response.data.accessToken  // never localStorage
```

---

## Security Guarantees

- ✅ **No fallback secrets** — throws at startup if secrets missing
- ✅ **Argon2id** password hashing (memory-hard, GPU-resistant)
- ✅ **Timing-safe** password comparison
- ✅ **Token rotation** — each refresh issues a new refresh token
- ✅ **Reuse detection** — replayed refresh token triggers full session revocation
- ✅ **Account lockout** — configurable attempt limits
- ✅ **Rate limiting** — per-IP sliding window (distributed with Redis)
- ✅ **Soft delete** — users are never hard-deleted
- ✅ **Safe errors** — internal details never exposed to clients
- ✅ **Audit log** — all auth events are logged with IP + UA

---

## Error Handling

```ts
import { toSafeError, isAuthError, AuthError } from '@websinaro/auth'

try {
  await auth.login(...)
} catch (err) {
  if (isAuthError(err)) {
    // err.code       — machine-readable (e.g. 'INVALID_CREDENTIALS')
    // err.publicMessage — safe to send to client
    // err.statusCode — HTTP status
  }

  // Or convert any error to a safe response:
  const safe = toSafeError(err)
  res.status(safe.statusCode).json(safe)
}
```

Error codes: `VALIDATION_ERROR`, `USER_NOT_FOUND`, `USER_ALREADY_EXISTS`,
`INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `EMAIL_NOT_VERIFIED`, `TOKEN_INVALID`,
`TOKEN_EXPIRED`, `TOKEN_REVOKED`, `TOKEN_REUSE_DETECTED`, `SESSION_NOT_FOUND`,
`SESSION_EXPIRED`, `SESSION_REVOKED`, `RATE_LIMIT_EXCEEDED`,
`INSUFFICIENT_PERMISSIONS`, `INSUFFICIENT_ROLE`, `PASSWORD_TOO_WEAK`,
`CSRF_INVALID`, `INTERNAL_ERROR`

---

## Custom Storage Adapter

Implement the `StorageAdapter` interface to use any database:

```ts
import type { StorageAdapter } from '@websinaro/auth'

class MyMongoAdapter implements StorageAdapter {
  async createUser(input) { ... }
  async findUserById(id) { ... }
  async findUserByEmail(email) { ... }
  async updateUser(id, input) { ... }
  async softDeleteUser(id) { ... }
  async createSession(input) { ... }
  async findSessionById(id) { ... }
  async findSessionsByUserId(userId) { ... }
  async updateSession(id, input) { ... }
  async revokeSession(id) { ... }
  async revokeAllUserSessions(userId) { ... }
  async deleteExpiredSessions() { ... }
  async blacklistToken(jti, expiresAt) { ... }
  async isTokenBlacklisted(jti) { ... }
  async saveVerificationToken(token, userId, purpose, expiresAt) { ... }
  async findVerificationToken(token) { ... }
  async deleteVerificationToken(token) { ... }
}
```

---

## License

MIT © Websinaro
