# Production Guide — @websinaro/auth

This guide covers everything needed to deploy `@websinaro/auth` safely in production.

---

## Environment Variables

Generate strong secrets:

```bash
# Generate secrets (run separately for each)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# or
openssl rand -hex 64
```

Required environment variables:

```env
# Secrets — NEVER commit these
ACCESS_TOKEN_SECRET=<64-char hex>
REFRESH_TOKEN_SECRET=<64-char hex>

# JWT config
JWT_ISSUER=my-app
JWT_AUDIENCE=my-app-api

# Database
DATABASE_URL=postgresql://user:pass@host:5432/myapp?sslmode=require

# Redis
REDIS_URL=redis://:password@host:6379/0

# App
NODE_ENV=production
PORT=3000
```

---

## Recommended Production Stack

| Concern | Recommendation |
|---|---|
| Database | PostgreSQL via **PrismaAuthAdapter** |
| Token blacklist | **Redis** via IoRedisAdapter |
| Rate limiting | **Redis** (distributed, multi-server) |
| Access token storage | **JS memory** only |
| Refresh token storage | **HttpOnly, Secure, SameSite=Strict cookie** |
| HTTPS | Required — TLS termination at load balancer |
| Password hashing | **Argon2id** (default) |
| Audit logs | Structured JSON → your log collector (Datadog, CloudWatch, etc.) |

---

## Redis Setup

```ts
import Redis from 'ioredis'
import { IoRedisAdapter } from '@websinaro/auth'

const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: 6379,
  password: process.env.REDIS_PASSWORD,
  tls: {}, // enable TLS for Redis in production
  retryStrategy: (times) => Math.min(times * 50, 2000),
})

redis.on('error', (err) => {
  console.error('[Redis] Connection error:', err)
})

export const redisAdapter = new IoRedisAdapter(redis)
```

Redis enables:
- **Distributed rate limiting** — consistent across multiple server instances
- **Token blacklist** — revoked tokens rejected on all instances
- **Distributed session state** — no single-server bottleneck

---

## Prisma Setup

1. Install:
```bash
npm install @websinaro/auth-prisma @prisma/client
```

2. Add the auth schema to your `prisma/schema.prisma`:
```prisma
// Copy contents from packages/prisma-adapter/prisma/schema.prisma
```

3. Run migrations:
```bash
npx prisma migrate deploy
```

4. Use in your app:
```ts
import { PrismaClient } from '@prisma/client'
import { PrismaAuthAdapter } from '@websinaro/auth-prisma'

const prisma = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query'] : ['error'],
})

const adapter = new PrismaAuthAdapter(prisma)
```

---

## Horizontal Scaling

`@websinaro/auth` is designed for horizontal scaling:

- All state lives in the database and Redis — no in-process state
- Multiple instances can share the same Redis and database
- Rate limiting is distributed when Redis is configured
- Token blacklist is shared across all instances via Redis

**With Redis (recommended):**
```
Instance 1 ─┐
Instance 2 ─┤── Redis ── PostgreSQL
Instance 3 ─┘
```

**Without Redis (single server only):**
```
Instance ── PostgreSQL
```

---

## Docker

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json .

# Never run as root
USER node

EXPOSE 3000
CMD ["node", "dist/index.js"]
```

```yaml
# docker-compose.yml
services:
  app:
    build: .
    environment:
      - ACCESS_TOKEN_SECRET=${ACCESS_TOKEN_SECRET}
      - REFRESH_TOKEN_SECRET=${REFRESH_TOKEN_SECRET}
      - DATABASE_URL=postgresql://auth:auth@postgres:5432/auth
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: auth
      POSTGRES_PASSWORD: auth
      POSTGRES_DB: auth

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
```

---

## Kubernetes

Health check endpoint: `GET /health` returns `{ status: 'ok' }`.

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 3000
  initialDelaySeconds: 10
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /health
    port: 3000
  initialDelaySeconds: 5
  periodSeconds: 10
```

Secrets via Kubernetes Secrets (never in configmaps):
```yaml
env:
  - name: ACCESS_TOKEN_SECRET
    valueFrom:
      secretKeyRef:
        name: auth-secrets
        key: access-token-secret
  - name: REFRESH_TOKEN_SECRET
    valueFrom:
      secretKeyRef:
        name: auth-secrets
        key: refresh-token-secret
```

---

## Session Cleanup

Add a scheduled job to clean up expired sessions and token blacklist entries:

```ts
// Run every hour (e.g. via cron or a queue worker)
async function cleanup() {
  await adapter.deleteExpiredSessions()
  // Prisma adapter: also clean expired blacklist entries
}

setInterval(cleanup, 60 * 60 * 1000)
```

---

## Audit Log Integration

By default, audit events are written to stdout as structured JSON.
Feed them into your log collector:

```ts
import { AuditLogger } from '@websinaro/auth'

// Custom writer — persist to database
const audit = new AuditLogger(true, async (entry) => {
  await prisma.authAuditLog.create({ data: entry })
})
```

---

## Security Checklist

- [ ] `ACCESS_TOKEN_SECRET` is ≥64 chars, random, stored as an env secret
- [ ] `REFRESH_TOKEN_SECRET` is ≥64 chars, random, stored as an env secret
- [ ] HTTPS enforced in production
- [ ] Refresh token stored in HttpOnly, Secure, SameSite=Strict cookie
- [ ] Access token stored only in JavaScript memory (not localStorage)
- [ ] Redis configured for distributed rate limiting
- [ ] Prisma adapter used (not MemoryAdapter)
- [ ] `requireEmailVerification: true` for sensitive applications
- [ ] `enableAuditLog: true` and logs collected
- [ ] Regular secret rotation procedure documented
- [ ] `maxLoginAttempts` tuned for your risk tolerance
- [ ] CORS configured to your domain only
- [ ] Rate limiting on all public auth endpoints
- [ ] Session cleanup job scheduled
