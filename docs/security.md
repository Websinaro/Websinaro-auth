# Security Guide — @websinaro/auth

## Design Principles

### 1. No Fallback Secrets

`@websinaro/auth` will throw a `ConfigurationError` at startup if secrets are missing or too short. There are no fallback values, no defaults, no `'dev-secret'` escape hatches.

```ts
// ✅ Correct
const auth = new AuthShield({
  accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!, // loaded from env
  ...
})

// ❌ Will throw ConfigurationError immediately
const auth = new AuthShield({
  accessTokenSecret: '', // empty
  ...
})
```

### 2. Passwords Never Sanitized

Passwords are hashed verbatim. XSS sanitization is never applied to passwords because:
- The raw bytes are what get hashed
- Sanitization would change the input and break future verification
- Argon2id hashing makes passwords safe regardless of content

Only display strings (name, username) are sanitized.

### 3. Timing-Safe Comparisons

All sensitive comparisons use `crypto.timingSafeEqual` to prevent timing side-channel attacks that could leak information about valid credentials.

### 4. Internal Errors Never Exposed

Every error has two messages:
- `publicMessage` — safe to send to clients (generic, no internals)
- `internalDetails` — logged server-side only, never serialized to HTTP responses

Use `toSafeError(err)` in your error handlers to convert any error into a safe client response.

---

## Token Security

### Access Tokens (15 min default)
- Signed with HS256 using `accessTokenSecret`
- Contain: userId, email, roles, permissions, sessionId, JTI
- Verified on every protected request
- Checked against blacklist

### Refresh Tokens (7 days default)
- Signed with separate `refreshTokenSecret`
- **Single use** — blacklisted after each use
- Carry a `family` claim for rotation chain tracking

### Token Rotation
Every refresh operation:
1. Verifies the refresh token signature and expiry
2. Checks the JTI against the blacklist
3. Verifies the token family matches the session record
4. Blacklists the old refresh token
5. Issues a new token pair

### Reuse Detection
If a blacklisted refresh token is presented (replay attack):
1. **All sessions for that user are immediately revoked**
2. `TOKEN_REUSE_DETECTED` error is thrown
3. `session.all_revoked` event is emitted

This is the correct response to token theft: assume the attacker has the token, invalidate everything, force re-login.

### Token Family
Each session carries a `tokenFamily` UUID. If the family in a presented refresh token doesn't match the session record, all sessions are revoked. This detects refresh token substitution attacks.

---

## Password Security

### Argon2id
Argon2id is used for all password hashing:
- Winner of the Password Hashing Competition (PHC)
- Memory-hard — resists GPU/ASIC brute force
- Side-channel resistant
- Default parameters: 64MB memory, 3 iterations, 4 parallelism

### Strength Validation
Passwords are checked for:
- Minimum length (configurable, default 8)
- Maximum length (128 — prevents DoS via bcrypt-style length issues)
- Must contain at least one letter and one number
- Checked against common/breached password list

In production, extend with the HaveIBeenPwned k-anonymity API:

```ts
async function checkHibp(password: string): Promise<boolean> {
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase()
  const prefix = hash.slice(0, 5)
  const suffix = hash.slice(5)
  
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`)
  const text = await res.text()
  
  return text.split('\n').some(line => line.startsWith(suffix))
}
```

---

## Session Security

### Multi-Device Sessions
- Each device gets its own session with separate refresh token
- Sessions carry IP address and user-agent for audit purposes
- `maxSessionsPerUser` prevents session sprawl (oldest revoked on cap)

### Session Revocation
| Trigger | Action |
|---|---|
| Logout | Revoke single session |
| Password change | Revoke ALL sessions |
| Password reset | Revoke ALL sessions |
| Token reuse detected | Revoke ALL sessions |
| Admin action | Revoke selected session(s) |

---

## Rate Limiting

Login and password-reset endpoints are rate-limited per IP using a sliding window algorithm.

With Redis: distributed across all server instances (consistent limits).
Without Redis: per-instance only (use Redis in production).

Default login limits:
- 5 attempts per 5-minute window
- 15-minute block on exceeding limit
- Counter resets on successful login

---

## CSRF Protection

When `enableCsrf: true`, `@websinaro/auth` uses the **Double Submit HMAC** pattern:

1. Server generates a random `secret` and its HMAC as `token`
2. `secret` → HttpOnly cookie (JS can't read it)
3. `token` → response body / header (JS sends it back in `X-CSRF-Token` header)
4. Server computes HMAC of the cookie secret and compares with the submitted token using `timingSafeEqual`

This is immune to CSRF because:
- An attacker can't read the HttpOnly cookie from another origin
- Without the cookie secret, they can't compute a valid HMAC token
- The comparison is timing-safe

---

## Account Lockout

After `maxLoginAttempts` consecutive failures:
- Account is locked for `lockDurationSeconds`
- `user.locked` event is emitted
- Lock is automatically lifted after the duration expires on the next login attempt
- Successful login resets the failure counter

---

## XSS Mitigation

- Refresh tokens stored in **HttpOnly cookies** — inaccessible to JavaScript
- Access tokens stored in **memory** (not localStorage/sessionStorage)
- All display strings sanitized with `xss` library before storage
- Passwords, tokens, and emails are never XSS-sanitized

---

## Security Headers

Add these headers in production (via helmet for Express):

```ts
import helmet from 'helmet'

app.use(helmet({
  contentSecurityPolicy: true,
  crossOriginEmbedderPolicy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}))
```

---

## Secret Rotation

To rotate JWT secrets without forcing all users to log out:

1. Add `accessTokenSecretOld` to config (verify with old secret as fallback)
2. Deploy new secret in `accessTokenSecret`
3. Wait for all existing access tokens to expire (15 min)
4. Remove `accessTokenSecretOld`

Refresh tokens require more care — a full rotation forces re-login:
1. Revoke all existing sessions (`revokeAllSessions` per user or DB truncate)
2. Rotate `refreshTokenSecret`
3. All users must log in again

This is expected for security incidents. Document it in your runbook.
