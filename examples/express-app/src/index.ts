import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import {
  AuthShield,
  MemoryAdapter,
  createExpressMiddleware,
  toSafeError,
  isAuthError,
} from '@websinaro/auth';
import type { Request, Response, NextFunction } from 'express';

// ─── Startup validation ──────────────────────────────────────

const {
  ACCESS_TOKEN_SECRET,
  REFRESH_TOKEN_SECRET,
  PORT = '3000',
  JWT_ISSUER = 'my-app',
  JWT_AUDIENCE = 'my-app-api',
} = process.env;

if (!ACCESS_TOKEN_SECRET || !REFRESH_TOKEN_SECRET) {
  console.error('[FATAL] ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET must be set in environment.');
  process.exit(1);
}

// ─── Auth setup ──────────────────────────────────────────────

const adapter = new MemoryAdapter(); // Swap for PrismaAuthAdapter in production

const auth = new AuthShield({
  accessTokenSecret: ACCESS_TOKEN_SECRET,
  refreshTokenSecret: REFRESH_TOKEN_SECRET,
  issuer: JWT_ISSUER,
  audience: JWT_AUDIENCE,
  adapter,
  enableAuditLog: true,
  requireEmailVerification: process.env['REQUIRE_EMAIL_VERIFICATION'] === 'true',
  maxLoginAttempts: 5,
  lockDurationSeconds: 900,
  rbac: {
    defaultRole: 'user',
    roles: {
      admin: {
        name: 'admin',
        permissions: ['users.manage', 'posts.delete', 'settings.manage'],
        inherits: ['editor'],
      },
      editor: {
        name: 'editor',
        permissions: ['posts.create', 'posts.edit'],
        inherits: ['user'],
      },
      user: {
        name: 'user',
        permissions: ['posts.read', 'profile.edit'],
      },
    },
  },
});

// ─── Wire up events ──────────────────────────────────────────

auth.on('user.registered', ({ userId, email }) => {
  console.log(`[Auth] New user registered: ${email} (${userId})`);
  // TODO: Send welcome email
});

auth.on('user.login_failed', ({ email, ip, reason }) => {
  console.warn(`[Auth] Login failed for ${email} from ${ip}: ${reason}`);
});

auth.on('user.locked', ({ userId, reason }) => {
  console.warn(`[Auth] Account locked: ${userId} — ${reason}`);
  // TODO: Send account lock notification email
});

auth.on('security.suspicious_login', ({ userId, ip, reason }) => {
  console.error(`[Auth] Suspicious login for ${userId} from ${ip}: ${reason}`);
  // TODO: Alert security team
});

// ─── Middleware factories ────────────────────────────────────

const { middleware, requireRole, requirePermission } = createExpressMiddleware(auth);

// ─── Express app ─────────────────────────────────────────────

const app = express();

app.use(cors({
  origin: process.env['APP_URL'] ?? 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// ─── Auth routes ─────────────────────────────────────────────

const authRouter = express.Router();

// POST /auth/register
authRouter.post('/register', async (req: Request, res: Response) => {
  try {
    const result = await auth.register(req.body, {
      ip: req.ip ?? '0.0.0.0',
      userAgent: req.headers['user-agent'],
    });
    res.status(201).json(result);
  } catch (err) {
    const safe = toSafeError(err);
    res.status(safe.statusCode).json({ success: false, ...safe });
  }
});

// POST /auth/login
authRouter.post('/login', async (req: Request, res: Response) => {
  try {
    const result = await auth.login({
      ...req.body,
      ipAddress: req.ip ?? '0.0.0.0',
      userAgent: req.headers['user-agent'] ?? '',
    });

    if (result.success) {
      // Store refresh token in HttpOnly cookie — inaccessible to JavaScript
      res.cookie('refresh_token', result.data.refreshToken, {
        httpOnly: true,
        secure: process.env['NODE_ENV'] === 'production',
        sameSite: 'strict',
        maxAge: (req.body.rememberMe ? 30 : 7) * 24 * 3600 * 1000,
        path: '/auth/refresh',
      });

      // Return access token in body (stored in memory by the client)
      const { refreshToken: _, ...safeData } = result.data;
      res.json({ success: true, data: safeData });
    } else {
      res.status(401).json(result);
    }
  } catch (err) {
    const safe = toSafeError(err);
    res.status(safe.statusCode).json({ success: false, ...safe });
  }
});

// POST /auth/refresh
authRouter.post('/refresh', async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies['refresh_token'] as string | undefined;
    if (!refreshToken) {
      res.status(401).json({ success: false, error: 'TOKEN_INVALID', message: 'No refresh token.' });
      return;
    }

    const result = await auth.refresh({
      refreshToken,
      ipAddress: req.ip ?? '0.0.0.0',
      userAgent: req.headers['user-agent'] ?? '',
    });

    if (result.success) {
      res.cookie('refresh_token', result.data.refreshToken, {
        httpOnly: true,
        secure: process.env['NODE_ENV'] === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 3600 * 1000,
        path: '/auth/refresh',
      });

      const { refreshToken: _, ...safeData } = result.data;
      res.json({ success: true, data: safeData });
    } else {
      res.status(401).json(result);
    }
  } catch (err) {
    const safe = toSafeError(err);
    res.status(safe.statusCode).json({ success: false, ...safe });
  }
});

// POST /auth/logout  (requires auth)
authRouter.post('/logout', middleware(), async (req: Request, res: Response) => {
  try {
    await auth.logout(
      { sessionId: req.authUser!.sessionId, userId: req.authUser!.sub },
      { ip: req.ip ?? '0.0.0.0', userAgent: req.headers['user-agent'] },
    );
    res.clearCookie('refresh_token', { path: '/auth/refresh' });
    res.json({ success: true });
  } catch (err) {
    const safe = toSafeError(err);
    res.status(safe.statusCode).json({ success: false, ...safe });
  }
});

// POST /auth/verify-email
authRouter.post('/verify-email', async (req: Request, res: Response) => {
  try {
    const { token } = req.body as { token?: string };
    if (!token) {
      res.status(422).json({ success: false, error: 'VALIDATION_ERROR', message: 'Token required.' });
      return;
    }
    await auth.verifyEmail(token, { ip: req.ip ?? '0.0.0.0' });
    res.json({ success: true });
  } catch (err) {
    const safe = toSafeError(err);
    res.status(safe.statusCode).json({ success: false, ...safe });
  }
});

// POST /auth/request-password-reset
authRouter.post('/request-password-reset', async (req: Request, res: Response) => {
  try {
    const result = await auth.requestPasswordReset(req.body, { ip: req.ip ?? '0.0.0.0' });
    // Always return 200 to prevent user enumeration
    res.json({ success: true, message: 'If that account exists, a reset link has been sent.' });

    if (result.success && result.data.resetToken) {
      // In production: send email with reset link
      console.log(`[Auth] Password reset token for dev: ${result.data.resetToken}`);
    }
  } catch (err) {
    const safe = toSafeError(err);
    res.status(safe.statusCode).json({ success: false, ...safe });
  }
});

// POST /auth/reset-password
authRouter.post('/reset-password', async (req: Request, res: Response) => {
  try {
    await auth.resetPassword(req.body, { ip: req.ip ?? '0.0.0.0' });
    res.json({ success: true, message: 'Password reset successfully.' });
  } catch (err) {
    const safe = toSafeError(err);
    res.status(safe.statusCode).json({ success: false, ...safe });
  }
});

// GET /auth/sessions  (requires auth)
authRouter.get('/sessions', middleware(), async (req: Request, res: Response) => {
  try {
    const sessions = await auth.listSessions(req.authUser!.sub);
    res.json({ success: true, data: sessions });
  } catch (err) {
    const safe = toSafeError(err);
    res.status(safe.statusCode).json({ success: false, ...safe });
  }
});

// DELETE /auth/sessions/:sessionId  (requires auth)
authRouter.delete('/sessions/:sessionId', middleware(), async (req: Request, res: Response) => {
  try {
    await auth.revokeSession(req.params['sessionId']!, req.authUser!.sub, {
      ip: req.ip ?? '0.0.0.0',
    });
    res.json({ success: true });
  } catch (err) {
    const safe = toSafeError(err);
    res.status(safe.statusCode).json({ success: false, ...safe });
  }
});

// ─── Protected API routes (examples) ────────────────────────

const apiRouter = express.Router();

// Public route
apiRouter.get('/posts', (_req, res) => {
  res.json({ success: true, data: [{ id: 1, title: 'Hello World' }] });
});

// Requires any authenticated user
apiRouter.get('/profile', middleware(), (req: Request, res: Response) => {
  res.json({ success: true, data: { user: req.authUser } });
});

// Requires 'editor' role
apiRouter.post('/posts',
  middleware(),
  requireRole('editor'),
  (req: Request, res: Response) => {
    res.status(201).json({ success: true, data: { message: 'Post created', by: req.authUser!.sub } });
  },
);

// Requires 'posts.delete' permission
apiRouter.delete('/posts/:id',
  middleware(),
  requirePermission('posts.delete'),
  (req: Request, res: Response) => {
    res.json({ success: true, data: { message: `Post ${req.params['id']} deleted` } });
  },
);

// Requires 'admin' role
apiRouter.get('/admin/users',
  middleware(),
  requireRole('admin'),
  (_req, res: Response) => {
    res.json({ success: true, data: { message: 'Admin panel' } });
  },
);

// ─── Mount routers ───────────────────────────────────────────

app.use('/auth', authRouter);
app.use('/api', apiRouter);

// ─── Health check ────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── Global error handler ────────────────────────────────────

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const safe = toSafeError(err);
  // Never expose stack traces in production
  res.status(safe.statusCode).json({ success: false, ...safe });
});

// ─── Start ───────────────────────────────────────────────────

app.listen(parseInt(PORT, 10), () => {
  console.log(`[AuthShield] Example app running on http://localhost:${PORT}`);
  console.log(`[AuthShield] Adapter: MemoryAdapter (dev only)`);
});

export default app;
