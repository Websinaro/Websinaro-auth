import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { AuthShield } from '../core/auth-shield.js';
import type { AccessTokenPayload, MiddlewareOptions } from '../types/index.js';
import { toSafeError, isAuthError } from '../errors/index.js';

// ─── Express Middleware ──────────────────────────────────────
// Augments Express Request with authUser for downstream handlers.

declare global {
  namespace Express {
    interface Request {
      authUser?: AccessTokenPayload;
    }
  }
}

export function createExpressMiddleware(auth: AuthShield) {
  /**
   * auth.middleware()
   * Verifies the Bearer token in Authorization header.
   * Sets req.authUser on success.
   */
  function middleware(options: MiddlewareOptions = {}): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const authHeader = req.headers['authorization'];
      const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;

      if (!token) {
        if (options.optional) {
          return next();
        }
        res.status(401).json({ success: false, error: 'TOKEN_INVALID', message: 'No token provided.' });
        return;
      }

      try {
        req.authUser = await auth.verifyAccessToken(token);
        next();
      } catch (err) {
        const safe = toSafeError(err);
        res.status(safe.statusCode).json({ success: false, ...safe });
      }
    };
  }

  /**
   * auth.requireRole("admin")
   * Must be used after auth.middleware().
   */
  function requireRole(role: string): RequestHandler {
    return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.authUser) {
        res.status(401).json({ success: false, error: 'TOKEN_INVALID', message: 'Not authenticated.' });
        return;
      }
      try {
        auth.service.assertRole(req.authUser.roles, role);
        next();
      } catch (err) {
        const safe = toSafeError(err);
        res.status(safe.statusCode).json({ success: false, ...safe });
      }
    };
  }

  /**
   * auth.requirePermission("posts.delete")
   * Must be used after auth.middleware().
   */
  function requirePermission(permission: string): RequestHandler {
    return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.authUser) {
        res.status(401).json({ success: false, error: 'TOKEN_INVALID', message: 'Not authenticated.' });
        return;
      }
      try {
        auth.service.assertPermission(
          req.authUser.roles,
          req.authUser.permissions,
          permission,
        );
        next();
      } catch (err) {
        const safe = toSafeError(err);
        res.status(safe.statusCode).json({ success: false, ...safe });
      }
    };
  }

  return { middleware, requireRole, requirePermission };
}
