import type { AuthShield } from '../core/auth-shield.js';
import type { AccessTokenPayload } from '../types/index.js';
import { toSafeError } from '../errors/index.js';

// ─── Fastify Plugin ──────────────────────────────────────────
// Compatible with Fastify v4+.
// Provides decorateRequest and hooks for auth checking.
//
// Usage:
//   await fastify.register(createFastifyPlugin(auth))
//   fastify.get('/protected', { preHandler: [fastify.authenticate] }, handler)

interface FastifyLike {
  decorateRequest(name: string, value: null): void;
  addHook(hook: string, fn: (...args: unknown[]) => Promise<void>): void;
  authenticate: unknown;
  requireRole: (role: string) => (...args: unknown[]) => Promise<void>;
  requirePermission: (perm: string) => (...args: unknown[]) => Promise<void>;
}

export function createFastifyPlugin(auth: AuthShield) {
  return async function authPlugin(fastify: FastifyLike) {
    fastify.decorateRequest('authUser', null);

    // Authenticate hook — extracts and verifies Bearer token
    const authenticate = async (
      request: { headers: Record<string, string | undefined>; authUser: AccessTokenPayload | null },
      reply: { code: (n: number) => { send: (body: unknown) => void } },
    ) => {
      const authHeader = request.headers['authorization'];
      const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;

      if (!token) {
        reply.code(401).send({ success: false, error: 'TOKEN_INVALID', message: 'No token provided.' });
        return;
      }

      try {
        request.authUser = await auth.verifyAccessToken(token);
      } catch (err) {
        const safe = toSafeError(err);
        reply.code(safe.statusCode).send({ success: false, ...safe });
      }
    };

    (fastify as any).decorate('authenticate', authenticate);

    // Role check factory
    (fastify as any).decorate('requireRole', (role: string) => {
      return async (
        request: { authUser?: AccessTokenPayload },
        reply: { code: (n: number) => { send: (b: unknown) => void } },
      ) => {
        if (!request.authUser) {
          reply.code(401).send({ success: false, error: 'TOKEN_INVALID', message: 'Not authenticated.' });
          return;
        }
        try {
          auth['service'].assertRole(request.authUser.roles, role);
        } catch (err) {
          const safe = toSafeError(err);
          reply.code(safe.statusCode).send({ success: false, ...safe });
        }
      };
    });

    // Permission check factory
    (fastify as any).decorate('requirePermission', (permission: string) => {
      return async (
        request: { authUser?: AccessTokenPayload },
        reply: { code: (n: number) => { send: (b: unknown) => void } },
      ) => {
        if (!request.authUser) {
          reply.code(401).send({ success: false, error: 'TOKEN_INVALID', message: 'Not authenticated.' });
          return;
        }
        try {
          auth['service'].assertPermission(
            request.authUser.roles,
            request.authUser.permissions,
            permission,
          );
        } catch (err) {
          const safe = toSafeError(err);
          reply.code(safe.statusCode).send({ success: false, ...safe });
        }
      };
    });
  };
}
