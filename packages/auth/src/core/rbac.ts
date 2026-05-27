import type { RBACConfig } from '../types/index.js';
import { SecurityError } from '../errors/index.js';

// ─── RBAC Service ────────────────────────────────────────────
// Hierarchical Role-Based Access Control.
// Roles can inherit permissions from other roles.

export class RBACService {
  private readonly config: RBACConfig;
  /** Resolved (flattened) permission set per role, including inherited perms */
  private readonly resolvedPermissions = new Map<string, Set<string>>();

  constructor(config: RBACConfig) {
    this.config = config;
    this.resolve();
  }

  private resolve(): void {
    const visited = new Set<string>();

    const resolveSingle = (roleName: string): Set<string> => {
      if (this.resolvedPermissions.has(roleName)) {
        return this.resolvedPermissions.get(roleName)!;
      }

      if (visited.has(roleName)) {
        // Circular inheritance — return empty set
        return new Set();
      }

      const role = this.config.roles[roleName];
      if (!role) return new Set();

      visited.add(roleName);

      const perms = new Set<string>(role.permissions);

      for (const inherited of role.inherits ?? []) {
        for (const perm of resolveSingle(inherited)) {
          perms.add(perm);
        }
      }

      this.resolvedPermissions.set(roleName, perms);
      visited.delete(roleName);
      return perms;
    };

    for (const roleName of Object.keys(this.config.roles)) {
      resolveSingle(roleName);
    }
  }

  /**
   * Get all permissions for a set of roles (union).
   */
  getPermissionsForRoles(roles: string[]): string[] {
    const all = new Set<string>();
    for (const role of roles) {
      const perms = this.resolvedPermissions.get(role);
      if (perms) {
        for (const p of perms) all.add(p);
      }
    }
    return [...all];
  }

  /**
   * Check if any of the given roles grants the required role.
   */
  hasRole(userRoles: string[], requiredRole: string): boolean {
    return userRoles.includes(requiredRole);
  }

  /**
   * Check if the user's roles grant the required permission.
   */
  hasPermission(userRoles: string[], userPermissions: string[], requiredPermission: string): boolean {
    if (userPermissions.includes(requiredPermission)) return true;

    for (const role of userRoles) {
      const perms = this.resolvedPermissions.get(role);
      if (perms?.has(requiredPermission)) return true;
    }

    return false;
  }

  /**
   * Check required role or throw.
   */
  assertRole(userRoles: string[], requiredRole: string): void {
    if (!this.hasRole(userRoles, requiredRole)) {
      throw new SecurityError(
        'INSUFFICIENT_ROLE',
        `Access denied. Required role: ${requiredRole}`,
      );
    }
  }

  /**
   * Check required permission or throw.
   */
  assertPermission(
    userRoles: string[],
    userPermissions: string[],
    requiredPermission: string,
  ): void {
    if (!this.hasPermission(userRoles, userPermissions, requiredPermission)) {
      throw new SecurityError(
        'INSUFFICIENT_PERMISSIONS',
        `Access denied. Required permission: ${requiredPermission}`,
      );
    }
  }

  getDefaultRole(): string | undefined {
    return this.config.defaultRole;
  }
}
