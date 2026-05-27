import { describe, it, expect } from 'vitest';
import { RBACService } from '../../src/core/rbac.js';
import { SecurityError } from '../../src/errors/index.js';
import type { RBACConfig } from '../../src/types/index.js';

const config: RBACConfig = {
  defaultRole: 'viewer',
  roles: {
    superadmin: {
      name: 'superadmin',
      permissions: ['*'],
      inherits: ['admin'],
    },
    admin: {
      name: 'admin',
      permissions: ['users.manage', 'settings.manage'],
      inherits: ['editor'],
    },
    editor: {
      name: 'editor',
      permissions: ['posts.create', 'posts.edit', 'posts.delete'],
      inherits: ['viewer'],
    },
    viewer: {
      name: 'viewer',
      permissions: ['posts.read', 'comments.read'],
    },
  },
};

describe('RBACService', () => {
  const rbac = new RBACService(config);

  describe('hasRole', () => {
    it('returns true when user has the role', () => {
      expect(rbac.hasRole(['admin', 'viewer'], 'admin')).toBe(true);
    });

    it('returns false when user does not have the role', () => {
      expect(rbac.hasRole(['viewer'], 'admin')).toBe(false);
    });
  });

  describe('hasPermission — direct', () => {
    it('returns true for a directly-granted permission', () => {
      expect(rbac.hasPermission(['editor'], [], 'posts.create')).toBe(true);
    });

    it('returns false for a permission not in the role', () => {
      expect(rbac.hasPermission(['viewer'], [], 'posts.create')).toBe(false);
    });
  });

  describe('hasPermission — inherited', () => {
    it('editor inherits posts.read from viewer', () => {
      expect(rbac.hasPermission(['editor'], [], 'posts.read')).toBe(true);
    });

    it('admin inherits posts.create from editor', () => {
      expect(rbac.hasPermission(['admin'], [], 'posts.create')).toBe(true);
    });

    it('admin inherits posts.read from viewer (two hops)', () => {
      expect(rbac.hasPermission(['admin'], [], 'posts.read')).toBe(true);
    });

    it('superadmin inherits everything', () => {
      expect(rbac.hasPermission(['superadmin'], [], 'users.manage')).toBe(true);
      expect(rbac.hasPermission(['superadmin'], [], 'posts.read')).toBe(true);
    });
  });

  describe('hasPermission — user-level permissions', () => {
    it('respects direct user permissions regardless of role', () => {
      expect(rbac.hasPermission(['viewer'], ['admin.custom'], 'admin.custom')).toBe(true);
    });
  });

  describe('getPermissionsForRoles', () => {
    it('returns union of permissions for multiple roles', () => {
      const perms = rbac.getPermissionsForRoles(['viewer', 'editor']);
      expect(perms).toContain('posts.read');
      expect(perms).toContain('posts.create');
      expect(perms).toContain('posts.edit');
    });

    it('returns empty array for unknown role', () => {
      expect(rbac.getPermissionsForRoles(['nonexistent'])).toEqual([]);
    });
  });

  describe('assertRole', () => {
    it('does not throw when role matches', () => {
      expect(() => rbac.assertRole(['admin'], 'admin')).not.toThrow();
    });

    it('throws SecurityError when role is missing', () => {
      expect(() => rbac.assertRole(['viewer'], 'admin')).toThrow(SecurityError);
    });

    it('thrown error has INSUFFICIENT_ROLE code', () => {
      expect(() => rbac.assertRole(['viewer'], 'admin')).toThrowError(
        expect.objectContaining({ code: 'INSUFFICIENT_ROLE' }),
      );
    });
  });

  describe('assertPermission', () => {
    it('does not throw when permission is granted via role', () => {
      expect(() => rbac.assertPermission(['editor'], [], 'posts.edit')).not.toThrow();
    });

    it('does not throw when permission is directly granted', () => {
      expect(() => rbac.assertPermission(['viewer'], ['special.access'], 'special.access')).not.toThrow();
    });

    it('throws SecurityError when permission is missing', () => {
      expect(() => rbac.assertPermission(['viewer'], [], 'users.manage')).toThrow(SecurityError);
    });

    it('thrown error has INSUFFICIENT_PERMISSIONS code', () => {
      expect(() => rbac.assertPermission(['viewer'], [], 'users.manage')).toThrowError(
        expect.objectContaining({ code: 'INSUFFICIENT_PERMISSIONS' }),
      );
    });
  });

  describe('getDefaultRole', () => {
    it('returns the configured default role', () => {
      expect(rbac.getDefaultRole()).toBe('viewer');
    });

    it('returns undefined when no default is set', () => {
      const r = new RBACService({ roles: {} });
      expect(r.getDefaultRole()).toBeUndefined();
    });
  });

  describe('circular inheritance guard', () => {
    it('does not infinite-loop on circular role inheritance', () => {
      const circular: RBACConfig = {
        roles: {
          a: { name: 'a', permissions: ['x'], inherits: ['b'] },
          b: { name: 'b', permissions: ['y'], inherits: ['a'] },
        },
      };
      expect(() => new RBACService(circular)).not.toThrow();
    });
  });
});
