import { z } from 'zod';
import xss from 'xss';
import { ValidationError } from '../errors/index.js';

// ─── Sanitization helpers ────────────────────────────────────
// IMPORTANT: Only sanitize display/user content. NEVER sanitize:
//   - passwords (must be compared verbatim)
//   - tokens (exact bytes matter)
//   - emails (case-normalised separately)

export function sanitizeDisplayString(value: string): string {
  return xss(value.trim());
}

export function normalizeEmail(email: string): string {
  // Trim whitespace and lowercase only — do NOT xss-sanitize
  return email.trim().toLowerCase();
}

// ─── Schemas ─────────────────────────────────────────────────

const emailSchema = z
  .string({ required_error: 'Email is required' })
  .email('Invalid email format')
  .max(254, 'Email too long');

const passwordSchema = (minLength: number) =>
  z
    .string({ required_error: 'Password is required' })
    .min(minLength, `Password must be at least ${minLength} characters`)
    .max(128, 'Password too long');

export const usernameSchema = z
  .string()
  .min(3, 'Username must be at least 3 characters')
  .max(30, 'Username too long')
  .regex(/^[a-zA-Z0-9_-]+$/, 'Username may only contain letters, numbers, underscores and hyphens')
  .optional();

export const nameSchema = z
  .string()
  .min(1, 'Name cannot be empty')
  .max(100, 'Name too long')
  .optional();

export const phoneSchema = z
  .string()
  .regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format (E.164)')
  .optional();

// ─── Register schema factory ─────────────────────────────────

export function buildRegisterSchema(passwordMinLength: number) {
  return z.object({
    email: emailSchema,
    password: passwordSchema(passwordMinLength),
    username: usernameSchema,
    name: nameSchema,
    phone: phoneSchema,
  });
}

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string({ required_error: 'Password is required' }).min(1, 'Password is required'),
  rememberMe: z.boolean().optional(),
  ipAddress: z.string().min(1),
  userAgent: z.string().min(1),
});

export const refreshSchema = z.object({
  refreshToken: z.string({ required_error: 'Refresh token is required' }).min(1),
  ipAddress: z.string().min(1),
  userAgent: z.string().min(1),
});

export const passwordChangeSchema = (minLength: number) =>
  z.object({
    userId: z.string().min(1),
    currentPassword: z.string().min(1),
    newPassword: passwordSchema(minLength),
  });

export const passwordResetSchema = (minLength: number) =>
  z.object({
    token: z.string().min(1),
    newPassword: passwordSchema(minLength),
  });

export const passwordResetRequestSchema = z.object({
  email: emailSchema,
});

// ─── Validator class ─────────────────────────────────────────

export class AuthValidator {
  private readonly passwordMinLength: number;

  constructor(passwordMinLength = 8) {
    this.passwordMinLength = passwordMinLength;
  }

  validateRegister(input: unknown) {
    const schema = buildRegisterSchema(this.passwordMinLength);
    const result = schema.safeParse(input);
    if (!result.success) {
      throw new ValidationError(result.error.flatten().fieldErrors as Record<string, string[]>);
    }
    // Sanitize display fields; leave password and email untouched (normalised below)
    return {
      email: normalizeEmail(result.data.email),
      password: result.data.password, // Never sanitize password
      username: result.data.username ? sanitizeDisplayString(result.data.username) : undefined,
      name: result.data.name ? sanitizeDisplayString(result.data.name) : undefined,
      phone: result.data.phone,
    };
  }

  validateLogin(input: unknown) {
    const result = loginSchema.safeParse(input);
    if (!result.success) {
      throw new ValidationError(result.error.flatten().fieldErrors as Record<string, string[]>);
    }
    return {
      ...result.data,
      email: normalizeEmail(result.data.email),
      // password is NOT sanitized
    };
  }

  validateRefresh(input: unknown) {
    const result = refreshSchema.safeParse(input);
    if (!result.success) {
      throw new ValidationError(result.error.flatten().fieldErrors as Record<string, string[]>);
    }
    return result.data;
  }

  validatePasswordChange(input: unknown) {
    const schema = passwordChangeSchema(this.passwordMinLength);
    const result = schema.safeParse(input);
    if (!result.success) {
      throw new ValidationError(result.error.flatten().fieldErrors as Record<string, string[]>);
    }
    return result.data;
  }

  validatePasswordReset(input: unknown) {
    const schema = passwordResetSchema(this.passwordMinLength);
    const result = schema.safeParse(input);
    if (!result.success) {
      throw new ValidationError(result.error.flatten().fieldErrors as Record<string, string[]>);
    }
    return result.data;
  }

  validatePasswordResetRequest(input: unknown) {
    const result = passwordResetRequestSchema.safeParse(input);
    if (!result.success) {
      throw new ValidationError(result.error.flatten().fieldErrors as Record<string, string[]>);
    }
    return { email: normalizeEmail(result.data.email) };
  }
}
