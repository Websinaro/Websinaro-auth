import type { AuditLogEntry, AuditAction } from '../types/index.js';

// ─── Audit Logger ────────────────────────────────────────────
// Pluggable audit logging.
// Default implementation writes structured JSON to stdout.
// Replace with a custom writer for DB persistence or external SIEM.

export type AuditWriter = (entry: AuditLogEntry) => void | Promise<void>;

export class AuditLogger {
  private readonly writer: AuditWriter;
  private readonly enabled: boolean;

  constructor(enabled = true, writer?: AuditWriter) {
    this.enabled = enabled;
    this.writer = writer ?? defaultWriter;
  }

  log(
    action: AuditAction,
    params: {
      userId?: string | null;
      ip: string;
      userAgent?: string;
      details?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    if (!this.enabled) return;

    const entry: AuditLogEntry = {
      action,
      userId: params.userId ?? null,
      ip: params.ip,
      userAgent: params.userAgent,
      details: params.details,
      metadata: params.metadata,
      timestamp: new Date(),
    };

    const result = this.writer(entry);
    if (result instanceof Promise) {
      result.catch((err: unknown) => {
        console.error('[AuthShield][AuditLogger] Writer error:', err);
      });
    }
  }
}

function defaultWriter(entry: AuditLogEntry): void {
  const line = JSON.stringify({
    '@timestamp': entry.timestamp.toISOString(),
    level: 'audit',
    action: entry.action,
    userId: entry.userId,
    ip: entry.ip,
    userAgent: entry.userAgent,
    details: entry.details,
    metadata: entry.metadata,
  });
  // Write to stdout — let the process manager / log collector handle it
  process.stdout.write(line + '\n');
}
