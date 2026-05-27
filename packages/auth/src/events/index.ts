import EventEmitter from 'eventemitter3';
import type { AuthEventMap, AuthEventName, AuthEventPayload } from '../types/index.js';

// ─── Typed Auth Event Emitter ────────────────────────────────

export class AuthEventEmitter {
  private readonly emitter = new EventEmitter();

  emit<K extends AuthEventName>(event: K, payload: AuthEventPayload<K>): void {
    this.emitter.emit(event, payload);
  }

  on<K extends AuthEventName>(
    event: K,
    listener: (payload: AuthEventPayload<K>) => void | Promise<void>,
  ): this {
    this.emitter.on(event, (payload: AuthEventPayload<K>) => {
      // Wrap in Promise to handle async listeners safely
      const result = listener(payload);
      if (result instanceof Promise) {
        result.catch((err: unknown) => {
          console.error(`[AuthShield] Unhandled async event listener error for "${event}":`, err);
        });
      }
    });
    return this;
  }

  once<K extends AuthEventName>(
    event: K,
    listener: (payload: AuthEventPayload<K>) => void | Promise<void>,
  ): this {
    this.emitter.once(event, (payload: AuthEventPayload<K>) => {
      const result = listener(payload);
      if (result instanceof Promise) {
        result.catch((err: unknown) => {
          console.error(`[AuthShield] Unhandled async once-listener error for "${event}":`, err);
        });
      }
    });
    return this;
  }

  off<K extends AuthEventName>(
    event: K,
    listener: (payload: AuthEventPayload<K>) => void | Promise<void>,
  ): this {
    this.emitter.off(event, listener as (...args: unknown[]) => void);
    return this;
  }

  removeAllListeners(event?: AuthEventName): this {
    this.emitter.removeAllListeners(event);
    return this;
  }
}
