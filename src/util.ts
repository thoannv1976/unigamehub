import { createHash, randomBytes } from 'node:crypto';

/** Random URL-safe id. */
export const rid = (bytes = 24): string => randomBytes(bytes).toString('base64url');

/** Stable hashed id from parts, e.g. hid('u', tenant, iss, sub). */
export const hid = (prefix: string, ...parts: string[]): string =>
  `${prefix}_${createHash('sha256').update(parts.join('\u0000')).digest('hex').slice(0, 24)}`;

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (s: unknown): string => String(s ?? '').replace(/[&<>"']/g, (c) => ESC[c]!);

export const nowSec = (): number => Math.floor(Date.now() / 1000);

export class HttpError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message?: string) {
    super(message ?? code);
    this.status = status;
    this.code = code;
  }
}

export const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
