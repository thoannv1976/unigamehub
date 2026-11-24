/**
 * Admin console accounts: username + password (scrypt), roles, temporary lockout.
 * Stored in COL.adminUsers, document id = normalized username.
 */
import { randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from 'node:crypto';
import { z } from 'zod';
import { COL, type Store } from './store/types.ts';

export type AdminRole = 'owner' | 'admin';

export interface AdminUser {
  [k: string]: unknown;
  username: string;
  displayName: string;
  passwordHash: string;
  role: AdminRole;
  status: 'active' | 'disabled';
  mustChangePassword: boolean;
  failedCount: number;
  lockedUntil: number;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  lastLoginAt?: string;
}

export const USER_LOCK_AFTER = 5;
export const USER_LOCK_MS = 15 * 60 * 1000;
export const PASSWORD_MIN = 10;

export const ROLE_LABEL: Record<AdminRole, string> = { owner: 'Chủ hệ thống', admin: 'Quản trị viên' };

export const normUsername = (v: unknown): string => String(v ?? '').trim().toLowerCase();

export const UserInput = z.object({
  username: z
    .string()
    .transform(normUsername)
    .pipe(z.string().regex(/^[a-z0-9][a-z0-9._-]{2,31}$/, 'Tên đăng nhập 3–32 ký tự: chữ thường, số, dấu . _ -')),
  displayName: z.string().trim().max(100).optional(),
  role: z.enum(['owner', 'admin']).default('admin'),
  password: z.string().optional(),
});

/** Returns an error message, or null when the password is acceptable. */
export function passwordProblem(password: string, username: string): string | null {
  if (password.length < PASSWORD_MIN) return `Mật khẩu cần ít nhất ${PASSWORD_MIN} ký tự.`;
  if (password.length > 200) return 'Mật khẩu quá dài (tối đa 200 ký tự).';
  if (password.toLowerCase().includes(username.toLowerCase())) return 'Mật khẩu không được chứa tên đăng nhập.';
  if (new Set(password).size < 4) return 'Mật khẩu quá đơn giản.';
  return null;
}

/** Readable temporary password (no ambiguous characters), ~95 bits. */
export function tempPassword(): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = randomBytes(16);
  let s = '';
  for (const b of bytes) s += alphabet[b % alphabet.length];
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}`;
}

const scrypt = (pw: string, salt: Buffer, len: number, opts: ScryptOptions) =>
  new Promise<Buffer>((res, rej) => scryptCb(pw.normalize('NFKC'), salt, len, opts, (e, k) => (e ? rej(e) : res(k))));

const PARAMS = { N: 16384, r: 8, p: 1 };

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, 32, { ...PARAMS, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${PARAMS.N}$${PARAMS.r}$${PARAMS.p}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [algo, n, r, p, salt, hash] = stored.split('$');
  if (algo !== 'scrypt' || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64url');
  const key = await scrypt(password, Buffer.from(salt, 'base64url'), expected.length, {
    N: Number(n), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024,
  });
  return key.length === expected.length && timingSafeEqual(key, expected);
}

/** Used when the username does not exist, so a wrong username costs the same time as a wrong password. */
let dummyHash: Promise<string> | null = null;
export const dummyVerify = async (password: string): Promise<void> => {
  dummyHash ??= hashPassword(randomBytes(12).toString('hex'));
  await verifyPassword(password, await dummyHash);
};

export const getUser = (store: Store, username: string) => store.get<AdminUser>(COL.adminUsers, normUsername(username));
export const listUsers = async (store: Store) =>
  (await store.find<AdminUser>(COL.adminUsers, {}, 500)).sort((a, b) => a.username.localeCompare(b.username));

export async function createUser(
  store: Store,
  input: { username: string; displayName?: string; role: AdminRole; password: string; mustChangePassword: boolean; createdBy: string },
): Promise<AdminUser | null> {
  const now = new Date().toISOString();
  const user: AdminUser = {
    username: input.username,
    displayName: input.displayName || input.username,
    passwordHash: await hashPassword(input.password),
    role: input.role,
    status: 'active',
    mustChangePassword: input.mustChangePassword,
    failedCount: 0,
    lockedUntil: 0,
    createdAt: now,
    updatedAt: now,
    createdBy: input.createdBy,
  };
  return (await store.create<AdminUser>(COL.adminUsers, user.username, user)) ? user : null;
}

/** Active owners other than `except` (used to never remove the last owner). */
export async function otherActiveOwners(store: Store, except: string): Promise<number> {
  const owners = await store.find<AdminUser>(COL.adminUsers, { role: 'owner' }, 500);
  return owners.filter((u) => u.status === 'active' && u.username !== except).length;
}
