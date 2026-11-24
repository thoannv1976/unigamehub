import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalJWKSet } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import { buildApp, type HubApp } from '../src/app.ts';
import { type AdminUser, hashPassword, verifyPassword } from '../src/adminUsers.ts';
import { GameSecrets, loadCatalog } from '../src/catalog.ts';
import type { Config } from '../src/config.ts';
import type { Deps } from '../src/deps.ts';
import { ephemeralKeyRing } from '../src/keys.ts';
import { FileStore } from '../src/store/file.ts';
import { COL } from '../src/store/types.ts';

const TOKEN = 'admin-token-for-tests-0123456789';
const NEW_PW = 'Hoa-sen-2026-xanh';

let hub: HubApp;
let deps: Deps;

beforeEach(async () => {
  const cfg: Config = {
    env: 'staging', port: 0, baseUrl: 'https://hub.test', selfUrl: 'https://hub.test', store: 'file', syncInline: false,
    dataDir: mkdtempSync(join(tmpdir(), 'ugh-accounts-')), gamesFile: join(import.meta.dirname, '..', 'config', 'games.json'), adminToken: TOKEN,
  };
  deps = {
    cfg, store: new FileStore(), keys: await ephemeralKeyRing(), catalog: loadCatalog(cfg, { GAMES_ENABLED: 'demo,k26game1' }),
    secrets: new GameSecrets(cfg, {}), platformJwks: () => createLocalJWKSet({ keys: [] }),
    fetch: async () => new Response('', { status: 500 }),
  };
  hub = await buildApp(deps);
});

const form = (data: Record<string, string>) => new URLSearchParams(data).toString();
const post = (url: string, data: Record<string, string>, cookie?: string) =>
  hub.app.inject({ method: 'POST', url, payload: form(data), headers: { 'content-type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}) } });
const get = (url: string, cookie?: string) => hub.app.inject({ method: 'GET', url, headers: cookie ? { cookie } : {} });
const cookieOf = (res: { headers: Record<string, unknown> }) => String(res.headers['set-cookie']).split(';')[0]!;
const csrfOf = (body: string) => /name="csrf" value="([^"]+)"/.exec(body)![1]!;

async function tokenSession() {
  const res = await post('/admin/login', { mode: 'token', token: TOKEN, next: '/admin' });
  expect(res.statusCode).toBe(303);
  const cookie = cookieOf(res);
  return { cookie, csrf: csrfOf((await get('/admin/users', cookie)).body) };
}

/** Creates an account through the console and returns its temporary password. */
async function createViaConsole(username: string, role: 'owner' | 'admin', displayName = '') {
  const { cookie, csrf } = await tokenSession();
  const res = await post('/admin/users', { csrf, username, role, displayName }, cookie);
  expect(res.statusCode).toBe(200);
  return /<pre class="secret">([^<]+)<\/pre>/.exec(res.body)![1]!;
}

async function seedUser(username: string, role: 'owner' | 'admin', password = NEW_PW, extra: Partial<AdminUser> = {}) {
  const now = new Date().toISOString();
  await deps.store.set<AdminUser>(COL.adminUsers, username, {
    username, displayName: username, passwordHash: await hashPassword(password), role, status: 'active', mustChangePassword: false,
    failedCount: 0, lockedUntil: 0, createdAt: now, updatedAt: now, createdBy: 'test', ...extra,
  });
}

async function signIn(username: string, password = NEW_PW) {
  const res = await post('/admin/login', { username, password, next: '/admin' });
  expect(res.statusCode, res.body).toBe(303);
  const cookie = cookieOf(res);
  return { cookie, csrf: csrfOf((await get('/admin', cookie)).body) };
}

describe('password hashing', () => {
  it('uses salted scrypt and verifies', async () => {
    const a = await hashPassword('correct horse battery');
    const b = await hashPassword('correct horse battery');
    expect(a).toMatch(/^scrypt\$16384\$8\$1\$/);
    expect(a).not.toBe(b);
    expect(await verifyPassword('correct horse battery', a)).toBe(true);
    expect(await verifyPassword('correct horse batterx', a)).toBe(false);
  });
});

describe('admin accounts', () => {
  it('shows username + password on the login page, and the token link only while no account exists', async () => {
    const first = await get('/admin/login');
    expect(first.body).toContain('name="username"');
    expect(first.body).toContain('name="password"');
    expect(first.body).not.toContain('name="token"');
    expect(first.body).toContain('/admin/login?mode=token');
    expect((await get('/admin/login?mode=token')).body).toContain('name="token"');
    await seedUser('boss', 'owner');
    expect((await get('/admin/login')).body).not.toContain('mode=token');
  });

  it('bootstraps with the token, forces a password change on first sign-in, then works normally', async () => {
    const temp = await createViaConsole('Thoan.NV', 'owner', 'Nguyễn Văn Thoan');
    const stored = await deps.store.get<AdminUser>(COL.adminUsers, 'thoan.nv');
    expect(stored).toMatchObject({ role: 'owner', status: 'active', mustChangePassword: true, createdBy: 'admin-token' });
    expect(stored!.passwordHash).not.toContain(temp);

    const login = await post('/admin/login', { username: 'thoan.nv', password: temp, next: '/admin/games' });
    expect(login.statusCode).toBe(303);
    expect(login.headers.location).toBe('/admin/password');
    const cookie = cookieOf(login);
    // Every other page and form is blocked until the password is changed.
    expect((await get('/admin/games', cookie)).headers.location).toBe('/admin/password');
    const pwPage = await get('/admin/password', cookie);
    expect(pwPage.body).toContain('mật khẩu tạm');
    const csrf = csrfOf(pwPage.body);
    expect((await post('/admin/sync', { csrf }, cookie)).statusCode).toBe(403);

    expect((await post('/admin/password', { csrf, current: temp, password: 'short', confirm: 'short' }, cookie)).statusCode).toBe(400);
    expect((await post('/admin/password', { csrf, current: temp, password: NEW_PW, confirm: `${NEW_PW}x` }, cookie)).statusCode).toBe(400);
    expect((await post('/admin/password', { csrf, current: 'wrong', password: NEW_PW, confirm: NEW_PW }, cookie)).statusCode).toBe(400);
    const ok = await post('/admin/password', { csrf, current: temp, password: NEW_PW, confirm: NEW_PW }, cookie);
    expect(ok.statusCode).toBe(303);
    expect(ok.headers.location).toBe('/admin?msg=password');

    const overview = await get('/admin', cookie);
    expect(overview.statusCode).toBe(200);
    expect(overview.body).toContain('Nguyễn Văn Thoan');
    expect(overview.body).toContain('href="/admin/users"');
    expect((await post('/admin/login', { username: 'thoan.nv', password: temp })).statusCode).toBe(401);
    expect((await post('/admin/login', { username: 'THOAN.NV', password: NEW_PW })).statusCode).toBe(303);
    const logins = await deps.store.find(COL.audit, { action: 'admin_login', actor: 'thoan.nv' });
    expect(logins.length).toBeGreaterThanOrEqual(2);
  });

  it('gives the same answer for an unknown user and a wrong password', async () => {
    await seedUser('boss', 'owner');
    const unknown = await post('/admin/login', { username: 'nobody', password: 'whatever-123' });
    const wrong = await post('/admin/login', { username: 'boss', password: 'whatever-123' });
    expect(unknown.statusCode).toBe(401);
    expect(wrong.statusCode).toBe(401);
    expect(unknown.body).toContain('Tên đăng nhập hoặc mật khẩu không đúng.');
    expect(wrong.body).toContain('Tên đăng nhập hoặc mật khẩu không đúng.');
    expect(unknown.headers['set-cookie']).toBeUndefined();
  });

  it('locks an account for 15 minutes after 5 wrong passwords', async () => {
    await seedUser('boss', 'owner');
    for (let i = 0; i < 5; i++) expect((await post('/admin/login', { username: 'boss', password: `nope-${i}-xxxxx` })).statusCode).toBe(401);
    const locked = await post('/admin/login', { username: 'boss', password: NEW_PW });
    expect(locked.statusCode).toBe(423);
    expect(locked.headers['set-cookie']).toBeUndefined();
    expect(await deps.store.find(COL.audit, { action: 'admin_user_locked' })).toHaveLength(1);
    // The owner can unlock from the console.
    const { cookie, csrf } = await tokenSession();
    expect((await post('/admin/users/boss/status', { csrf, action: 'unlock' }, cookie)).statusCode).toBe(303);
    expect((await post('/admin/login', { username: 'boss', password: NEW_PW })).statusCode).toBe(303);
  });

  it('keeps account management for owners only', async () => {
    await seedUser('staff', 'admin');
    const { cookie } = await signIn('staff');
    const overview = await get('/admin', cookie);
    expect(overview.body).not.toContain('href="/admin/users"');
    expect((await get('/admin/users', cookie)).statusCode).toBe(403);
    expect((await post('/admin/users', { csrf: csrfOf(overview.body), username: 'evil', role: 'owner' }, cookie)).statusCode).toBe(403);
    expect(await deps.store.get(COL.adminUsers, 'evil')).toBeNull();
    // Everything else works for an admin.
    for (const url of ['/admin/jobs', '/admin/tenants', '/admin/platforms', '/admin/games', '/admin/setup', '/admin/audit', '/admin/password']) {
      expect((await get(url, cookie)).statusCode, url).toBe(200);
    }
  });

  it('disabling an account ends its sessions and blocks sign-in', async () => {
    await seedUser('boss', 'owner');
    await seedUser('staff', 'admin');
    const staff = await signIn('staff');
    const boss = await signIn('boss');
    expect((await post('/admin/users/staff/status', { csrf: boss.csrf, action: 'disable' }, boss.cookie)).statusCode).toBe(303);
    expect((await get('/admin', staff.cookie)).statusCode).toBe(303);
    expect((await post('/admin/login', { username: 'staff', password: NEW_PW })).statusCode).toBe(403);
    expect((await deps.store.find(COL.audit, { action: 'admin_user_disable', actor: 'boss' }))).toHaveLength(1);
  });

  it('resets a password to a new temporary one and ends the old sessions', async () => {
    await seedUser('boss', 'owner');
    await seedUser('staff', 'admin');
    const staff = await signIn('staff');
    const boss = await signIn('boss');
    const res = await post('/admin/users/staff/reset', { csrf: boss.csrf }, boss.cookie);
    const temp = /<pre class="secret">([^<]+)<\/pre>/.exec(res.body)![1]!;
    expect((await get('/admin', staff.cookie)).statusCode).toBe(303);
    expect((await post('/admin/login', { username: 'staff', password: NEW_PW })).statusCode).toBe(401);
    const again = await post('/admin/login', { username: 'staff', password: temp });
    expect(again.headers.location).toBe('/admin/password');
  });

  it('never leaves the system without an active owner, and blocks self-changes', async () => {
    await seedUser('boss', 'owner');
    const { cookie, csrf } = await tokenSession();
    expect((await post('/admin/users/boss/role', { csrf, role: 'admin' }, cookie)).statusCode).toBe(400);
    expect((await post('/admin/users/boss/status', { csrf, action: 'disable' }, cookie)).statusCode).toBe(400);
    await seedUser('boss2', 'owner');
    expect((await post('/admin/users/boss/role', { csrf, role: 'admin' }, cookie)).statusCode).toBe(303);
    expect((await deps.store.get<AdminUser>(COL.adminUsers, 'boss'))!.role).toBe('admin');
    const b2 = await signIn('boss2');
    expect((await post('/admin/users/boss2/status', { csrf: b2.csrf, action: 'disable' }, b2.cookie)).statusCode).toBe(400);
  });

  it('rejects duplicate and invalid usernames', async () => {
    await seedUser('boss', 'owner');
    const { cookie, csrf } = await tokenSession();
    expect((await post('/admin/users', { csrf, username: 'boss', role: 'admin' }, cookie)).statusCode).toBe(409);
    expect((await post('/admin/users', { csrf, username: 'a b', role: 'admin' }, cookie)).statusCode).toBe(400);
    expect((await post('/admin/users', { csrf, username: 'admin-token', role: 'admin' }, cookie)).statusCode).toBe(400);
  });

  it('invalidates sessions created before account sign-in existed', async () => {
    const { cookie } = await tokenSession();
    const [s] = await deps.store.find<Record<string, unknown>>(COL.adminSessions, {});
    const { id, username: _u, role: _r, viaToken: _v, ...legacy } = s!;
    await deps.store.set(COL.adminSessions, id as string, legacy);
    expect((await get('/admin', cookie)).statusCode).toBe(303);
  });

  it('creates accounts through the JSON API with the header token', async () => {
    const headers = { 'content-type': 'application/json', 'x-admin-token': TOKEN };
    expect((await hub.app.inject({ method: 'POST', url: '/api/v1/admin/users', payload: { username: 'boss' } })).statusCode).toBe(401);
    const weak = await hub.app.inject({ method: 'POST', url: '/api/v1/admin/users', headers, payload: { username: 'boss', password: 'short' } });
    expect(weak.statusCode).toBe(400);
    const res = await hub.app.inject({ method: 'POST', url: '/api/v1/admin/users', headers, payload: { username: 'boss', role: 'owner' } });
    expect(res.statusCode).toBe(201);
    const temp = res.json().temporaryPassword as string;
    expect(temp).toMatch(/^[\w]{4}-[\w]{4}-[\w]{4}-[\w]{4}$/);
    expect((await post('/admin/login', { username: 'boss', password: temp })).headers.location).toBe('/admin/password');
  });
});
