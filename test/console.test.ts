import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalJWKSet } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import { buildApp, type HubApp } from '../src/app.ts';
import { GameSecrets, loadCatalog } from '../src/catalog.ts';
import type { Config } from '../src/config.ts';
import type { Deps } from '../src/deps.ts';
import { ephemeralKeyRing } from '../src/keys.ts';
import type { Tenant } from '../src/lti/platforms.ts';
import type { SyncJob } from '../src/results.ts';
import { FileStore } from '../src/store/file.ts';
import { COL } from '../src/store/types.ts';

const TOKEN = 'admin-token-for-tests-0123456789';

let hub: HubApp;
let deps: Deps;

beforeEach(async () => {
  const cfg: Config = {
    env: 'staging', port: 0, baseUrl: 'https://hub.test', selfUrl: 'https://hub.test', store: 'file', syncInline: false,
    dataDir: mkdtempSync(join(tmpdir(), 'ugh-console-')), gamesFile: join(import.meta.dirname, '..', 'config', 'games.json'), adminToken: TOKEN,
  };
  deps = {
    cfg, store: new FileStore(), keys: await ephemeralKeyRing(), catalog: loadCatalog(cfg, { GAMES_ENABLED: 'demo,k26game1,k26game2' }),
    secrets: new GameSecrets(cfg, {}), platformJwks: () => createLocalJWKSet({ keys: [] }),
    fetch: async () => new Response('', { status: 500 }),
  };
  hub = await buildApp(deps);
});

const form = (data: Record<string, string | string[]>) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(data)) for (const x of Array.isArray(v) ? v : [v]) p.append(k, x);
  return p.toString();
};
const post = (url: string, data: Record<string, string | string[]>, cookie?: string) =>
  hub.app.inject({ method: 'POST', url, payload: form(data), headers: { 'content-type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}) } });

async function signIn(): Promise<{ cookie: string; csrf: string }> {
  const res = await post('/admin/login', { token: TOKEN, next: '/admin' });
  expect(res.statusCode).toBe(303);
  const setCookie = String(res.headers['set-cookie']);
  const cookie = setCookie.split(';')[0]!;
  const page = await hub.app.inject({ method: 'GET', url: '/admin', headers: { cookie } });
  const csrf = /name="csrf" value="([^"]+)"/.exec(page.body)![1]!;
  return { cookie, csrf };
}

describe('admin console', () => {
  it('shows a public landing page at / instead of an error', async () => {
    const res = await hub.app.inject({ method: 'GET', url: '/' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('UniGame Hub');
    expect(res.body).toContain('href="/admin"');
  });

  it('redirects to the login form when not signed in', async () => {
    const res = await hub.app.inject({ method: 'GET', url: '/admin/jobs?status=dead' });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/admin/login?next=%2Fadmin%2Fjobs%3Fstatus%3Ddead');
    const login = await hub.app.inject({ method: 'GET', url: String(res.headers.location) });
    expect(login.statusCode).toBe(200);
    expect(login.body).toContain('type="password"');
  });

  it('rejects a wrong token and audits it', async () => {
    const res = await post('/admin/login', { token: 'wrong' });
    expect(res.statusCode).toBe(401);
    expect(res.headers['set-cookie']).toBeUndefined();
    const logs = await deps.store.find(COL.audit, { action: 'admin_login_failed' });
    expect(logs).toHaveLength(1);
  });

  it('signs in with a secure session cookie and serves pages with strict headers', async () => {
    const res = await post('/admin/login', { token: TOKEN, next: '/admin/games' });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/admin/games');
    const sc = String(res.headers['set-cookie']);
    expect(sc).toMatch(/^ugh_admin=[\w-]{40,};/);
    expect(sc).toContain('HttpOnly');
    expect(sc).toContain('SameSite=Strict');
    expect(sc).toContain('Secure');
    expect(sc).toContain('Path=/admin');
    const cookie = sc.split(';')[0]!;
    for (const url of ['/admin', '/admin/jobs', '/admin/tenants', '/admin/platforms', '/admin/games', '/admin/setup', '/admin/audit']) {
      const page = await hub.app.inject({ method: 'GET', url, headers: { cookie } });
      expect(page.statusCode, url).toBe(200);
      expect(page.headers['cache-control']).toBe('no-store');
      expect(page.headers['x-frame-options']).toBe('DENY');
      expect(String(page.headers['content-security-policy'])).toContain("frame-ancestors 'none'");
    }
    const games = await hub.app.inject({ method: 'GET', url: '/admin/games', headers: { cookie } });
    expect(games.body).toContain('English Detective');
    // The session id is not stored in clear text.
    const sessions = await deps.store.find(COL.adminSessions, {});
    expect(sessions).toHaveLength(1);
    expect(sessions[0]!.id).not.toBe(cookie.split('=')[1]);
  });

  it('does not redirect outside the console after login', async () => {
    const res = await post('/admin/login', { token: TOKEN, next: 'https://evil.example/' });
    expect(res.headers.location).toBe('/admin');
    const res2 = await post('/admin/login', { token: TOKEN, next: '//evil.example/admin' });
    expect(res2.headers.location).toBe('/admin');
  });

  it('requires the CSRF token on forms and saves tenants', async () => {
    const { cookie, csrf } = await signIn();
    const bad = await post('/admin/tenants', { id: 'uni-a', name: 'Uni A', allowedGames: ['k26game1'], status: 'active' }, cookie);
    expect(bad.statusCode).toBe(403);
    expect(await deps.store.get(COL.tenants, 'uni-a')).toBeNull();
    const ok = await post('/admin/tenants', { csrf, id: 'uni-a', name: 'Uni A', allowedGames: ['k26game1', 'k26game2'], status: 'active' }, cookie);
    expect(ok.statusCode).toBe(303);
    const t = await deps.store.get<Tenant>(COL.tenants, 'uni-a');
    expect(t).toMatchObject({ name: 'Uni A', allowedGames: ['k26game1', 'k26game2'], status: 'active' });
    // Unchecking every game leaves an empty list (not "all games").
    await post('/admin/tenants', { csrf, id: 'uni-a', name: 'Uni A', status: 'suspended' }, cookie);
    expect(await deps.store.get<Tenant>(COL.tenants, 'uni-a')).toMatchObject({ allowedGames: [], status: 'suspended' });
  });

  it('lists failed grade deliveries and lets the admin retry them', async () => {
    const { cookie, csrf } = await signIn();
    const job: SyncJob = {
      tenantId: 'uni-a', status: 'dead', gradeTarget: 'gt_missing', recordId: 'r1', attempts: 8, nextRunAt: 0, lastError: 'HTTP 500',
      occurredAt: new Date().toISOString(), payload: { scoreGiven: 91, scoreMaximum: 100, activityProgress: 'Completed', gradingProgress: 'FullyGraded' },
      createdAt: new Date().toISOString(),
    };
    await deps.store.set(COL.jobs, 'job1', job);
    const overview = await hub.app.inject({ method: 'GET', url: '/admin', headers: { cookie } });
    expect(overview.body).toContain('1 lượt gửi điểm bị lỗi');
    const list = await hub.app.inject({ method: 'GET', url: '/admin/jobs?status=dead', headers: { cookie } });
    expect(list.body).toContain('HTTP 500');
    expect(list.body).toContain('/admin/jobs/job1/retry');
    const res = await post('/admin/jobs/job1/retry', { csrf, back: '/admin/jobs?status=dead' }, cookie);
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/admin/jobs?status=dead&msg=retry');
    const after = await deps.store.get<SyncJob>(COL.jobs, 'job1');
    expect(after!.attempts).toBeLessThan(8);
    expect(await deps.store.find(COL.audit, { action: 'admin_job_retry' })).toHaveLength(1);
  });

  it('logs out and invalidates the session', async () => {
    const { cookie, csrf } = await signIn();
    const res = await post('/admin/logout', { csrf }, cookie);
    expect(res.statusCode).toBe(303);
    expect(String(res.headers['set-cookie'])).toContain('Max-Age=0');
    const again = await hub.app.inject({ method: 'GET', url: '/admin', headers: { cookie } });
    expect(again.statusCode).toBe(303);
  });

  it('rate-limits repeated wrong tokens', async () => {
    for (let i = 0; i < 10; i++) expect((await post('/admin/login', { token: `wrong-${i}` })).statusCode).toBe(401);
    const blocked = await post('/admin/login', { token: TOKEN });
    expect(blocked.statusCode).toBe(429);
  });

  it('keeps the JSON admin API on the header token', async () => {
    expect((await hub.app.inject({ method: 'GET', url: '/api/v1/admin/setup' })).statusCode).toBe(401);
    const ok = await hub.app.inject({ method: 'GET', url: '/api/v1/admin/setup', headers: { 'x-admin-token': TOKEN } });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().toolUrl).toBe('https://hub.test/lti/launch');
  });
});
