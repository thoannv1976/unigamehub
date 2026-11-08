import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT, type JWTPayload } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import { createResultToken, verifyLaunchTicket } from '../sdk/index.ts';
import { buildApp, type HubApp } from '../src/app.ts';
import { GameSecrets, loadCatalog } from '../src/catalog.ts';
import type { Config } from '../src/config.ts';
import type { Deps } from '../src/deps.ts';
import { ephemeralKeyRing } from '../src/keys.ts';
import { CLAIM, SCOPE } from '../src/lti/claims.ts';
import { scoresUrl, serviceUrl } from '../src/lti/ags.ts';
import { FileStore } from '../src/store/file.ts';

const HUB = 'http://hub.test';
const ISS = 'http://moodle.test';
const CID = 'client-abc';
const LINEITEM = `${ISS}/mod/lti/services.php/2/lineitems/5/lineitem?type_id=1`;

interface Env {
  hub: HubApp;
  deps: Deps;
  platformKey: CryptoKey;
  scores: Array<{ url: string; body: Record<string, unknown> }>;
  tokenCalls: number;
}

async function setup(): Promise<Env> {
  const cfg: Config = {
    env: 'dev', port: 0, baseUrl: HUB, selfUrl: HUB, store: 'file', syncInline: false,
    dataDir: mkdtempSync(join(tmpdir(), 'ugh-')), gamesFile: join(import.meta.dirname, '..', 'config', 'games.json'),
  };
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const platformJwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(publicKey)), kid: 'pk1', alg: 'RS256' }] });
  const env = { scores: [], tokenCalls: 0 } as unknown as Env;
  const fakeFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url === `${ISS}/mod/lti/token.php`) {
      env.tokenCalls++;
      return new Response(JSON.stringify({ access_token: 'tok', expires_in: 3600 }), { status: 200 });
    }
    if (url.startsWith(`${ISS}/`) && url.includes('/scores')) {
      env.scores.push({ url, body: JSON.parse(String(init?.body)) });
      return new Response('', { status: 200 });
    }
    if (url.startsWith(HUB)) {
      const res = await env.hub.app.inject({ method: (init?.method ?? 'GET') as 'POST', url: url.slice(HUB.length), headers: init?.headers as Record<string, string>, payload: init?.body as string });
      return new Response(res.body, { status: res.statusCode, headers: { 'content-type': String(res.headers['content-type'] ?? '') } });
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  const deps: Deps = {
    cfg, store: new FileStore(), keys: await ephemeralKeyRing(), catalog: loadCatalog(cfg, {}),
    secrets: new GameSecrets(cfg, {}), platformJwks: () => platformJwks, fetch: fakeFetch,
  };
  env.hub = await buildApp(deps);
  env.deps = deps;
  env.platformKey = privateKey;

  const t = await env.hub.app.inject({ method: 'POST', url: '/api/v1/admin/tenants', payload: { id: 'test-uni', name: 'Test University', allowedGames: ['demo'] } });
  expect(t.statusCode).toBe(200);
  const p = await env.hub.app.inject({
    method: 'POST', url: '/api/v1/admin/platforms',
    payload: { tenantId: 'test-uni', name: 'Moodle test', issuer: ISS, clientId: CID, authUrl: `${ISS}/mod/lti/auth.php`, tokenUrl: `${ISS}/mod/lti/token.php`, jwksUrl: `${ISS}/mod/lti/certs.php`, deploymentIds: ['1'] },
  });
  expect(p.statusCode).toBe(200);
  return env;
}

async function login(env: Env) {
  const res = await env.hub.app.inject({ method: 'GET', url: `/lti/login?iss=${encodeURIComponent(ISS)}&login_hint=7&target_link_uri=${encodeURIComponent(HUB + '/lti/launch')}&client_id=${CID}&lti_deployment_id=1` });
  expect(res.statusCode).toBe(302);
  const loc = new URL(String(res.headers.location));
  expect(loc.origin + loc.pathname).toBe(`${ISS}/mod/lti/auth.php`);
  expect(loc.searchParams.get('redirect_uri')).toBe(`${HUB}/lti/launch`);
  return { state: loc.searchParams.get('state')!, nonce: loc.searchParams.get('nonce')! };
}

function idToken(env: Env, nonce: string, claims: JWTPayload, key = env.platformKey) {
  return new SignJWT({
    nonce, sub: 'moodle-user-7', name: 'Nguyễn Văn A', email: 'a@uni.test',
    [CLAIM.version]: '1.3.0', [CLAIM.deploymentId]: '1', [CLAIM.messageType]: 'LtiResourceLinkRequest',
    [CLAIM.roles]: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
    [CLAIM.resourceLink]: { id: 'rl-1', title: 'Bài demo' }, [CLAIM.context]: { id: 'c-2', title: 'Khóa test' },
    [CLAIM.custom]: { game_id: 'demo', activity: 'round-1' },
    [CLAIM.ags]: { scope: [SCOPE.score, SCOPE.lineitem], lineitem: LINEITEM },
    ...claims,
  }).setProtectedHeader({ alg: 'RS256', kid: 'pk1' }).setIssuer(ISS).setAudience(CID).setIssuedAt().setExpirationTime('5m').sign(key);
}

const launch = (env: Env, state: string, token: string) =>
  env.hub.app.inject({ method: 'POST', url: '/lti/launch', payload: new URLSearchParams({ state, id_token: token }).toString(), headers: { 'content-type': 'application/x-www-form-urlencoded' } });

function ticketFrom(body: string): string {
  const m = /location\.replace\("([^"]+)"\)/.exec(body);
  expect(m).toBeTruthy();
  return decodeURIComponent(/#ticket=(.+)$/.exec(m![1]!)![1]!);
}

async function launchAsStudent(env: Env, claims: JWTPayload = {}) {
  const { state, nonce } = await login(env);
  const res = await launch(env, state, await idToken(env, nonce, claims));
  expect(res.statusCode).toBe(200);
  return ticketFrom(res.body);
}

describe('LTI launch → game → grade sync', () => {
  let env: Env;
  beforeEach(async () => {
    env = await setup();
  });

  it('runs the whole flow and posts the score to the LMS line item', async () => {
    const ticket = await launchAsStudent(env);
    const ctx = await verifyLaunchTicket(ticket, { hubUrl: HUB, gameId: 'demo', jwks: async (h) => env.deps.keys.publicKeyFor(h.kid) });
    expect(ctx).toMatchObject({ tenantId: 'test-uni', role: 'learner', name: 'Nguyễn Văn A', activity: 'round-1', resourceLink: { id: 'rl-1' } });
    expect(ctx.gradeTarget).toMatch(/^gt_/);

    const ex = await env.hub.app.inject({ method: 'POST', url: '/demo/api/exchange', payload: { ticket } });
    expect(ex.statusCode).toBe(200);
    expect(ex.json()).toMatchObject({ gradable: true, course: 'Khóa test' });
    const replay = await env.hub.app.inject({ method: 'POST', url: '/demo/api/exchange', payload: { ticket } });
    expect(replay.statusCode).toBe(401);

    const fin = await env.hub.app.inject({ method: 'POST', url: '/demo/api/finish', payload: { session: ex.json().session, score: 85 } });
    expect(fin.statusCode).toBe(200);
    expect(fin.json().status).toBe('queued');
    await env.hub.sync.runOnce();
    expect(env.scores).toHaveLength(1);
    expect(env.scores[0]!.url).toBe(`${ISS}/mod/lti/services.php/2/lineitems/5/lineitem/scores?type_id=1`);
    expect(env.scores[0]!.body).toMatchObject({ userId: 'moodle-user-7', scoreGiven: 85, scoreMaximum: 100, gradingProgress: 'FullyGraded', activityProgress: 'Completed' });
    const job = await env.hub.app.inject({ method: 'GET', url: `/demo/api/job?session=${ex.json().session}&id=${fin.json().job_id}` });
    expect(job.json().status).toBe('done');
  });

  it('rejects a reused state, a bad signature, a wrong nonce and an unknown deployment', async () => {
    const a = await login(env);
    expect((await launch(env, a.state, await idToken(env, a.nonce, {}))).statusCode).toBe(200);
    expect((await launch(env, a.state, await idToken(env, a.nonce, {}))).statusCode).toBe(400);

    const b = await login(env);
    const other = (await generateKeyPair('RS256')).privateKey;
    expect((await launch(env, b.state, await idToken(env, b.nonce, {}, other))).statusCode).toBe(401);

    const c = await login(env);
    expect((await launch(env, c.state, await idToken(env, 'wrong-nonce', {}))).statusCode).toBe(401);

    const d = await login(env);
    expect((await launch(env, d.state, await idToken(env, d.nonce, { [CLAIM.deploymentId]: '99' }))).statusCode).toBe(403);
  });

  it('refuses games the tenant is not licensed for', async () => {
    const { state, nonce } = await login(env);
    const res = await launch(env, state, await idToken(env, nonce, { [CLAIM.custom]: { game_id: 'k26game1' } }));
    expect(res.statusCode).toBe(404); // disabled in catalog
  });

  it('does not create a grade target for instructors', async () => {
    const ticket = await launchAsStudent(env, { [CLAIM.roles]: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'] });
    const ctx = await verifyLaunchTicket(ticket, { hubUrl: HUB, gameId: 'demo', jwks: async (h) => env.deps.keys.publicKeyFor(h.kid) });
    expect(ctx.role).toBe('instructor');
    expect(ctx.gradeTarget).toBeUndefined();
  });
});

describe('results API integrity', () => {
  let env: Env;
  let gradeTarget: string;
  const post = (token: string) => env.hub.app.inject({ method: 'POST', url: '/api/v1/results', payload: { result_token: token } });
  const opts = () => ({ hubUrl: HUB, gameId: 'demo', secret: env.deps.secrets.get('demo')! });

  beforeEach(async () => {
    env = await setup();
    const ticket = await launchAsStudent(env);
    gradeTarget = (await verifyLaunchTicket(ticket, { hubUrl: HUB, gameId: 'demo', jwks: async (h) => env.deps.keys.publicKeyFor(h.kid) })).gradeTarget!;
  });

  it('dedupes identical results, ignores older ones and lets newer re-scores through', async () => {
    const base = { gradeTarget, attemptId: 'att-1', score: 70, maxScore: 100, occurredAt: '2026-11-08T10:00:00.000Z' };
    expect((await post(await createResultToken(opts(), base))).json().status).toBe('queued');
    expect((await post(await createResultToken(opts(), base))).json().status).toBe('duplicate');
    expect((await post(await createResultToken(opts(), { ...base, score: 10, occurredAt: '2026-11-08T09:00:00.000Z' }))).json().status).toBe('stale_ignored');
    expect((await post(await createResultToken(opts(), { ...base, score: 90, occurredAt: '2026-11-08T11:00:00.000Z' }))).json().status).toBe('queued');
    await env.hub.sync.runOnce();
    expect(env.scores.map((s) => s.body.scoreGiven)).toEqual([70, 90]);
  });

  it('rejects replayed tokens, wrong secrets, other games and bad scores', async () => {
    const token = await createResultToken(opts(), { gradeTarget, attemptId: 'a', score: 5, maxScore: 10 });
    expect((await post(token)).statusCode).toBe(202);
    expect((await post(token)).statusCode).toBe(409);
    expect((await post(await createResultToken({ ...opts(), secret: 'nope' }, { gradeTarget, attemptId: 'b', score: 5, maxScore: 10 }))).statusCode).toBe(401);
    const otherGame = { hubUrl: HUB, gameId: 'k26game1', secret: env.deps.secrets.get('k26game1')! };
    expect((await post(await createResultToken(otherGame, { gradeTarget, attemptId: 'c', score: 5, maxScore: 10 }))).statusCode).toBe(403);
    expect((await post(await createResultToken(opts(), { gradeTarget, attemptId: 'd', score: 11, maxScore: 10 }))).statusCode).toBe(400);
    expect((await post(await createResultToken(opts(), { gradeTarget: 'gt_unknown000', attemptId: 'e', score: 1, maxScore: 10 }))).statusCode).toBe(404);
  });

  it('retries failed deliveries with backoff', async () => {
    const realFetch = env.deps.fetch;
    let fail = true;
    env.deps.fetch = async (u, i) => (fail && String(u).includes('/scores') ? new Response('boom', { status: 503 }) : realFetch(u, i));
    // AgsClient captured deps.fetch at construction; rebuild to pick up the failing fetch.
    env.hub = await buildApp(env.deps);
    const r = await post(await createResultToken(opts(), { gradeTarget, attemptId: 'x', score: 3, maxScore: 10 }));
    await env.hub.sync.runOnce();
    const job = await env.deps.store.get<{ status: string; attempts: number; lastError: string }>('grade_sync_jobs', r.json().job_id);
    expect(job).toMatchObject({ status: 'pending', attempts: 1 });
    expect(job!.lastError).toContain('503');
    fail = false;
  });
});

describe('deep linking', () => {
  it('lets an instructor pick a game and returns a signed content item with a line item', async () => {
    const env = await setup();
    const { state, nonce } = await login(env);
    const token = await idToken(env, nonce, {
      [CLAIM.messageType]: 'LtiDeepLinkingRequest',
      [CLAIM.roles]: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'],
      [CLAIM.dlSettings]: { deep_link_return_url: `${ISS}/mod/lti/contentitem_return.php?course=2&id=1`, accept_types: ['ltiResourceLink'], data: 'opaque-123' },
    });
    const pick = await launch(env, state, token);
    expect(pick.statusCode).toBe(200);
    expect(pick.body).toContain('Demo game');
    expect(pick.body).not.toContain('English City Simulator'); // disabled / not licensed
    const dl = /name="dl" value="([^"]+)"/.exec(pick.body)![1]!;

    const sub = await env.hub.app.inject({
      method: 'POST', url: '/lti/deeplink/submit', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ dl, game_id: 'demo', activity: 'round-2', title: 'Vòng 2 – demo', gradable: '1', max_score: '50', grade_policy: 'best' }).toString(),
    });
    expect(sub.statusCode).toBe(200);
    expect(sub.body).toContain(`action="${ISS}/mod/lti/contentitem_return.php?course=2&amp;id=1"`);
    const jwt = /name="JWT" value="([^"]+)"/.exec(sub.body)![1]!;
    const { payload } = await jwtVerify(jwt, async (h) => env.deps.keys.publicKeyFor(h.kid), { issuer: CID, audience: ISS });
    expect(payload[CLAIM.messageType]).toBe('LtiDeepLinkingResponse');
    expect(payload[CLAIM.dlData]).toBe('opaque-123');
    const item = (payload[CLAIM.dlContentItems] as Array<Record<string, any>>)[0]!;
    expect(item).toMatchObject({ type: 'ltiResourceLink', url: `${HUB}/lti/launch`, title: 'Vòng 2 – demo', custom: { game_id: 'demo', activity: 'round-2', grade_policy: 'best' }, lineItem: { scoreMaximum: 50 } });

    // The deep-link session is single use.
    const again = await env.hub.app.inject({ method: 'POST', url: '/lti/deeplink/submit', headers: { 'content-type': 'application/x-www-form-urlencoded' }, payload: `dl=${dl}&game_id=demo` });
    expect(again.statusCode).toBe(400);
  });

  it('blocks learners from deep linking', async () => {
    const env = await setup();
    const { state, nonce } = await login(env);
    const token = await idToken(env, nonce, { [CLAIM.messageType]: 'LtiDeepLinkingRequest', [CLAIM.dlSettings]: { deep_link_return_url: `${ISS}/x` } });
    expect((await launch(env, state, token)).statusCode).toBe(403);
  });
});

describe('catalog overrides', () => {
  it('enables games and overrides adapter URLs from the environment', () => {
    const cfg = { baseUrl: HUB, gamesFile: join(import.meta.dirname, '..', 'config', 'games.json') } as Config;
    const c = loadCatalog(cfg, { GAMES_ENABLED: 'k26game1', GAME_LAUNCH_URL_K26GAME1: 'https://k26game1--lti-x.web.app/lti-launch' });
    expect(c.get('k26game1')).toMatchObject({ enabled: true, launchUrl: 'https://k26game1--lti-x.web.app/lti-launch' });
    expect(c.get('demo')!.enabled).toBe(false);
    expect(loadCatalog(cfg, {}).get('demo')).toMatchObject({ enabled: true, launchUrl: `${HUB}/demo/` });
  });
});

describe('helpers', () => {
  it('builds AGS scores URLs keeping the query string', () => {
    expect(scoresUrl(LINEITEM)).toBe(`${ISS}/mod/lti/services.php/2/lineitems/5/lineitem/scores?type_id=1`);
    expect(scoresUrl('https://lms.test/li/9/')).toBe('https://lms.test/li/9/scores');
  });

  it('rewrites service URLs through a tunnel only for the issuer origin', () => {
    const p = { issuer: 'http://localhost', serviceBaseUrl: 'https://abc.ngrok-free.app' };
    expect(serviceUrl(p, 'http://localhost/mod/lti/services.php/4/lineitems/1/lineitem/scores?type_id=2'))
      .toBe('https://abc.ngrok-free.app/mod/lti/services.php/4/lineitems/1/lineitem/scores?type_id=2');
    expect(serviceUrl(p, 'http://localhost:8080/x')).toBe('http://localhost:8080/x');
    expect(serviceUrl({ issuer: 'http://localhost' }, 'http://localhost/x')).toBe('http://localhost/x');
  });
});
