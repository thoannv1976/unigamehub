/**
 * Browser admin console (/admin/*).
 * Sign-in with an admin account (username + password, see adminUsers.ts), then a server-side session
 * in an HttpOnly, SameSite=Strict cookie (8 hours). Every state-changing form carries a per-session
 * CSRF token. The ADMIN_TOKEN still works as a break-glass sign-in at /admin/login?mode=token
 * (and is how the first account is created). The JSON admin API (/api/v1/admin/*, header token)
 * is unchanged and used by scripts and Cloud Scheduler.
 */
import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { isLocal, TenantInput, toolConfig } from './admin.ts';
import {
  type AdminRole, type AdminUser, createUser, dummyVerify, getUser, hashPassword, listUsers, normUsername,
  otherActiveOwners, passwordProblem, ROLE_LABEL, tempPassword, USER_LOCK_AFTER, USER_LOCK_MS, UserInput, verifyPassword,
} from './adminUsers.ts';
import { audit, type Deps } from './deps.ts';
import type { Platform, Tenant } from './lti/platforms.ts';
import type { GradeTarget } from './lti/routes.ts';
import type { SyncJob } from './results.ts';
import { COL } from './store/types.ts';
import type { GradeSync } from './sync.ts';
import { esc, hid, HttpError, rid } from './util.ts';
import { adminPage, page } from './views.ts';

export const SESSION_COOKIE = 'ugh_admin';
export const TOKEN_ACTOR = 'admin-token';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 10;

interface AdminSession {
  [k: string]: unknown;
  createdAt: string;
  expiresAt: number;
  csrf: string;
  username: string;
  role: AdminRole;
  viaToken: boolean;
}

interface Throttle {
  [k: string]: unknown;
  count: number;
  resetAt: number;
}

export interface Ctx {
  csrf: string;
  username: string;
  displayName: string;
  role: AdminRole;
  viaToken: boolean;
  sessionKey: string;
}

interface GuardOpts {
  owner?: boolean;
  /** Allowed while the account still has to change its temporary password. */
  allowMustChange?: boolean;
}

const JOB_STATUSES = ['pending', 'dead', 'done', 'superseded'] as const;
const JOB_LABEL: Record<string, string> = { pending: 'Đang chờ gửi', dead: 'Lỗi (đã dừng thử)', done: 'Đã gửi', superseded: 'Bị thay bằng điểm mới hơn' };

const fmtTime = (v: unknown): string => {
  if (v === undefined || v === null || v === '' || v === 0) return '–';
  const d = new Date(typeof v === 'number' ? v : String(v));
  return Number.isNaN(d.getTime()) ? esc(v) : esc(d.toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh', hour12: false }));
};
const badge = (cls: string, label: string): string => `<span class="badge ${esc(cls)}">${esc(label)}</span>`;
const csrfField = (ctx: Ctx): string => `<input type="hidden" name="csrf" value="${esc(ctx.csrf)}">`;
const actor = (ctx: Ctx) => ({ actor: ctx.username });

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

const sameSecret = (given: string, expected: string): boolean => {
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
};

export function registerConsole(app: FastifyInstance, deps: Deps, sync: GradeSync): void {
  const { cfg, store, catalog } = deps;
  const secure = cfg.env !== 'dev';

  const cookie = (value: string, maxAgeSec: number): string =>
    `${SESSION_COOKIE}=${value}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
  const sessionKey = (id: string): string => hid('as', id);

  async function currentSession(req: FastifyRequest): Promise<(AdminSession & { key: string }) | null> {
    const id = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (!id || id.length > 100) return null;
    const key = sessionKey(id);
    const s = await store.get<AdminSession>(COL.adminSessions, key);
    if (!s) return null;
    // Sessions from before account sign-in (no username/role) are no longer valid.
    if (s.expiresAt < Date.now() || !s.username || !s.role) {
      await store.delete(COL.adminSessions, key);
      return null;
    }
    return { ...s, key };
  }

  /** Session + live account check. Returns the context, or a reason the request cannot continue. */
  async function resolve(req: FastifyRequest, opts: GuardOpts): Promise<Ctx | 'login' | 'must_change'> {
    const s = await currentSession(req);
    if (!s) return 'login';
    let displayName = s.username;
    let role = s.role;
    if (!s.viaToken) {
      const u = await getUser(store, s.username);
      if (!u || u.status !== 'active') {
        await store.delete(COL.adminSessions, s.key);
        return 'login';
      }
      displayName = u.displayName;
      role = u.role;
      if (u.mustChangePassword && !opts.allowMustChange) return 'must_change';
    }
    if (opts.owner && role !== 'owner') throw new HttpError(403, 'forbidden', 'Chỉ Chủ hệ thống mới dùng được chức năng này.');
    return { csrf: s.csrf, username: s.username, displayName, role, viaToken: s.viaToken, sessionKey: s.key };
  }

  /** Page guard: redirect to the login form when not signed in. */
  async function guard(req: FastifyRequest, reply: FastifyReply, opts: GuardOpts = {}): Promise<Ctx | null> {
    const r = await resolve(req, opts);
    if (r === 'login') {
      reply.redirect(`/admin/login?next=${encodeURIComponent(req.url)}`, 303);
      return null;
    }
    if (r === 'must_change') {
      reply.redirect('/admin/password', 303);
      return null;
    }
    return r;
  }

  /** Form guard: signed in + valid CSRF token. */
  async function guardPost(req: FastifyRequest, opts: GuardOpts = {}): Promise<Ctx> {
    const r = await resolve(req, opts);
    if (r === 'login') throw new HttpError(401, 'unauthorized', 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.');
    if (r === 'must_change') throw new HttpError(403, 'must_change_password', 'Bạn cần đổi mật khẩu tạm trước khi tiếp tục.');
    const given = String((req.body as Record<string, unknown> | undefined)?.csrf ?? '');
    if (!sameSecret(given, r.csrf)) throw new HttpError(403, 'csrf', 'Yêu cầu không hợp lệ (CSRF). Hãy tải lại trang và thử lại.');
    return r;
  }

  /** Ends every session of an account (after a password change, reset or disable). */
  async function endSessions(username: string, exceptKey?: string): Promise<void> {
    for (const s of await store.find<AdminSession>(COL.adminSessions, { username }, 500)) {
      if (s.id !== exceptKey) await store.delete(COL.adminSessions, s.id);
    }
  }

  async function startSession(reply: FastifyReply, username: string, role: AdminRole, viaToken: boolean): Promise<void> {
    const id = rid(32);
    await store.set<AdminSession>(COL.adminSessions, sessionKey(id), {
      createdAt: new Date().toISOString(), expiresAt: Date.now() + SESSION_TTL_MS, csrf: rid(24), username, role, viaToken,
    });
    reply.header('set-cookie', cookie(id, SESSION_TTL_MS / 1000));
  }

  // Per-IP failure counter, shared by all instances (store-backed).
  const ipKey = (ip: string) => hid('ip', ip);
  async function ipBlocked(ip: string): Promise<boolean> {
    const t = await store.get<Throttle>(COL.loginThrottle, ipKey(ip));
    return !!t && t.resetAt > Date.now() && t.count >= LOGIN_MAX_FAILURES;
  }
  async function ipFailed(ip: string): Promise<void> {
    const now = Date.now();
    await store.update<Throttle>(COL.loginThrottle, ipKey(ip), (cur) =>
      cur && cur.resetAt > now ? { ...cur, count: cur.count + 1 } : { count: 1, resetAt: now + LOGIN_WINDOW_MS },
    );
  }

  const html = (reply: FastifyReply, body: string, status = 200) =>
    reply.status(status).header('content-type', 'text/html; charset=utf-8').send(body);
  const safeNext = (v: unknown): string => {
    const s = String(v ?? '');
    return /^\/admin(\/[a-z/]*)?(\?[\w=&%.-]*)?$/.test(s) && !s.startsWith('/admin/login') ? s : '/admin';
  };

  // Security headers for every console page.
  app.addHook('onSend', async (req, reply) => {
    if (req.url === '/admin' || req.url.startsWith('/admin/') || req.url.startsWith('/admin?')) {
      reply.header('cache-control', 'no-store');
      reply.header('x-frame-options', 'DENY');
      reply.header('content-security-policy', "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    }
  });

  // ---------- public landing page ----------
  app.get('/', async (_req, reply) =>
    html(reply, page('UniGame Hub', `<h1>UniGame Hub</h1>
<p class="muted">Cổng kết nối Moodle với các game học tập (LTI 1.3): đăng nhập một lần bằng tài khoản Moodle, điểm tự động về Sổ điểm.</p>
<div class="card"><p><b>Giảng viên và sinh viên:</b> hãy mở game từ hoạt động trong khóa học Moodle của bạn. Trang này không cần đăng nhập riêng.</p>
<p class="muted">Quản trị viên hệ thống: <a href="/admin">đăng nhập trang quản trị</a>.</p></div>`)));

  // ---------- login / logout ----------
  const errBox = (error?: string) => (error ? `<div class="card notice err"><p class="err">${esc(error)}</p></div>` : '');
  const loginForm = async (next: string, error?: string, username = '') => {
    const noAccounts = (await store.find(COL.adminUsers, {}, 1)).length === 0;
    return page('Đăng nhập quản trị · UniGame Hub', `<h1>UniGame Hub · Quản trị</h1>${errBox(error)}
<form class="card" method="post" action="/admin/login">
<input type="hidden" name="next" value="${esc(next)}">
<div class="field"><label for="username">Tên đăng nhập</label><input id="username" name="username" type="text" value="${esc(username)}" autocomplete="username" autocapitalize="none" spellcheck="false" required${username ? '' : ' autofocus'}></div>
<div class="field"><label for="password">Mật khẩu</label><input id="password" name="password" type="password" autocomplete="current-password" required${username ? ' autofocus' : ''}></div>
<button>Đăng nhập</button>
<p class="muted">Phiên đăng nhập có hiệu lực 8 giờ. Quên mật khẩu: nhờ Chủ hệ thống đặt lại.</p>
</form>${noAccounts ? `<div class="card notice"><p>Chưa có tài khoản quản trị nào. <a href="/admin/login?mode=token">Đăng nhập bằng mã ADMIN_TOKEN</a> để tạo tài khoản đầu tiên.</p></div>` : ''}`);
  };
  const tokenForm = (next: string, error?: string) =>
    page('Đăng nhập bằng mã khẩn cấp · UniGame Hub', `<h1>UniGame Hub · Mã khẩn cấp</h1>${errBox(error)}
<form class="card" method="post" action="/admin/login">
<input type="hidden" name="next" value="${esc(next)}"><input type="hidden" name="mode" value="token">
<div class="field"><label for="token">Mã quản trị (ADMIN_TOKEN)</label><input id="token" name="token" type="password" autocomplete="off" required autofocus></div>
<button>Đăng nhập</button>
<p class="muted">Chỉ dùng khi không đăng nhập được bằng tài khoản. Mã lưu trong Secret Manager (<code>hub-admin-token</code>) của project GCP. <a href="/admin/login">Đăng nhập bằng tài khoản</a>.</p>
</form>`);

  app.get('/admin/login', async (req, reply) => {
    const q = req.query as Record<string, string>;
    if (await currentSession(req)) return reply.redirect(safeNext(q.next), 303);
    return html(reply, q.mode === 'token' ? tokenForm(safeNext(q.next)) : await loginForm(safeNext(q.next)));
  });

  app.post('/admin/login', async (req, reply) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const next = safeNext(body.next);
    const ip = req.ip;
    const viaToken = body.mode === 'token' || body.token !== undefined;
    const username = normUsername(body.username).slice(0, 64);
    const again = async (msg: string, status: number) =>
      html(reply, viaToken ? tokenForm(next, msg) : await loginForm(next, msg, username), status);

    if (await ipBlocked(ip)) return again('Đăng nhập sai quá nhiều lần. Vui lòng thử lại sau 15 phút.', 429);

    if (viaToken) {
      const token = String(body.token ?? '');
      const ok = cfg.adminToken ? sameSecret(token, cfg.adminToken) : cfg.env === 'dev' && isLocal(req);
      if (!ok) {
        await ipFailed(ip);
        await audit(deps, null, 'admin_login_failed', { ip, via: 'token' });
        return again('Mã quản trị không đúng.', 401);
      }
      await audit(deps, null, 'admin_login', { ip, via: 'token', actor: TOKEN_ACTOR });
      await startSession(reply, TOKEN_ACTOR, 'owner', true);
      return reply.redirect(next, 303);
    }

    const password = String(body.password ?? '');
    const user = username ? await getUser(store, username) : null;
    if (!user) {
      await dummyVerify(password);
      await ipFailed(ip);
      await audit(deps, null, 'admin_login_failed', { ip, username, reason: 'unknown_user' });
      return again('Tên đăng nhập hoặc mật khẩu không đúng.', 401);
    }
    if (user.lockedUntil > Date.now()) {
      await ipFailed(ip);
      await audit(deps, null, 'admin_login_failed', { ip, username, reason: 'locked' });
      return again('Tài khoản đang tạm khóa do nhập sai mật khẩu nhiều lần. Vui lòng thử lại sau 15 phút.', 423);
    }
    if (!(await verifyPassword(password, user.passwordHash))) {
      await ipFailed(ip);
      const after = await store.update<AdminUser>(COL.adminUsers, user.username, (cur) => {
        if (!cur) return null;
        const failed = cur.failedCount + 1;
        return failed >= USER_LOCK_AFTER ? { ...cur, failedCount: 0, lockedUntil: Date.now() + USER_LOCK_MS } : { ...cur, failedCount: failed };
      });
      const locked = !!after && after.lockedUntil > Date.now();
      await audit(deps, null, locked ? 'admin_user_locked' : 'admin_login_failed', { ip, username, reason: 'bad_password' });
      return again(locked ? 'Sai mật khẩu quá nhiều lần: tài khoản bị tạm khóa 15 phút.' : 'Tên đăng nhập hoặc mật khẩu không đúng.', 401);
    }
    if (user.status !== 'active') {
      await audit(deps, null, 'admin_login_failed', { ip, username, reason: 'disabled' });
      return again('Tài khoản đã bị vô hiệu hóa. Liên hệ Chủ hệ thống.', 403);
    }
    await store.update<AdminUser>(COL.adminUsers, user.username, (cur) =>
      cur ? { ...cur, failedCount: 0, lockedUntil: 0, lastLoginAt: new Date().toISOString() } : null,
    );
    await audit(deps, null, 'admin_login', { ip, actor: user.username });
    await startSession(reply, user.username, user.role, false);
    return reply.redirect(user.mustChangePassword ? '/admin/password' : next, 303);
  });

  app.post('/admin/logout', async (req, reply) => {
    await guardPost(req, { allowMustChange: true });
    const id = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (id) await store.delete(COL.adminSessions, sessionKey(id));
    return reply.header('set-cookie', cookie('', 0)).redirect('/admin/login', 303);
  });

  // ---------- own password ----------
  const passwordForm = (ctx: Ctx, error?: string, mustChange = false) =>
    adminPage('Đổi mật khẩu', '/admin/password', ctx, `${errBox(error)}
${mustChange ? '<div class="card notice"><p>Bạn đang dùng mật khẩu tạm. Hãy đặt mật khẩu mới để tiếp tục.</p></div>' : ''}
${ctx.viaToken
    ? '<div class="card"><p>Bạn đang đăng nhập bằng mã ADMIN_TOKEN nên không có mật khẩu để đổi. Hãy tạo tài khoản ở trang <a href="/admin/users">Tài khoản</a>.</p></div>'
    : `<form class="card" method="post" action="/admin/password">${csrfField(ctx)}
<input type="text" name="username" value="${esc(ctx.username)}" autocomplete="username" hidden>
<div class="field"><label for="current">Mật khẩu hiện tại</label><input id="current" name="current" type="password" autocomplete="current-password" required autofocus></div>
<div class="field"><label for="next_pw">Mật khẩu mới (ít nhất 10 ký tự)</label><input id="next_pw" name="password" type="password" autocomplete="new-password" minlength="10" required></div>
<div class="field"><label for="confirm">Nhập lại mật khẩu mới</label><input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="10" required></div>
<button>Đổi mật khẩu</button><p class="muted">Các phiên đăng nhập khác của bạn sẽ bị đăng xuất.</p></form>`}`);

  app.get('/admin/password', async (req, reply) => {
    const ctx = await guard(req, reply, { allowMustChange: true });
    if (!ctx) return reply;
    const u = ctx.viaToken ? null : await getUser(store, ctx.username);
    return html(reply, passwordForm(ctx, undefined, !!u?.mustChangePassword));
  });

  app.post('/admin/password', async (req, reply) => {
    const ctx = await guardPost(req, { allowMustChange: true });
    if (ctx.viaToken) throw new HttpError(400, 'no_password', 'Phiên ADMIN_TOKEN không có mật khẩu.');
    const b = (req.body ?? {}) as Record<string, unknown>;
    const u = await getUser(store, ctx.username);
    if (!u) throw new HttpError(401, 'unauthorized', 'Tài khoản không còn tồn tại.');
    const fail = (msg: string) => html(reply, passwordForm(ctx, msg, u.mustChangePassword), 400);
    if (!(await verifyPassword(String(b.current ?? ''), u.passwordHash))) return fail('Mật khẩu hiện tại không đúng.');
    const pw = String(b.password ?? '');
    if (pw !== String(b.confirm ?? '')) return fail('Hai lần nhập mật khẩu mới không khớp.');
    const problem = passwordProblem(pw, u.username);
    if (problem) return fail(problem);
    if (await verifyPassword(pw, u.passwordHash)) return fail('Mật khẩu mới phải khác mật khẩu hiện tại.');
    const passwordHash = await hashPassword(pw);
    await store.update<AdminUser>(COL.adminUsers, u.username, (cur) =>
      cur ? { ...cur, passwordHash, mustChangePassword: false, updatedAt: new Date().toISOString() } : null,
    );
    await endSessions(u.username, ctx.sessionKey);
    await audit(deps, null, 'admin_password_changed', actor(ctx));
    return reply.redirect('/admin?msg=password', 303);
  });

  // ---------- helpers for job tables ----------
  async function jobRows(ctx: Ctx, jobs: Array<SyncJob & { id: string }>, back: string): Promise<string> {
    const targets = new Map<string, GradeTarget | null>();
    for (const j of jobs) if (!targets.has(j.gradeTarget)) targets.set(j.gradeTarget, await store.get<GradeTarget>(COL.gradeTargets, j.gradeTarget));
    if (!jobs.length) return '<p class="muted">Chưa có lượt gửi điểm nào.</p>';
    const rows = jobs.map((j) => {
      const gt = targets.get(j.gradeTarget);
      const game = gt ? catalog.get(gt.gameId)?.name ?? gt.gameId : '–';
      const canRetry = j.status === 'dead' || j.status === 'pending';
      return `<tr><td>${fmtTime(j.createdAt)}</td><td>${esc(j.tenantId)}</td><td>${esc(game)}</td>
<td><code>${esc(gt?.userSub ?? '–')}</code></td><td>${esc(j.payload.scoreGiven)} / ${esc(j.payload.scoreMaximum)}</td>
<td>${badge(j.status, JOB_LABEL[j.status] ?? j.status)}</td><td>${esc(j.attempts)}</td>
<td class="muted">${esc(j.lastError ?? '')}</td>
<td>${canRetry ? `<form method="post" action="/admin/jobs/${esc(encodeURIComponent(j.id))}/retry">${csrfField(ctx)}<input type="hidden" name="back" value="${esc(back)}"><button class="small">Gửi lại</button></form>` : ''}</td></tr>`;
    });
    return `<div class="tablewrap"><table><tr><th>Thời gian</th><th>Trường</th><th>Game</th><th>Người dùng LMS</th><th>Điểm</th><th>Trạng thái</th><th>Lần thử</th><th>Lỗi gần nhất</th><th></th></tr>${rows.join('')}</table></div>`;
  }

  // ---------- overview ----------
  app.get('/admin', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const [tenants, platforms, pending, dead, recent] = await Promise.all([
      store.find<Tenant>(COL.tenants, {}, 500),
      store.find<Platform>(COL.platforms, {}, 500),
      store.find<SyncJob>(COL.jobs, { status: 'pending' }, 1000),
      store.find<SyncJob>(COL.jobs, { status: 'dead' }, 1000),
      store.recent<SyncJob>(COL.jobs, 'createdAt', 10),
    ]);
    const enabledGames = catalog.list().filter((g) => g.enabled && g.id !== 'demo');
    const stat = (n: number | string, label: string, href?: string) =>
      `<div class="stat"><b>${esc(n)}</b>${href ? `<a href="${href}">${esc(label)}</a>` : esc(label)}</div>`;
    const alert = dead.length
      ? `<div class="card notice err"><p class="err"><b>${dead.length} lượt gửi điểm bị lỗi</b> – Moodle chưa nhận các điểm này. <a href="/admin/jobs?status=dead">Xem và gửi lại</a>.</p></div>`
      : '';
    const pwFlash = (req.query as Record<string, string>).msg === 'password' ? '<div class="card notice"><p>Đã đổi mật khẩu.</p></div>' : '';
    const tokenHint = ctx.viaToken
      ? '<div class="card notice"><p>Bạn đang dùng mã khẩn cấp ADMIN_TOKEN. Hãy <a href="/admin/users">tạo tài khoản</a> và đăng nhập bằng tài khoản cho công việc hằng ngày.</p></div>'
      : '';
    return html(reply, adminPage('Tổng quan', '/admin', ctx, `${pwFlash}${tokenHint}<p class="muted">Môi trường <b>${esc(cfg.env)}</b> · ${esc(cfg.baseUrl)}</p>
${alert}
<div class="stats">${stat(tenants.length, 'Trường', '/admin/tenants')}${stat(platforms.length, 'Moodle / LMS', '/admin/platforms')}
${stat(enabledGames.length, 'Game đang bật', '/admin/games')}${stat(pending.length, 'Điểm đang chờ gửi', '/admin/jobs?status=pending')}
${stat(dead.length, 'Điểm gửi lỗi', '/admin/jobs?status=dead')}</div>
<h2>Lượt gửi điểm gần đây</h2><div class="card">${await jobRows(ctx, recent, '/admin')}
<form method="post" action="/admin/sync">${csrfField(ctx)}<button class="small">Chạy gửi điểm ngay</button>
<span class="muted"> Hệ thống tự gửi lại mỗi 5 phút (Cloud Scheduler).</span></form></div>`));
  });

  // ---------- grade sync jobs ----------
  app.get('/admin/jobs', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const q = req.query as Record<string, string>;
    const status = (JOB_STATUSES as readonly string[]).includes(q.status ?? '') ? q.status! : 'all';
    const jobs =
      status === 'all'
        ? await store.recent<SyncJob>(COL.jobs, 'createdAt', 100)
        : (await store.find<SyncJob>(COL.jobs, { status }, 500)).sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)).slice(0, 100);
    const filters = [['all', 'Tất cả'], ...JOB_STATUSES.map((s) => [s, JOB_LABEL[s]!])]
      .map(([v, l]) => `<a href="/admin/jobs${v === 'all' ? '' : `?status=${v}`}"${v === status ? ' class="on"' : ''}>${esc(l)}</a>`)
      .join('');
    const flash = q.msg === 'retry' ? '<div class="card notice"><p>Đã đưa lượt gửi vào hàng chờ và chạy gửi lại.</p></div>' : q.msg === 'sync' ? '<div class="card notice"><p>Đã chạy gửi điểm.</p></div>' : '';
    return html(reply, adminPage('Gửi điểm về Moodle', '/admin/jobs', ctx, `${flash}
<p class="muted">Mỗi lần game gửi kết quả, Hub tạo một lượt gửi điểm về Sổ điểm Moodle. Lượt lỗi được thử lại tối đa 8 lần; sau đó dừng và cần bấm <b>Gửi lại</b>. Hiển thị tối đa 100 lượt mới nhất.</p>
<div class="filters">${filters}</div>
<div class="card">${await jobRows(ctx, jobs, `/admin/jobs${status === 'all' ? '' : `?status=${status}`}`)}</div>`));
  });

  app.post('/admin/jobs/:id/retry', async (req, reply) => {
    const ctx = await guardPost(req);
    const id = (req.params as { id: string }).id;
    const job = await store.update<SyncJob>(COL.jobs, id, (cur) =>
      cur && (cur.status === 'dead' || cur.status === 'pending') ? { ...cur, status: 'pending', attempts: 0, nextRunAt: Date.now() } : null,
    );
    if (!job) throw new HttpError(404, 'not_found', 'Không tìm thấy lượt gửi điểm (hoặc đã gửi xong).');
    await audit(deps, job.tenantId, 'admin_job_retry', { jobId: id, ...actor(ctx) });
    await sync.runOnce();
    const back = safeNext((req.body as Record<string, unknown>).back);
    return reply.redirect(`${back}${back.includes('?') ? '&' : '?'}msg=retry`, 303);
  });

  app.post('/admin/sync', async (req, reply) => {
    await guardPost(req);
    await sync.runOnce();
    return reply.redirect('/admin/jobs?msg=sync', 303);
  });

  // ---------- tenants ----------
  app.get('/admin/tenants', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const tenants = (await store.find<Tenant>(COL.tenants, {}, 500)).sort((a, b) => a.id.localeCompare(b.id));
    const games = catalog.list().filter((g) => g.enabled);
    const flash = (req.query as Record<string, string>).msg === 'saved' ? '<div class="card notice"><p>Đã lưu.</p></div>' : '';
    const form = (t?: Tenant) => {
      const allowed = t?.allowedGames ?? [];
      const boxes = games
        .map((g) => `<label class="game"><input type="checkbox" name="allowedGames" value="${esc(g.id)}"${allowed.includes('*') || allowed.includes(g.id) ? ' checked' : ''}>${esc(g.name)} <span class="muted">(${esc(g.id)})</span></label>`)
        .join('');
      return `<form method="post" action="/admin/tenants">${csrfField(ctx)}
${t ? `<input type="hidden" name="id" value="${esc(t.id)}">` : `<div class="field"><label>Mã trường (chữ thường, số, -, _)</label><input type="text" name="id" required pattern="[a-z0-9][a-z0-9_-]{1,63}"></div>`}
<div class="field"><label>Tên trường</label><input type="text" name="name" value="${esc(t?.name ?? '')}" required maxlength="200"></div>
<div class="field"><label>Game được dùng</label>${boxes || '<p class="muted">Chưa có game nào được bật.</p>'}</div>
<div class="field"><label>Trạng thái</label><select name="status"><option value="active"${t?.status !== 'suspended' ? ' selected' : ''}>Hoạt động</option><option value="suspended"${t?.status === 'suspended' ? ' selected' : ''}>Tạm dừng</option></select></div>
<button class="small">${t ? 'Lưu thay đổi' : 'Tạo trường'}</button></form>`;
    };
    const cards = tenants
      .map((t) => `<div class="card"><h2 style="margin-top:0">${esc(t.name)} <code>${esc(t.id)}</code> ${badge(t.status, t.status === 'active' ? 'Hoạt động' : 'Tạm dừng')}</h2>${form(t)}</div>`)
      .join('');
    return html(reply, adminPage('Trường', '/admin/tenants', ctx, `${flash}
<p class="muted">Mỗi trường gắn với một hoặc nhiều Moodle. Giảng viên chỉ thấy các game được chọn ở đây (và đang bật trên Hub). Lưu ý: game cũng cần tạo trường cùng mã trong database của game.</p>
${cards || '<p class="muted">Chưa có trường.</p>'}
<h2>Thêm trường</h2><div class="card">${form()}</div>`));
  });

  app.post('/admin/tenants', async (req, reply) => {
    const ctx = await guardPost(req);
    const b = (req.body ?? {}) as Record<string, unknown>;
    const allowed = b.allowedGames === undefined ? [] : Array.isArray(b.allowedGames) ? b.allowedGames.map(String) : [String(b.allowedGames)];
    const t = TenantInput.parse({ id: b.id, name: b.name, allowedGames: allowed, status: b.status });
    await store.set<Tenant>(COL.tenants, t.id, t);
    await audit(deps, t.id, 'tenant_upsert', { allowedGames: t.allowedGames, status: t.status, via: 'console', ...actor(ctx) });
    return reply.redirect('/admin/tenants?msg=saved', 303);
  });

  // ---------- platforms ----------
  app.get('/admin/platforms', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const platforms = await store.find<Platform>(COL.platforms, {}, 500);
    const rows = platforms
      .map((p) => `<tr><td>${esc(p.name)}</td><td>${esc(p.tenantId)}</td><td><code>${esc(p.issuer)}</code></td><td><code>${esc(p.clientId)}</code></td>
<td>${esc(p.deploymentIds.join(', '))}</td><td>${badge(p.status, p.status === 'active' ? 'Hoạt động' : 'Tắt')}</td><td>${fmtTime(p.updatedAt)}</td></tr>`)
      .join('');
    return html(reply, adminPage('Moodle / LMS đã kết nối', '/admin/platforms', ctx, `
<p class="muted">Mỗi dòng là một Moodle (issuer + client ID) đã đăng ký với Hub. Thêm Moodle mới bằng script <code>npm run register-platform</code> (cần thông tin từ trang External tool của Moodle).</p>
<div class="card tablewrap"><table><tr><th>Tên</th><th>Trường</th><th>Issuer</th><th>Client ID</th><th>Deployment</th><th>Trạng thái</th><th>Cập nhật</th></tr>
${rows || '<tr><td colspan="7" class="muted">Chưa có</td></tr>'}</table></div>`));
  });

  // ---------- games ----------
  app.get('/admin/games', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const rows = catalog
      .list()
      .map((g) => `<tr><td><code>${esc(g.id)}</code></td><td>${esc(g.name)}${g.alias ? ` <span class="tag">${esc(g.alias)}</span>` : ''}</td>
<td>${g.enabled ? badge('active', 'Đang bật') : badge('', 'Chưa tích hợp')}</td><td>${esc(g.activities?.length ?? 0)}</td><td><code>${esc(g.launchUrl)}</code></td></tr>`)
      .join('');
    return html(reply, adminPage('Game', '/admin/games', ctx, `
<p class="muted">Bật/tắt game cho toàn Hub bằng biến môi trường <code>GAMES_ENABLED</code> khi deploy (deploy/deploy-cloudrun.sh). Chọn game cho từng trường ở trang <a href="/admin/tenants">Trường</a>.</p>
<div class="card tablewrap"><table><tr><th>ID</th><th>Tên</th><th>Trạng thái</th><th>Số bài chọn được</th><th>Địa chỉ adapter</th></tr>${rows}</table></div>`));
  });

  // ---------- LTI configuration ----------
  app.get('/admin/setup', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const c = await toolConfig(deps);
    const rows = (pairs: Array<[string, string]>) => pairs.map(([k, v]) => `<tr><th>${esc(k)}</th><td><code>${esc(v)}</code></td></tr>`).join('');
    return html(reply, adminPage('Cấu hình LTI 1.3 cho Moodle', '/admin/setup', ctx, `
<p class="muted">Thông tin khai báo trong Moodle: Site administration → Plugins → External tool → Manage tools → Configure a tool manually.</p>
<div class="card tablewrap"><table>${rows([
      ['Tool URL', c.toolUrl], ['LTI version', 'LTI 1.3'], ['Public key type', 'Keyset URL'],
      ['Public keyset', c.publicKeysetUrl], ['Initiate login URL', c.initiateLoginUrl], ['Redirection URI(s)', c.redirectionUris.join('\n')],
      ['Supports Deep Linking', 'Có'], ['Content Selection URL', c.deepLinkingUrl], ['Default launch container', 'New window'],
      ['Services', 'IMS LTI Assignment and Grade Services: "Use this service for grade sync and column management"; Names and Role Provisioning: "Use this service"'],
      ['Privacy', "Share launcher's name: Always · Share email: Always · Accept grades: Always"],
    ])}</table><h2>Public key (RSA)</h2><pre>${esc(c.publicKeyPem)}</pre></div>`));
  });

  // ---------- audit log ----------
  app.get('/admin/audit', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const logs = await store.recent<Record<string, unknown>>(COL.audit, 'at', 150);
    const rows = logs
      .map((l) => {
        const { at, tenantId, action, id: _id, ...rest } = l as Record<string, unknown>;
        return `<tr><td>${fmtTime(at)}</td><td>${esc(tenantId ?? '–')}</td><td><code>${esc(action)}</code></td><td class="muted"><code>${esc(JSON.stringify(rest))}</code></td></tr>`;
      })
      .join('');
    return html(reply, adminPage('Nhật ký hoạt động', '/admin/audit', ctx, `
<p class="muted">150 sự kiện gần nhất: mở game, nhận kết quả, đăng nhập quản trị, thay đổi cấu hình.</p>
<div class="card tablewrap"><table><tr><th>Thời gian</th><th>Trường</th><th>Sự kiện</th><th>Chi tiết</th></tr>${rows || '<tr><td colspan="4" class="muted">Chưa có</td></tr>'}</table></div>`));
  });

  // ---------- admin accounts (owner only) ----------
  const USER_FLASH: Record<string, string> = {
    disabled: 'Đã vô hiệu hóa tài khoản và đăng xuất mọi phiên của tài khoản đó.',
    enabled: 'Đã kích hoạt lại tài khoản.',
    unlocked: 'Đã mở khóa tài khoản.',
    role: 'Đã đổi vai trò.',
  };

  const userTable = (ctx: Ctx, users: AdminUser[]) => {
    if (!users.length) return '<p class="muted">Chưa có tài khoản nào.</p>';
    const now = Date.now();
    const rows = users.map((u) => {
      const self = u.username === ctx.username;
      const locked = u.lockedUntil > now;
      const state = u.status !== 'active' ? badge('disabled', 'Vô hiệu') : locked ? badge('pending', 'Tạm khóa') : badge('active', 'Hoạt động');
      const action = (path: string, fields: Record<string, string>, label: string, cls = 'small') =>
        `<form class="inline" method="post" action="/admin/users/${esc(encodeURIComponent(u.username))}/${path}">${csrfField(ctx)}${Object.entries(fields)
          .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
          .join('')}<button class="${cls}">${esc(label)}</button></form>`;
      const actions = self
        ? '<span class="muted">(bạn)</span>'
        : [
            action('reset', {}, 'Đặt lại mật khẩu'),
            u.status === 'active' ? action('status', { action: 'disable' }, 'Vô hiệu hóa', 'small danger') : action('status', { action: 'enable' }, 'Kích hoạt'),
            locked ? action('status', { action: 'unlock' }, 'Mở khóa') : '',
            action('role', { role: u.role === 'owner' ? 'admin' : 'owner' }, u.role === 'owner' ? 'Hạ xuống Quản trị viên' : 'Nâng lên Chủ hệ thống'),
          ].join(' ');
      return `<tr><td><b>${esc(u.username)}</b><br><span class="muted">${esc(u.displayName)}</span></td><td>${esc(ROLE_LABEL[u.role])}</td><td>${state}${u.mustChangePassword ? ' <span class="tag">chờ đổi mật khẩu</span>' : ''}</td>
<td>${fmtTime(u.lastLoginAt)}</td><td>${fmtTime(u.createdAt)}<br><span class="muted">${esc(u.createdBy)}</span></td><td class="actions">${actions}</td></tr>`;
    });
    return `<div class="tablewrap"><table><tr><th>Tài khoản</th><th>Vai trò</th><th>Trạng thái</th><th>Đăng nhập gần nhất</th><th>Tạo lúc / bởi</th><th></th></tr>${rows.join('')}</table></div>`;
  };

  const usersPage = async (ctx: Ctx, notice = '') =>
    adminPage('Tài khoản quản trị', '/admin/users', ctx, `${notice}
<p class="muted"><b>Chủ hệ thống</b> quản lý được tài khoản; <b>Quản trị viên</b> dùng mọi chức năng còn lại. Tài khoản mới nhận mật khẩu tạm và phải đổi ở lần đăng nhập đầu. Sai mật khẩu ${USER_LOCK_AFTER} lần liên tiếp thì tài khoản bị khóa 15 phút.</p>
<div class="card">${userTable(ctx, await listUsers(store))}</div>
<h2>Thêm tài khoản</h2>
<form class="card" method="post" action="/admin/users">${csrfField(ctx)}
<div class="field"><label for="nu">Tên đăng nhập (3–32 ký tự: chữ thường, số, . _ -)</label><input id="nu" name="username" type="text" required pattern="[a-zA-Z0-9][a-zA-Z0-9._\\-]{2,31}" autocapitalize="none" spellcheck="false"></div>
<div class="field"><label for="nd">Họ tên (không bắt buộc)</label><input id="nd" name="displayName" type="text" maxlength="100"></div>
<div class="field"><label for="nr">Vai trò</label><select id="nr" name="role"><option value="admin">${ROLE_LABEL.admin}</option><option value="owner">${ROLE_LABEL.owner}</option></select></div>
<button class="small">Tạo tài khoản</button><span class="muted"> Hệ thống sẽ tạo mật khẩu tạm và hiện một lần duy nhất.</span></form>`);

  const tempPasswordNotice = (username: string, pw: string, what: string) =>
    `<div class="card notice"><p>${esc(what)} <b>${esc(username)}</b>. Mật khẩu tạm (chỉ hiện <b>một lần</b>, hãy gửi riêng cho người dùng):</p>
<pre class="secret">${esc(pw)}</pre><p class="muted">Người dùng phải đổi mật khẩu ngay ở lần đăng nhập đầu tiên.</p></div>`;

  app.get('/admin/users', async (req, reply) => {
    const ctx = await guard(req, reply, { owner: true });
    if (!ctx) return reply;
    const msg = USER_FLASH[(req.query as Record<string, string>).msg ?? ''];
    return html(reply, await usersPage(ctx, msg ? `<div class="card notice"><p>${esc(msg)}</p></div>` : ''));
  });

  app.post('/admin/users', async (req, reply) => {
    const ctx = await guardPost(req, { owner: true });
    const b = (req.body ?? {}) as Record<string, unknown>;
    const parsed = UserInput.safeParse({ username: b.username, displayName: b.displayName || undefined, role: b.role });
    if (!parsed.success) return html(reply, await usersPage(ctx, errBox(parsed.error.issues[0]?.message ?? 'Dữ liệu không hợp lệ.')), 400);
    const { username, displayName, role } = parsed.data;
    if (username === TOKEN_ACTOR) return html(reply, await usersPage(ctx, errBox('Tên đăng nhập này được dành riêng.')), 400);
    const pw = tempPassword();
    const user = await createUser(store, { username, displayName, role, password: pw, mustChangePassword: true, createdBy: ctx.username });
    if (!user) return html(reply, await usersPage(ctx, errBox(`Tài khoản "${username}" đã tồn tại.`)), 409);
    await audit(deps, null, 'admin_user_created', { ...actor(ctx), username, role });
    return html(reply, await usersPage(ctx, tempPasswordNotice(username, pw, 'Đã tạo tài khoản')));
  });

  /** Loads the target account of a /admin/users/:username/* action; never the acting account itself. */
  async function target(req: FastifyRequest, ctx: Ctx): Promise<AdminUser> {
    const username = normUsername((req.params as { username: string }).username);
    if (username === ctx.username) throw new HttpError(400, 'self', 'Không thể tự thao tác trên tài khoản của chính mình ở đây.');
    const u = await getUser(store, username);
    if (!u) throw new HttpError(404, 'not_found', 'Không tìm thấy tài khoản.');
    return u;
  }

  app.post('/admin/users/:username/reset', async (req, reply) => {
    const ctx = await guardPost(req, { owner: true });
    const u = await target(req, ctx);
    const pw = tempPassword();
    const passwordHash = await hashPassword(pw);
    await store.update<AdminUser>(COL.adminUsers, u.username, (cur) =>
      cur ? { ...cur, passwordHash, mustChangePassword: true, failedCount: 0, lockedUntil: 0, updatedAt: new Date().toISOString() } : null,
    );
    await endSessions(u.username);
    await audit(deps, null, 'admin_user_password_reset', { ...actor(ctx), username: u.username });
    return html(reply, await usersPage(ctx, tempPasswordNotice(u.username, pw, 'Đã đặt lại mật khẩu cho')));
  });

  app.post('/admin/users/:username/status', async (req, reply) => {
    const ctx = await guardPost(req, { owner: true });
    const u = await target(req, ctx);
    const act = String((req.body as Record<string, unknown>).action ?? '');
    if (act === 'disable' && u.role === 'owner' && (await otherActiveOwners(store, u.username)) === 0) {
      throw new HttpError(400, 'last_owner', 'Phải còn ít nhất một Chủ hệ thống đang hoạt động.');
    }
    const patch: Partial<AdminUser> =
      act === 'disable' ? { status: 'disabled' } : act === 'enable' ? { status: 'active', failedCount: 0, lockedUntil: 0 } : act === 'unlock' ? { failedCount: 0, lockedUntil: 0 } : {};
    if (!Object.keys(patch).length) throw new HttpError(400, 'bad_action', 'Thao tác không hợp lệ.');
    await store.update<AdminUser>(COL.adminUsers, u.username, (cur) => (cur ? { ...cur, ...patch, updatedAt: new Date().toISOString() } : null));
    if (act === 'disable') await endSessions(u.username);
    await audit(deps, null, `admin_user_${act}`, { ...actor(ctx), username: u.username });
    return reply.redirect(`/admin/users?msg=${act === 'disable' ? 'disabled' : act === 'enable' ? 'enabled' : 'unlocked'}`, 303);
  });

  app.post('/admin/users/:username/role', async (req, reply) => {
    const ctx = await guardPost(req, { owner: true });
    const u = await target(req, ctx);
    const role = String((req.body as Record<string, unknown>).role ?? '');
    if (role !== 'owner' && role !== 'admin') throw new HttpError(400, 'bad_role', 'Vai trò không hợp lệ.');
    if (u.role === 'owner' && role === 'admin' && u.status === 'active' && (await otherActiveOwners(store, u.username)) === 0) {
      throw new HttpError(400, 'last_owner', 'Phải còn ít nhất một Chủ hệ thống đang hoạt động.');
    }
    await store.update<AdminUser>(COL.adminUsers, u.username, (cur) => (cur ? { ...cur, role, updatedAt: new Date().toISOString() } : null));
    await audit(deps, null, 'admin_user_role', { ...actor(ctx), username: u.username, role });
    return reply.redirect('/admin/users?msg=role', 303);
  });
}
