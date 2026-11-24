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
import { adminPage, centerPage, emptyState, icon, notice } from './views.ts';

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

  // ---------- list helpers: query params, pagination ----------
  const q = (req: FastifyRequest): Record<string, string> => {
    const raw = (req.query ?? {}) as Record<string, unknown>;
    return Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, String(Array.isArray(v) ? v[0] : v ?? '').slice(0, 200)]));
  };
  const url = (base: string, params: Record<string, string | number | undefined>): string => {
    const parts = Object.entries(params)
      .filter(([, v]) => v !== undefined && v !== '' && v !== 'all' && !(typeof v === 'number' && v <= 1))
      .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`);
    return parts.length ? `${base}?${parts.join('&')}` : base;
  };
  function paginate<T>(items: T[], pageParam: string, size: number) {
    const pages = Math.max(1, Math.ceil(items.length / size));
    const pageNo = Math.min(Math.max(1, Number.parseInt(pageParam, 10) || 1), pages);
    return { items: items.slice((pageNo - 1) * size, pageNo * size), pageNo, pages, total: items.length, from: items.length ? (pageNo - 1) * size + 1 : 0, to: Math.min(pageNo * size, items.length) };
  }
  const pager = (base: string, params: Record<string, string>, p: { pageNo: number; pages: number; total: number; from: number; to: number }, capped: boolean) =>
    p.total
      ? `<div class="pager"><span>Hiển thị ${p.from}–${p.to} / ${p.total}${capped ? '+' : ''}</span><nav>${p.pageNo > 1 ? `<a class="btn small ghost" href="${esc(url(base, { ...params, page: p.pageNo - 1 }))}">← Trước</a>` : ''}${
          p.pageNo < p.pages ? `<a class="btn small ghost" href="${esc(url(base, { ...params, page: p.pageNo + 1 }))}">Sau →</a>` : ''
        }</nav></div>`
      : '';
  const contains = (hay: unknown, needle: string) => String(hay ?? '').toLowerCase().includes(needle);

  // ---------- public landing page ----------
  app.get('/', async (_req, reply) =>
    html(reply, centerPage('UniGame Hub', `<div class="card"><h1>Cổng game học tập cho Moodle</h1>
<p class="lead">Đăng nhập một lần bằng tài khoản Moodle, điểm tự động về Sổ điểm (LTI 1.3).</p>
${notice('info', '<b>Giảng viên và sinh viên:</b> hãy mở game từ hoạt động trong khóa học Moodle của bạn. Trang này không cần đăng nhập riêng.')}
<p class="foot">Quản trị viên hệ thống: <a href="/admin">đăng nhập trang quản trị</a></p></div>`)));

  // ---------- login / logout ----------
  const errBox = (error?: string) => (error ? notice('err', esc(error)) : '');
  const loginForm = async (next: string, error?: string, username = '') => {
    const noAccounts = (await store.find(COL.adminUsers, {}, 1)).length === 0;
    return centerPage('Đăng nhập quản trị · UniGame Hub', `<form class="card" method="post" action="/admin/login">
<h1>Đăng nhập quản trị</h1><p class="lead">Dành cho quản trị viên hệ thống</p>${errBox(error)}
<input type="hidden" name="next" value="${esc(next)}">
<div class="field"><label for="username">Tên đăng nhập</label><input id="username" name="username" type="text" value="${esc(username)}" autocomplete="username" autocapitalize="none" spellcheck="false" required${username ? '' : ' autofocus'}></div>
<div class="field"><label for="password">Mật khẩu</label><input id="password" name="password" type="password" autocomplete="current-password" required${username ? ' autofocus' : ''}></div>
<button class="wide">Đăng nhập</button>
<p class="foot">Phiên đăng nhập có hiệu lực 8 giờ. Quên mật khẩu: nhờ Chủ hệ thống đặt lại.</p>
</form>${noAccounts ? notice('info', 'Chưa có tài khoản quản trị nào. <a href="/admin/login?mode=token">Đăng nhập bằng mã ADMIN_TOKEN</a> để tạo tài khoản đầu tiên.') : ''}`, 'Quản trị');
  };
  const tokenForm = (next: string, error?: string) =>
    centerPage('Đăng nhập bằng mã khẩn cấp · UniGame Hub', `<form class="card" method="post" action="/admin/login">
<h1>Mã khẩn cấp</h1><p class="lead">Chỉ dùng khi không đăng nhập được bằng tài khoản</p>${errBox(error)}
<input type="hidden" name="next" value="${esc(next)}"><input type="hidden" name="mode" value="token">
<div class="field"><label for="token">Mã quản trị (ADMIN_TOKEN)</label><input id="token" name="token" type="password" autocomplete="off" required autofocus>
<div class="hint">Lưu trong Secret Manager (<code>hub-admin-token</code>) của project GCP.</div></div>
<button class="wide">Đăng nhập</button>
<p class="foot"><a href="/admin/login">← Đăng nhập bằng tài khoản</a></p>
</form>`, 'Quản trị');

  app.get('/admin/login', async (req, reply) => {
    const qs = q(req);
    if (await currentSession(req)) return reply.redirect(safeNext(qs.next), 303);
    return html(reply, qs.mode === 'token' ? tokenForm(safeNext(qs.next)) : await loginForm(safeNext(qs.next)));
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
${mustChange ? notice('warn', 'Bạn đang dùng <b>mật khẩu tạm</b>. Hãy đặt mật khẩu mới để tiếp tục.') : ''}
${ctx.viaToken
    ? notice('info', 'Bạn đang đăng nhập bằng mã ADMIN_TOKEN nên không có mật khẩu để đổi. Hãy tạo tài khoản ở trang <a href="/admin/users">Tài khoản</a>.')
    : `<form class="card" method="post" action="/admin/password" style="max-width:520px">${csrfField(ctx)}
<input type="text" name="username" value="${esc(ctx.username)}" autocomplete="username" hidden>
<div class="field"><label for="current">Mật khẩu hiện tại</label><input id="current" name="current" type="password" autocomplete="current-password" required autofocus></div>
<div class="field"><label for="next_pw">Mật khẩu mới</label><input id="next_pw" name="password" type="password" autocomplete="new-password" minlength="10" required><div class="hint">Ít nhất 10 ký tự, không chứa tên đăng nhập.</div></div>
<div class="field"><label for="confirm">Nhập lại mật khẩu mới</label><input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="10" required></div>
<div class="actions-row"><button>Đổi mật khẩu</button><span class="muted small">Các phiên đăng nhập khác của bạn sẽ bị đăng xuất.</span></div></form>`}`);

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

  // ---------- job tables ----------
  type JobRow = SyncJob & { id: string };
  async function loadTargets(jobs: JobRow[]): Promise<Map<string, GradeTarget | null>> {
    const targets = new Map<string, GradeTarget | null>();
    for (const j of jobs) if (!targets.has(j.gradeTarget)) targets.set(j.gradeTarget, await store.get<GradeTarget>(COL.gradeTargets, j.gradeTarget));
    return targets;
  }
  const gameName = (gt: GradeTarget | null | undefined) => (gt ? catalog.get(gt.gameId)?.name ?? gt.gameId : '–');

  async function jobTable(ctx: Ctx, jobs: JobRow[], back: string, empty: string, compact = false): Promise<string> {
    if (!jobs.length) return emptyState(empty, '', 'inbox');
    const targets = await loadTargets(jobs);
    const rows = jobs.map((j) => {
      const gt = targets.get(j.gradeTarget);
      const canRetry = j.status === 'dead' || j.status === 'pending';
      if (compact) {
        return `<tr><td class="nowrap">${fmtTime(j.createdAt)}</td><td><b>${esc(gameName(gt))}</b><div class="muted small">${esc(j.tenantId)} · <code>${esc(gt?.userSub ?? '–')}</code></div></td>
<td class="num">${esc(j.payload.scoreGiven)} / ${esc(j.payload.scoreMaximum)}</td><td>${badge(j.status, JOB_LABEL[j.status] ?? j.status)}</td></tr>`;
      }
      const who = `<b>${esc(gameName(gt))}</b><div class="muted small">${esc(j.tenantId)} · <code>${esc(gt?.userSub ?? '–')}</code></div>`;
      return `<tr><td class="nowrap">${fmtTime(j.createdAt)}</td><td>${who}</td><td class="num">${esc(j.payload.scoreGiven)} / ${esc(j.payload.scoreMaximum)}</td>
<td class="nowrap">${badge(j.status, JOB_LABEL[j.status] ?? j.status)}<div class="muted small">${esc(j.attempts)} lần thử</div></td>
<td class="wrap muted small">${esc(j.lastError ?? '')}</td>
<td class="actions">${canRetry ? `<form method="post" action="/admin/jobs/${esc(encodeURIComponent(j.id))}/retry">${csrfField(ctx)}<input type="hidden" name="back" value="${esc(back)}"><button class="small ghost">${icon('refresh')}Gửi lại</button></form>` : ''}</td></tr>`;
    });
    if (compact) return `<div class="tablewrap"><table><thead><tr><th>Thời gian</th><th>Game · Trường · Người dùng LMS</th><th>Điểm</th><th>Trạng thái</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
    return `<div class="tablewrap"><table><thead><tr><th>Thời gian</th><th>Game · Trường · Người dùng LMS</th><th>Điểm</th><th>Trạng thái</th><th>Lỗi gần nhất</th><th></th></tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
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
    const stat = (n: number, label: string, ic: string, href: string, tone = '') =>
      `<a class="stat ${tone}" href="${href}"><span class="ic">${icon(ic)}</span><span><b>${esc(n)}</b><span class="lbl">${esc(label)}</span></span></a>`;
    const flash = q(req).msg === 'password' ? notice('ok', 'Đã đổi mật khẩu.') : '';
    const tokenHint = ctx.viaToken
      ? notice('warn', 'Bạn đang dùng mã khẩn cấp ADMIN_TOKEN. Hãy <a href="/admin/users">tạo tài khoản</a> và đăng nhập bằng tài khoản cho công việc hằng ngày.')
      : '';
    const alert = dead.length
      ? notice('err', `<b>${dead.length} lượt gửi điểm bị lỗi</b> – Moodle chưa nhận các điểm này. <a href="/admin/jobs?status=dead">Xem và gửi lại</a>.`)
      : '';
    const latestDead = [...dead].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)).slice(0, 5) as JobRow[];
    const deadTargets = await loadTargets(latestDead);
    const deadList = latestDead.length
      ? `<div class="tablewrap"><table><tbody>${latestDead
          .map((j) => `<tr><td><b>${esc(gameName(deadTargets.get(j.gradeTarget)))}</b> · ${esc(j.tenantId)}<div class="muted small">${fmtTime(j.createdAt)}</div><div class="err small">${esc(j.lastError ?? '')}</div></td></tr>`)
          .join('')}</tbody></table></div><div class="card-f"><a href="/admin/jobs?status=dead">Xem tất cả lỗi →</a></div>`
      : emptyState('Không có lỗi gửi điểm', 'Mọi điểm đều đã về Moodle.', 'check');
    const revision = process.env.K_REVISION;
    return html(reply, adminPage('Tổng quan', '/admin', ctx, `${flash}${tokenHint}${alert}
<div class="stats">${stat(tenants.length, 'Trường', 'school', '/admin/tenants')}${stat(platforms.length, 'Moodle / LMS', 'plug', '/admin/platforms')}
${stat(enabledGames.length, 'Game đang bật', 'game', '/admin/games')}${stat(pending.length, 'Điểm đang chờ gửi', 'clock', '/admin/jobs?status=pending', pending.length ? 'warn' : '')}
${stat(dead.length, 'Điểm gửi lỗi', 'alert', '/admin/jobs?status=dead', dead.length ? 'err' : 'ok')}</div>
<div class="cols"><section class="card flush"><div class="card-h"><h2>Lượt gửi điểm gần đây</h2>
<form method="post" action="/admin/sync">${csrfField(ctx)}<button class="small ghost">${icon('bolt')}Chạy gửi điểm ngay</button></form></div>
${await jobTable(ctx, recent as JobRow[], '/admin', 'Chưa có lượt gửi điểm nào.', true)}
<div class="card-f muted small">Hệ thống tự gửi lại mỗi 5 phút (Cloud Scheduler). <a href="/admin/jobs">Xem tất cả →</a></div></section>
<div><section class="card flush"><div class="card-h"><h2>Cần chú ý</h2>${dead.length ? badge('dead', `${dead.length} lỗi`) : ''}</div>${deadList}</section>
<section class="card"><h3>Hệ thống</h3><table class="kv"><tbody>
<tr><th>Môi trường</th><td><b>${esc(cfg.env)}</b></td></tr><tr><th>Địa chỉ</th><td><code>${esc(cfg.baseUrl)}</code></td></tr>
${revision ? `<tr><th>Phiên bản</th><td><code>${esc(revision)}</code></td></tr>` : ''}</tbody></table></section></div></div>`,
      { lead: `Xin chào <b>${esc(ctx.viaToken ? 'quản trị viên' : ctx.displayName)}</b>. Tình trạng kết nối Moodle và gửi điểm của hệ thống.` }));
  });

  // ---------- grade sync jobs ----------
  const JOB_PAGE = 25;
  const JOB_CAP = 500;
  app.get('/admin/jobs', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const qs = q(req);
    const status = (JOB_STATUSES as readonly string[]).includes(qs.status ?? '') ? qs.status! : 'all';
    const tenant = qs.tenant ?? '';
    const needle = (qs.q ?? '').trim().toLowerCase();
    let jobs =
      status === 'all'
        ? await store.recent<SyncJob>(COL.jobs, 'createdAt', JOB_CAP)
        : (await store.find<SyncJob>(COL.jobs, { status }, JOB_CAP)).sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    const capped = jobs.length >= JOB_CAP;
    if (tenant) jobs = jobs.filter((j) => j.tenantId === tenant);
    if (needle) {
      const targets = await loadTargets(jobs);
      jobs = jobs.filter((j) => {
        const gt = targets.get(j.gradeTarget);
        return [j.tenantId, j.lastError, gt?.userSub, gameName(gt), j.id].some((v) => contains(v, needle));
      });
    }
    const pg = paginate(jobs, qs.page ?? '', JOB_PAGE);
    const params = { status, tenant, q: qs.q ?? '' };
    const tenants = (await store.find<Tenant>(COL.tenants, {}, 500)).sort((a, b) => a.id.localeCompare(b.id));
    const chips = [['all', 'Tất cả'], ...JOB_STATUSES.map((s) => [s, JOB_LABEL[s]!])]
      .map(([v, l]) => `<a href="${esc(url('/admin/jobs', { ...params, status: v }))}"${v === status ? ' class="on"' : ''}>${esc(l)}</a>`)
      .join('');
    const toolbar = `<div class="toolbar"><div class="filters">${chips}</div>
<form method="get" action="/admin/jobs" role="search">${status !== 'all' ? `<input type="hidden" name="status" value="${esc(status)}">` : ''}
<select name="tenant" aria-label="Trường"><option value="">Mọi trường</option>${tenants.map((t) => `<option value="${esc(t.id)}"${t.id === tenant ? ' selected' : ''}>${esc(t.name)}</option>`).join('')}</select>
<input type="search" name="q" value="${esc(qs.q ?? '')}" placeholder="Người dùng, game, lỗi…" aria-label="Tìm kiếm"><button class="small ghost">${icon('search')}Lọc</button></form></div>`;
    const flash = qs.msg === 'retry' ? notice('ok', 'Đã đưa lượt gửi vào hàng chờ và chạy gửi lại.') : qs.msg === 'sync' ? notice('ok', 'Đã chạy gửi điểm.') : '';
    const filtered = tenant || needle || status !== 'all';
    return html(reply, adminPage('Gửi điểm về Moodle', '/admin/jobs', ctx, `${flash}
<section class="card flush">${toolbar}
${await jobTable(ctx, pg.items, url('/admin/jobs', { ...params, page: pg.pageNo }), filtered ? 'Không có lượt gửi nào khớp bộ lọc.' : 'Chưa có lượt gửi điểm nào.')}
${pager('/admin/jobs', params, pg, capped)}</section>`, {
      lead: 'Mỗi lần game gửi kết quả, Hub tạo một lượt gửi điểm về Sổ điểm Moodle. Lượt lỗi được thử lại tối đa 8 lần; sau đó dừng và cần bấm <b>Gửi lại</b>.',
      actions: `<form method="post" action="/admin/sync">${csrfField(ctx)}<button class="small">${icon('bolt')}Chạy gửi điểm ngay</button></form>`,
    }));
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
    const qs = q(req);
    const [tenants, platforms] = await Promise.all([
      store.find<Tenant>(COL.tenants, {}, 500).then((ts) => ts.sort((a, b) => a.id.localeCompare(b.id))),
      store.find<Platform>(COL.platforms, {}, 500),
    ]);
    const games = catalog.list().filter((g) => g.enabled);
    const editing = tenants.find((t) => t.id === qs.edit);
    const form = (t?: Tenant) => {
      const allowed = t?.allowedGames ?? [];
      const boxes = games
        .map((g) => `<label><input type="checkbox" name="allowedGames" value="${esc(g.id)}"${allowed.includes('*') || allowed.includes(g.id) ? ' checked' : ''}><span>${esc(g.name)}<br><span class="muted small">${esc(g.id)}</span></span></label>`)
        .join('');
      return `<form method="post" action="/admin/tenants">${csrfField(ctx)}
<div class="row">${t ? `<input type="hidden" name="id" value="${esc(t.id)}">` : `<div class="field"><label for="tid">Mã trường</label><input id="tid" type="text" name="id" required pattern="[a-z0-9][a-z0-9_-]{1,63}" autocapitalize="none" spellcheck="false"><div class="hint">Chữ thường, số, - và _. Không đổi được sau khi tạo.</div></div>`}
<div class="field"><label for="tname${t ? '-e' : ''}">Tên trường</label><input id="tname${t ? '-e' : ''}" type="text" name="name" value="${esc(t?.name ?? '')}" required maxlength="200"></div>
<div class="field"><label for="tstatus${t ? '-e' : ''}">Trạng thái</label><select id="tstatus${t ? '-e' : ''}" name="status"><option value="active"${t?.status !== 'suspended' ? ' selected' : ''}>Hoạt động</option><option value="suspended"${t?.status === 'suspended' ? ' selected' : ''}>Tạm dừng</option></select></div></div>
<div class="field"><label>Game được dùng</label>${boxes ? `<div class="checks">${boxes}</div>` : '<p class="muted">Chưa có game nào được bật.</p>'}</div>
<div class="actions-row"><button class="small">${t ? 'Lưu thay đổi' : `${icon('plus')}Tạo trường`}</button>${t ? '<a class="btn small ghost" href="/admin/tenants">Hủy</a>' : ''}</div></form>`;
    };
    const gameCount = (t: Tenant) => (t.allowedGames.includes('*') ? 'Tất cả game' : `${t.allowedGames.length} game`);
    const rows = tenants
      .map((t) => `<tr><td><b>${esc(t.name)}</b><div class="muted small"><code>${esc(t.id)}</code></div></td><td>${esc(gameCount(t))}</td>
<td class="num">${platforms.filter((p) => p.tenantId === t.id).length}</td><td>${badge(t.status, t.status === 'active' ? 'Hoạt động' : 'Tạm dừng')}</td>
<td class="actions"><a class="btn small ghost" href="/admin/tenants?edit=${esc(encodeURIComponent(t.id))}#edit">Sửa</a></td></tr>`)
      .join('');
    const flash = qs.msg === 'saved' ? notice('ok', 'Đã lưu.') : '';
    return html(reply, adminPage('Trường', '/admin/tenants', ctx, `${flash}
${editing ? `<section class="card" id="edit"><h2 style="margin-top:0">Sửa: ${esc(editing.name)} <code>${esc(editing.id)}</code></h2>${form(editing)}</section>` : ''}
<section class="card flush"><div class="card-h"><h2>Danh sách trường</h2><span class="muted small">${tenants.length} trường</span></div>
${tenants.length ? `<div class="tablewrap"><table><thead><tr><th>Trường</th><th>Game được dùng</th><th>Moodle</th><th>Trạng thái</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>` : emptyState('Chưa có trường nào', 'Thêm trường đầu tiên ở bên dưới.', 'school')}</section>
<section class="card"><details class="more"${tenants.length ? '' : ' open'}><summary>${icon('plus')}Thêm trường</summary>${form()}</details></section>`, {
      lead: 'Mỗi trường gắn với một hoặc nhiều Moodle. Giảng viên chỉ thấy các game được chọn ở đây (và đang bật trên Hub). Game cũng cần tạo trường cùng mã trong database của game.',
    }));
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
    const platforms = (await store.find<Platform>(COL.platforms, {}, 500)).sort((a, b) => a.tenantId.localeCompare(b.tenantId));
    const rows = platforms
      .map((p) => `<tr><td><b>${esc(p.name)}</b></td><td>${esc(p.tenantId)}</td><td class="wrap"><code>${esc(p.issuer)}</code></td><td><code>${esc(p.clientId)}</code></td>
<td>${esc(p.deploymentIds.join(', '))}</td><td>${badge(p.status, p.status === 'active' ? 'Hoạt động' : 'Tắt')}</td><td class="nowrap">${fmtTime(p.updatedAt)}</td></tr>`)
      .join('');
    return html(reply, adminPage('Moodle / LMS đã kết nối', '/admin/platforms', ctx, `
<section class="card flush">${platforms.length
      ? `<div class="tablewrap"><table><thead><tr><th>Tên</th><th>Trường</th><th>Issuer</th><th>Client ID</th><th>Deployment</th><th>Trạng thái</th><th>Cập nhật</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : emptyState('Chưa có Moodle nào được kết nối', 'Đăng ký bằng <code>npm run register-platform</code>.', 'plug')}</section>`, {
      lead: 'Mỗi dòng là một Moodle (issuer + client ID) đã đăng ký với Hub. Thêm Moodle mới bằng script <code>npm run register-platform</code> (cần thông tin từ trang External tool của Moodle).',
    }));
  });

  // ---------- games ----------
  app.get('/admin/games', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const qs = q(req);
    const show = qs.show === 'on' || qs.show === 'off' ? qs.show : 'all';
    const needle = (qs.q ?? '').trim().toLowerCase();
    const all = catalog.list();
    const list = all
      .filter((g) => show === 'all' || (show === 'on') === g.enabled)
      .filter((g) => !needle || [g.id, g.name, g.alias].some((v) => contains(v, needle)));
    const rows = list
      .map((g) => `<tr><td><b>${esc(g.name)}</b>${g.alias ? ` <span class="tag">${esc(g.alias)}</span>` : ''}<div class="muted small"><code>${esc(g.id)}</code></div></td>
<td>${g.enabled ? badge('active', 'Đang bật') : badge('', 'Chưa tích hợp')}</td><td class="num">${esc(g.activities?.length ?? 0)}</td><td class="wrap"><code>${esc(g.launchUrl)}</code></td></tr>`)
      .join('');
    const on = all.filter((g) => g.enabled).length;
    const chip = (v: string, label: string, n: number) => `<a href="${esc(url('/admin/games', { show: v, q: qs.q ?? '' }))}"${v === show ? ' class="on"' : ''}>${esc(label)}<span class="n">${n}</span></a>`;
    return html(reply, adminPage('Game', '/admin/games', ctx, `
<section class="card flush"><div class="toolbar"><div class="filters">${chip('all', 'Tất cả', all.length)}${chip('on', 'Đang bật', on)}${chip('off', 'Chưa tích hợp', all.length - on)}</div>
<form method="get" action="/admin/games" role="search">${show !== 'all' ? `<input type="hidden" name="show" value="${esc(show)}">` : ''}<input type="search" name="q" value="${esc(qs.q ?? '')}" placeholder="Tên hoặc mã game…" aria-label="Tìm game"><button class="small ghost">${icon('search')}Tìm</button></form></div>
${list.length ? `<div class="tablewrap"><table><thead><tr><th>Game</th><th>Trạng thái</th><th>Số bài chọn được</th><th>Địa chỉ adapter</th></tr></thead><tbody>${rows}</tbody></table></div>` : emptyState('Không có game nào khớp bộ lọc', '', 'game')}</section>`, {
      lead: 'Bật/tắt game cho toàn Hub bằng biến môi trường <code>GAMES_ENABLED</code> trên Cloud Run. Chọn game cho từng trường ở trang <a href="/admin/tenants">Trường</a>.',
    }));
  });

  // ---------- LTI configuration ----------
  app.get('/admin/setup', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const c = await toolConfig(deps);
    const rows = (pairs: Array<[string, string]>) => pairs.map(([k, v]) => `<tr><th>${esc(k)}</th><td><code>${esc(v)}</code></td></tr>`).join('');
    return html(reply, adminPage('Cấu hình LTI 1.3 cho Moodle', '/admin/setup', ctx, `
<section class="card flush"><div class="card-h"><h2>Thông số khai báo trong Moodle</h2></div><div class="tablewrap"><table class="kv"><tbody>${rows([
      ['Tool URL', c.toolUrl], ['LTI version', 'LTI 1.3'], ['Public key type', 'Keyset URL'],
      ['Public keyset', c.publicKeysetUrl], ['Initiate login URL', c.initiateLoginUrl], ['Redirection URI(s)', c.redirectionUris.join('\n')],
      ['Supports Deep Linking', 'Có'], ['Content Selection URL', c.deepLinkingUrl], ['Default launch container', 'New window'],
      ['Services', 'IMS LTI Assignment and Grade Services: "Use this service for grade sync and column management"; Names and Role Provisioning: "Use this service"'],
      ['Privacy', "Share launcher's name: Always · Share email: Always · Accept grades: Always"],
    ])}</tbody></table></div></section>
<section class="card"><details class="more"><summary>${icon('key')}Public key (RSA)</summary><pre>${esc(c.publicKeyPem)}</pre></details></section>`, {
      lead: 'Moodle: Site administration → Plugins → External tool → Manage tools → <b>Configure a tool manually</b>.',
    }));
  });

  // ---------- audit log ----------
  const AUDIT_LABEL: Record<string, string> = {
    admin_login: 'Đăng nhập quản trị', admin_login_failed: 'Đăng nhập thất bại', admin_user_locked: 'Khóa tài khoản (sai mật khẩu)',
    admin_password_changed: 'Đổi mật khẩu', admin_user_created: 'Tạo tài khoản', admin_user_password_reset: 'Đặt lại mật khẩu',
    admin_user_disable: 'Vô hiệu hóa tài khoản', admin_user_enable: 'Kích hoạt tài khoản', admin_user_unlock: 'Mở khóa tài khoản', admin_user_role: 'Đổi vai trò',
    admin_job_retry: 'Gửi lại điểm', tenant_upsert: 'Lưu trường', platform_upsert: 'Lưu Moodle',
  };
  const AUDIT_PAGE = 50;
  const AUDIT_CAP = 500;
  app.get('/admin/audit', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const qs = q(req);
    const logs = await store.recent<Record<string, unknown>>(COL.audit, 'at', AUDIT_CAP);
    const actions = [...new Set(logs.map((l) => String(l.action)))].sort();
    const action = actions.includes(qs.action ?? '') ? qs.action! : '';
    const needle = (qs.q ?? '').trim().toLowerCase();
    const filtered = logs.filter((l) => (!action || l.action === action) && (!needle || contains(JSON.stringify(l), needle)));
    const pg = paginate(filtered, qs.page ?? '', AUDIT_PAGE);
    const params = { action, q: qs.q ?? '' };
    const rows = pg.items
      .map((l) => {
        const { at, tenantId, action: act, actor: who, id: _id, ...rest } = l as Record<string, unknown>;
        const label = AUDIT_LABEL[String(act)];
        const bad = /failed|locked/.test(String(act));
        return `<tr><td class="nowrap">${fmtTime(at)}</td><td>${who ? `<b>${esc(who)}</b>` : '<span class="muted">–</span>'}</td><td>${esc(tenantId ?? '–')}</td>
<td>${label ? `<span${bad ? ' class="err"' : ''}>${esc(label)}</span><div class="muted small"><code>${esc(act)}</code></div>` : `<code>${esc(act)}</code>`}</td>
<td class="wrap muted small"><code>${esc(JSON.stringify(rest))}</code></td></tr>`;
      })
      .join('');
    const toolbar = `<div class="toolbar"><form method="get" action="/admin/audit" role="search" style="margin-left:0">
<select name="action" aria-label="Sự kiện"><option value="">Mọi sự kiện</option>${actions.map((a) => `<option value="${esc(a)}"${a === action ? ' selected' : ''}>${esc(AUDIT_LABEL[a] ?? a)}</option>`).join('')}</select>
<input type="search" name="q" value="${esc(qs.q ?? '')}" placeholder="Người thao tác, IP, mã…" aria-label="Tìm trong nhật ký"><button class="small ghost">${icon('search')}Lọc</button>
${action || needle ? '<a class="btn small ghost" href="/admin/audit">Xóa lọc</a>' : ''}</form></div>`;
    return html(reply, adminPage('Nhật ký hoạt động', '/admin/audit', ctx, `
<section class="card flush">${toolbar}
${pg.items.length ? `<div class="tablewrap"><table><thead><tr><th>Thời gian</th><th>Người thao tác</th><th>Trường</th><th>Sự kiện</th><th>Chi tiết</th></tr></thead><tbody>${rows}</tbody></table></div>` : emptyState(action || needle ? 'Không có sự kiện nào khớp bộ lọc' : 'Chưa có sự kiện nào', '', 'list')}
${pager('/admin/audit', params, pg, logs.length >= AUDIT_CAP)}</section>`, {
      lead: `Mở game, nhận kết quả, đăng nhập quản trị, thay đổi cấu hình. Tìm trong ${AUDIT_CAP} sự kiện gần nhất.`,
    }));
  });

  // ---------- admin accounts (owner only) ----------
  const USER_FLASH: Record<string, string> = {
    disabled: 'Đã vô hiệu hóa tài khoản và đăng xuất mọi phiên của tài khoản đó.',
    enabled: 'Đã kích hoạt lại tài khoản.',
    unlocked: 'Đã mở khóa tài khoản.',
    role: 'Đã đổi vai trò.',
  };

  const userTable = (ctx: Ctx, users: AdminUser[]) => {
    if (!users.length) return emptyState('Chưa có tài khoản nào', 'Tạo tài khoản Chủ hệ thống đầu tiên ở bên dưới.', 'users');
    const now = Date.now();
    const rows = users.map((u) => {
      const self = u.username === ctx.username;
      const locked = u.lockedUntil > now;
      const state = u.status !== 'active' ? badge('disabled', 'Vô hiệu') : locked ? badge('pending', 'Tạm khóa') : badge('active', 'Hoạt động');
      const action = (path: string, fields: Record<string, string>, label: string, cls = 'small ghost') =>
        `<form method="post" action="/admin/users/${esc(encodeURIComponent(u.username))}/${path}">${csrfField(ctx)}${Object.entries(fields)
          .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
          .join('')}<button class="${cls}">${esc(label)}</button></form>`;
      const actions = self
        ? '<span class="muted small">(bạn)</span>'
        : [
            action('reset', {}, 'Đặt lại mật khẩu'),
            locked ? action('status', { action: 'unlock' }, 'Mở khóa') : '',
            action('role', { role: u.role === 'owner' ? 'admin' : 'owner' }, u.role === 'owner' ? 'Hạ xuống Quản trị viên' : 'Nâng lên Chủ hệ thống'),
            u.status === 'active' ? action('status', { action: 'disable' }, 'Vô hiệu hóa', 'small danger') : action('status', { action: 'enable' }, 'Kích hoạt'),
          ].join('');
      return `<tr><td><b>${esc(u.username)}</b><div class="muted small">${esc(u.displayName)}</div></td><td>${esc(ROLE_LABEL[u.role])}</td><td>${state}${u.mustChangePassword ? ' <span class="tag">chờ đổi mật khẩu</span>' : ''}</td>
<td class="nowrap">${fmtTime(u.lastLoginAt)}</td><td class="nowrap">${fmtTime(u.createdAt)}<div class="muted small">${esc(u.createdBy)}</div></td><td class="actions">${actions}</td></tr>`;
    });
    return `<div class="tablewrap"><table><thead><tr><th>Tài khoản</th><th>Vai trò</th><th>Trạng thái</th><th>Đăng nhập gần nhất</th><th>Tạo lúc / bởi</th><th></th></tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
  };

  const usersPage = async (ctx: Ctx, top = '') => {
    const users = await listUsers(store);
    return adminPage('Tài khoản quản trị', '/admin/users', ctx, `${top}
<section class="card flush"><div class="card-h"><h2>Tài khoản</h2><span class="muted small">${users.length} tài khoản</span></div>${userTable(ctx, users)}</section>
<section class="card"><h2 style="margin-top:0">Thêm tài khoản</h2>
<form method="post" action="/admin/users">${csrfField(ctx)}<div class="row">
<div class="field"><label for="nu">Tên đăng nhập</label><input id="nu" name="username" type="text" required pattern="[a-zA-Z0-9][a-zA-Z0-9._\\-]{2,31}" autocapitalize="none" spellcheck="false"><div class="hint">3–32 ký tự: chữ thường, số, . _ -</div></div>
<div class="field"><label for="nd">Họ tên</label><input id="nd" name="displayName" type="text" maxlength="100"><div class="hint">Không bắt buộc</div></div>
<div class="field"><label for="nr">Vai trò</label><select id="nr" name="role"><option value="admin">${ROLE_LABEL.admin}</option><option value="owner">${ROLE_LABEL.owner}</option></select></div></div>
<div class="actions-row"><button class="small">${icon('plus')}Tạo tài khoản</button><span class="muted small">Hệ thống tạo mật khẩu tạm và hiện một lần duy nhất.</span></div></form></section>`, {
      lead: `<b>Chủ hệ thống</b> quản lý được tài khoản; <b>Quản trị viên</b> dùng mọi chức năng còn lại. Tài khoản mới nhận mật khẩu tạm và phải đổi ở lần đăng nhập đầu. Sai mật khẩu ${USER_LOCK_AFTER} lần liên tiếp thì bị khóa 15 phút.`,
    });
  };

  const tempPasswordNotice = (username: string, pw: string, what: string) =>
    `<div class="notice ok" role="status">${icon('check')}<div><p>${esc(what)} <b>${esc(username)}</b>. Mật khẩu tạm (chỉ hiện <b>một lần</b>, hãy gửi riêng cho người dùng):</p>
<pre class="secret">${esc(pw)}</pre><p class="muted small">Người dùng phải đổi mật khẩu ngay ở lần đăng nhập đầu tiên.</p></div></div>`;

  app.get('/admin/users', async (req, reply) => {
    const ctx = await guard(req, reply, { owner: true });
    if (!ctx) return reply;
    const msg = USER_FLASH[q(req).msg ?? ''];
    return html(reply, await usersPage(ctx, msg ? notice('ok', esc(msg)) : ''));
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
