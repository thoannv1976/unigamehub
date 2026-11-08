/**
 * Browser admin console (/admin/*).
 * Sign-in with the ADMIN_TOKEN, then a server-side session in an HttpOnly, SameSite=Strict cookie
 * (8 hours). Every state-changing form carries a per-session CSRF token. The JSON admin API
 * (/api/v1/admin/*, header token) is unchanged and used by scripts and Cloud Scheduler.
 */
import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { isLocal, TenantInput, toolConfig } from './admin.ts';
import { audit, type Deps } from './deps.ts';
import type { Platform, Tenant } from './lti/platforms.ts';
import type { GradeTarget } from './lti/routes.ts';
import type { SyncJob } from './results.ts';
import { COL } from './store/types.ts';
import type { GradeSync } from './sync.ts';
import { esc, hid, HttpError, rid } from './util.ts';
import { adminPage, page } from './views.ts';

export const SESSION_COOKIE = 'ugh_admin';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 10;

interface AdminSession {
  [k: string]: unknown;
  createdAt: string;
  expiresAt: number;
  csrf: string;
}

interface Ctx {
  csrf: string;
}

const JOB_STATUSES = ['pending', 'dead', 'done', 'superseded'] as const;
const JOB_LABEL: Record<string, string> = { pending: 'Đang chờ gửi', dead: 'Lỗi (đã dừng thử)', done: 'Đã gửi', superseded: 'Bị thay bằng điểm mới hơn' };

const fmtTime = (v: unknown): string => {
  if (v === undefined || v === null || v === '') return '–';
  const d = new Date(typeof v === 'number' ? v : String(v));
  return Number.isNaN(d.getTime()) ? esc(v) : esc(d.toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh', hour12: false }));
};
const badge = (cls: string, label: string): string => `<span class="badge ${esc(cls)}">${esc(label)}</span>`;
const csrfField = (ctx: Ctx): string => `<input type="hidden" name="csrf" value="${esc(ctx.csrf)}">`;

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
  const failures = new Map<string, { count: number; resetAt: number }>();

  const cookie = (value: string, maxAgeSec: number): string =>
    `${SESSION_COOKIE}=${value}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
  const sessionKey = (id: string): string => hid('as', id);

  async function currentSession(req: FastifyRequest): Promise<AdminSession | null> {
    const id = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (!id || id.length > 100) return null;
    const s = await store.get<AdminSession>(COL.adminSessions, sessionKey(id));
    if (!s) return null;
    if (s.expiresAt < Date.now()) {
      await store.delete(COL.adminSessions, sessionKey(id));
      return null;
    }
    return s;
  }

  /** Page guard: redirect to the login form when not signed in. */
  async function guard(req: FastifyRequest, reply: FastifyReply): Promise<Ctx | null> {
    const s = await currentSession(req);
    if (!s) {
      reply.redirect(`/admin/login?next=${encodeURIComponent(req.url)}`, 303);
      return null;
    }
    return { csrf: s.csrf };
  }

  /** Form guard: signed in + valid CSRF token. */
  async function guardPost(req: FastifyRequest): Promise<Ctx> {
    const s = await currentSession(req);
    if (!s) throw new HttpError(401, 'unauthorized', 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.');
    const given = String((req.body as Record<string, unknown> | undefined)?.csrf ?? '');
    if (!sameSecret(given, s.csrf)) throw new HttpError(403, 'csrf', 'Yêu cầu không hợp lệ (CSRF). Hãy tải lại trang và thử lại.');
    return { csrf: s.csrf };
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
  const loginForm = (next: string, error?: string) =>
    page('Đăng nhập quản trị · UniGame Hub', `<h1>UniGame Hub · Quản trị</h1>
${error ? `<div class="card notice err"><p class="err">${esc(error)}</p></div>` : ''}
<form class="card" method="post" action="/admin/login">
<input type="hidden" name="next" value="${esc(next)}">
<div class="field"><label for="token">Mã quản trị (ADMIN_TOKEN)</label><input id="token" name="token" type="password" autocomplete="current-password" required autofocus></div>
<button>Đăng nhập</button>
<p class="muted">Phiên đăng nhập có hiệu lực 8 giờ. Mã quản trị lưu trong Secret Manager (<code>hub-admin-token</code>) của project GCP.</p>
</form>`);

  app.get('/admin/login', async (req, reply) => {
    if (await currentSession(req)) return reply.redirect(safeNext((req.query as Record<string, string>).next), 303);
    return html(reply, loginForm(safeNext((req.query as Record<string, string>).next)));
  });

  app.post('/admin/login', async (req, reply) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const next = safeNext(body.next);
    const ip = req.ip;
    const now = Date.now();
    const f = failures.get(ip);
    if (f && f.resetAt > now && f.count >= LOGIN_MAX_FAILURES) {
      return html(reply, loginForm(next, 'Đăng nhập sai quá nhiều lần. Vui lòng thử lại sau 15 phút.'), 429);
    }
    const token = String(body.token ?? '');
    const ok = cfg.adminToken ? sameSecret(token, cfg.adminToken) : cfg.env === 'dev' && isLocal(req);
    if (!ok) {
      const cur = f && f.resetAt > now ? f : { count: 0, resetAt: now + LOGIN_WINDOW_MS };
      cur.count += 1;
      failures.set(ip, cur);
      await audit(deps, null, 'admin_login_failed', { ip });
      return html(reply, loginForm(next, 'Mã quản trị không đúng.'), 401);
    }
    failures.delete(ip);
    const id = rid(32);
    await store.set<AdminSession>(COL.adminSessions, sessionKey(id), { createdAt: new Date().toISOString(), expiresAt: now + SESSION_TTL_MS, csrf: rid(24) });
    await audit(deps, null, 'admin_login', { ip });
    return reply.header('set-cookie', cookie(id, SESSION_TTL_MS / 1000)).redirect(next, 303);
  });

  app.post('/admin/logout', async (req, reply) => {
    await guardPost(req);
    const id = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (id) await store.delete(COL.adminSessions, sessionKey(id));
    return reply.header('set-cookie', cookie('', 0)).redirect('/admin/login', 303);
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
    return html(reply, adminPage('Tổng quan', '/admin', ctx.csrf, `<p class="muted">Môi trường <b>${esc(cfg.env)}</b> · ${esc(cfg.baseUrl)}</p>
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
    return html(reply, adminPage('Gửi điểm về Moodle', '/admin/jobs', ctx.csrf, `${flash}
<p class="muted">Mỗi lần game gửi kết quả, Hub tạo một lượt gửi điểm về Sổ điểm Moodle. Lượt lỗi được thử lại tối đa 8 lần; sau đó dừng và cần bấm <b>Gửi lại</b>. Hiển thị tối đa 100 lượt mới nhất.</p>
<div class="filters">${filters}</div>
<div class="card">${await jobRows(ctx, jobs, `/admin/jobs${status === 'all' ? '' : `?status=${status}`}`)}</div>`));
  });

  app.post('/admin/jobs/:id/retry', async (req, reply) => {
    await guardPost(req);
    const id = (req.params as { id: string }).id;
    const job = await store.update<SyncJob>(COL.jobs, id, (cur) =>
      cur && (cur.status === 'dead' || cur.status === 'pending') ? { ...cur, status: 'pending', attempts: 0, nextRunAt: Date.now() } : null,
    );
    if (!job) throw new HttpError(404, 'not_found', 'Không tìm thấy lượt gửi điểm (hoặc đã gửi xong).');
    await audit(deps, job.tenantId, 'admin_job_retry', { jobId: id });
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
    return html(reply, adminPage('Trường', '/admin/tenants', ctx.csrf, `${flash}
<p class="muted">Mỗi trường gắn với một hoặc nhiều Moodle. Giảng viên chỉ thấy các game được chọn ở đây (và đang bật trên Hub). Lưu ý: game cũng cần tạo trường cùng mã trong database của game.</p>
${cards || '<p class="muted">Chưa có trường.</p>'}
<h2>Thêm trường</h2><div class="card">${form()}</div>`));
  });

  app.post('/admin/tenants', async (req, reply) => {
    await guardPost(req);
    const b = (req.body ?? {}) as Record<string, unknown>;
    const allowed = b.allowedGames === undefined ? [] : Array.isArray(b.allowedGames) ? b.allowedGames.map(String) : [String(b.allowedGames)];
    const t = TenantInput.parse({ id: b.id, name: b.name, allowedGames: allowed, status: b.status });
    await store.set<Tenant>(COL.tenants, t.id, t);
    await audit(deps, t.id, 'tenant_upsert', { allowedGames: t.allowedGames, status: t.status, via: 'console' });
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
    return html(reply, adminPage('Moodle / LMS đã kết nối', '/admin/platforms', ctx.csrf, `
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
    return html(reply, adminPage('Game', '/admin/games', ctx.csrf, `
<p class="muted">Bật/tắt game cho toàn Hub bằng biến môi trường <code>GAMES_ENABLED</code> khi deploy (deploy/deploy-cloudrun.sh). Chọn game cho từng trường ở trang <a href="/admin/tenants">Trường</a>.</p>
<div class="card tablewrap"><table><tr><th>ID</th><th>Tên</th><th>Trạng thái</th><th>Số bài chọn được</th><th>Địa chỉ adapter</th></tr>${rows}</table></div>`));
  });

  // ---------- LTI configuration ----------
  app.get('/admin/setup', async (req, reply) => {
    const ctx = await guard(req, reply);
    if (!ctx) return reply;
    const c = await toolConfig(deps);
    const rows = (pairs: Array<[string, string]>) => pairs.map(([k, v]) => `<tr><th>${esc(k)}</th><td><code>${esc(v)}</code></td></tr>`).join('');
    return html(reply, adminPage('Cấu hình LTI 1.3 cho Moodle', '/admin/setup', ctx.csrf, `
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
    return html(reply, adminPage('Nhật ký hoạt động', '/admin/audit', ctx.csrf, `
<p class="muted">150 sự kiện gần nhất: mở game, nhận kết quả, đăng nhập quản trị, thay đổi cấu hình.</p>
<div class="card tablewrap"><table><tr><th>Thời gian</th><th>Trường</th><th>Sự kiện</th><th>Chi tiết</th></tr>${rows || '<tr><td colspan="4" class="muted">Chưa có</td></tr>'}</table></div>`));
  });
}
