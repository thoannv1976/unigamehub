import type { FastifyInstance, FastifyReply } from 'fastify';
import { jwtVerify, type JWTPayload } from 'jose';
import { TICKET_TYP } from '../../sdk/index.ts';
import { type GameDef } from '../catalog.ts';
import { audit, type Deps } from '../deps.ts';
import { COL } from '../store/types.ts';
import { esc, hid, HttpError, isRecord, nowSec, rid } from '../util.ts';
import { autoPost, page, redirectWithFragment } from '../views.ts';
import { CLAIM, normalizeRole, SCOPE } from './claims.ts';
import { findPlatform, type Platform, type Tenant } from './platforms.ts';

interface LoginState {
  [k: string]: unknown;
  platformId: string;
  nonce: string;
  exp: number;
}

interface DlSession {
  [k: string]: unknown;
  platformId: string;
  tenantId: string;
  deploymentId: string;
  returnUrl: string;
  data?: string;
  exp: number;
}

/** Per resource link: where class-wide grades go (bulk results). */
export interface LinkTarget {
  [k: string]: unknown;
  tenantId: string;
  platformId: string;
  deploymentId: string;
  contextId?: string;
  resourceLinkId: string;
  gameId: string;
  lineitem: string;
  nrpsUrl: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface GradeTarget {
  [k: string]: unknown;
  tenantId: string;
  platformId: string;
  deploymentId: string;
  contextId?: string;
  resourceLinkId: string;
  userSub: string;
  hubUserId: string;
  gameId: string;
  lineitem: string;
  policy: 'latest' | 'best';
  lastSentOccurredAt: string | null;
  bestNormalized: number | null;
  createdAt: string;
  updatedAt: string;
}

const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);
const html = (reply: FastifyReply, body: string, status = 200) =>
  reply.status(status).header('content-type', 'text/html; charset=utf-8').header('cache-control', 'no-store').send(body);

const STATE_COOKIE = 'ugh_state';

export function isAllowed(tenant: Tenant, gameId: string): boolean {
  return tenant.allowedGames.includes('*') || tenant.allowedGames.includes(gameId);
}

export function registerLtiRoutes(app: FastifyInstance, deps: Deps): void {
  const { cfg, store, keys, catalog } = deps;
  const secureCookies = cfg.baseUrl.startsWith('https://');

  app.get('/lti/jwks', async (_req, reply) => {
    reply.header('cache-control', 'public, max-age=300');
    return keys.jwks();
  });

  // ---- OIDC third-party initiated login -------------------------------------------------
  app.route({
    method: ['GET', 'POST'],
    url: '/lti/login',
    handler: async (req, reply) => {
      const p = { ...(req.query as Record<string, unknown>), ...((isRecord(req.body) ? req.body : {}) as Record<string, unknown>) };
      const iss = str(p.iss);
      const loginHint = str(p.login_hint);
      const target = str(p.target_link_uri);
      if (!iss || !loginHint) throw new HttpError(400, 'bad_login', 'Thiếu tham số iss hoặc login_hint.');
      if (target && !target.startsWith(cfg.baseUrl)) throw new HttpError(400, 'bad_target', 'target_link_uri không thuộc Hub.');
      const platform = await findPlatform(store, iss, str(p.client_id));
      if (!platform) throw new HttpError(404, 'unknown_platform', 'Hệ thống LMS này chưa được đăng ký với UniGame Hub.');
      const dep = str(p.lti_deployment_id);
      if (dep && !platform.deploymentIds.includes(dep)) throw new HttpError(403, 'unknown_deployment', 'Deployment LTI chưa được đăng ký.');

      const state = rid();
      const nonce = rid();
      await store.set<LoginState>(COL.states, state, { platformId: platform.id, nonce, exp: nowSec() + 600 });
      const q = new URLSearchParams({
        scope: 'openid',
        response_type: 'id_token',
        response_mode: 'form_post',
        prompt: 'none',
        client_id: platform.clientId,
        redirect_uri: `${cfg.baseUrl}/lti/launch`,
        login_hint: loginHint,
        state,
        nonce,
      });
      const hint = str(p.lti_message_hint);
      if (hint) q.set('lti_message_hint', hint);
      if (secureCookies) {
        // Binds the browser to the state when third-party cookies are available (new-window launches).
        reply.header('set-cookie', `${STATE_COOKIE}=${state}; Path=/lti; Max-Age=600; HttpOnly; Secure; SameSite=None`);
      }
      const sep = platform.authUrl.includes('?') ? '&' : '?';
      return reply.redirect(`${platform.authUrl}${sep}${q.toString()}`, 302);
    },
  });

  // ---- Launch (resource link + deep linking request) -----------------------------------
  app.post('/lti/launch', async (req, reply) => {
    const b = (isRecord(req.body) ? req.body : {}) as Record<string, unknown>;
    if (str(b.error)) {
      throw new HttpError(400, 'platform_error', `LMS báo lỗi: ${str(b.error_description) ?? str(b.error)}`);
    }
    const stateId = str(b.state);
    const idToken = str(b.id_token);
    if (!stateId || !idToken) throw new HttpError(400, 'bad_launch', 'Thiếu id_token hoặc state.');
    const state = await store.take<LoginState>(COL.states, stateId);
    if (!state || state.exp < nowSec()) throw new HttpError(400, 'state_expired', 'Phiên đăng nhập LTI đã hết hạn hoặc đã được dùng.');
    const cookieState = /(?:^|;\s*)ugh_state=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
    if (cookieState && cookieState !== stateId) throw new HttpError(400, 'state_mismatch', 'Trạng thái đăng nhập không khớp.');

    const platform = await store.get<Platform>(COL.platforms, state.platformId);
    if (!platform || platform.status !== 'active') throw new HttpError(403, 'platform_disabled', 'Kết nối LMS đã bị tắt.');

    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(idToken, deps.platformJwks(platform), {
        issuer: platform.issuer,
        audience: platform.clientId,
        algorithms: ['RS256'],
        clockTolerance: 60,
      }));
    } catch (e) {
      req.log.warn({ err: (e as Error).message }, 'id_token verification failed');
      throw new HttpError(401, 'bad_signature', 'Không xác thực được thông điệp LTI từ LMS.');
    }
    if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== platform.clientId) {
      throw new HttpError(401, 'bad_azp', 'azp không hợp lệ.');
    }
    if (payload.nonce !== state.nonce) throw new HttpError(401, 'bad_nonce', 'Nonce không khớp.');
    if (!(await store.create(COL.nonces, hid('n', platform.id, String(payload.nonce)), { exp: payload.exp ?? nowSec() + 3600 }))) {
      throw new HttpError(401, 'replay', 'Thông điệp LTI đã được sử dụng.');
    }
    if (payload[CLAIM.version] !== '1.3.0') throw new HttpError(400, 'bad_version', 'Chỉ hỗ trợ LTI 1.3.0.');
    const deploymentId = String(payload[CLAIM.deploymentId] ?? '');
    if (!platform.deploymentIds.includes(deploymentId)) throw new HttpError(403, 'unknown_deployment', 'Deployment LTI chưa được đăng ký.');
    const tenant = await store.get<Tenant>(COL.tenants, platform.tenantId);
    if (!tenant || tenant.status !== 'active') throw new HttpError(403, 'tenant_inactive', 'Đơn vị (trường) chưa được kích hoạt trên Hub.');

    const type = payload[CLAIM.messageType];
    if (type === 'LtiDeepLinkingRequest') return deepLinkStart(reply, payload, platform, tenant, deploymentId);
    if (type !== 'LtiResourceLinkRequest') throw new HttpError(400, 'bad_message_type', `Loại thông điệp không hỗ trợ: ${String(type)}`);
    return resourceLaunch(reply, payload, platform, tenant, deploymentId);
  });

  async function resourceLaunch(reply: FastifyReply, payload: JWTPayload, platform: Platform, tenant: Tenant, deploymentId: string) {
    const sub = str(payload.sub);
    if (!sub) throw new HttpError(400, 'anonymous', 'Không hỗ trợ truy cập ẩn danh.');
    const custom = (isRecord(payload[CLAIM.custom]) ? payload[CLAIM.custom] : {}) as Record<string, unknown>;
    const rl = (isRecord(payload[CLAIM.resourceLink]) ? payload[CLAIM.resourceLink] : {}) as Record<string, unknown>;
    const ctx = (isRecord(payload[CLAIM.context]) ? payload[CLAIM.context] : undefined) as Record<string, unknown> | undefined;
    const lp = (isRecord(payload[CLAIM.launchPresentation]) ? payload[CLAIM.launchPresentation] : {}) as Record<string, unknown>;
    const role = normalizeRole(payload[CLAIM.roles]);
    const resourceLinkId = str(rl.id);
    if (!resourceLinkId) throw new HttpError(400, 'no_resource_link', 'Thiếu resource_link.');

    const gameId = str(custom.game_id) ?? str(custom.gameid);
    if (!gameId) {
      return html(reply, page('Chưa chọn game', `<h1>Hoạt động này chưa được gắn với game</h1>
<div class="card"><p>${role === 'instructor'
        ? 'Hãy sửa hoạt động trong Moodle, bấm <b>Chọn nội dung</b> (Select content) để chọn game từ UniGame Hub.'
        : 'Giảng viên chưa cấu hình hoạt động này. Vui lòng báo giảng viên.'}</p></div>`), 400);
    }
    const game = catalog.get(gameId);
    if (!game || !game.enabled) throw new HttpError(404, 'game_unavailable', 'Game này hiện chưa sẵn sàng trên Hub.');
    if (!isAllowed(tenant, game.id)) throw new HttpError(403, 'not_licensed', 'Trường chưa được cấp phép sử dụng game này.');

    const now = new Date().toISOString();
    const hubUserId = hid('u', tenant.id, platform.issuer, sub);
    const name = str(payload.name);
    const email = str(payload.email);
    const ext = (isRecord(payload[CLAIM.ext]) ? payload[CLAIM.ext] : {}) as Record<string, unknown>;
    const username = str(ext.user_username);
    await store.update(COL.users, hubUserId, (cur) => ({
      tenantId: tenant.id,
      issuer: platform.issuer,
      sub,
      name: name ?? cur?.name,
      email: email ?? cur?.email,
      username: username ?? cur?.username,
      firstSeenAt: cur?.firstSeenAt ?? now,
      lastLaunchAt: now,
      launches: Number(cur?.launches ?? 0) + 1,
    }));

    // Grade target: one per (platform, deployment, resource link, user). Only for learners with AGS score scope.
    let gradeTarget: string | undefined;
    const ags = isRecord(payload[CLAIM.ags]) ? (payload[CLAIM.ags] as Record<string, unknown>) : undefined;
    const scopes = Array.isArray(ags?.scope) ? (ags!.scope as string[]) : [];
    const lineitem = str(ags?.lineitem);
    if (role === 'learner' && lineitem && scopes.includes(SCOPE.score)) {
      gradeTarget = hid('gt', platform.id, deploymentId, resourceLinkId, sub);
      await store.update<GradeTarget>(COL.gradeTargets, gradeTarget, (cur) => ({
        tenantId: tenant.id,
        platformId: platform.id,
        deploymentId,
        contextId: str(ctx?.id),
        resourceLinkId,
        userSub: sub,
        hubUserId,
        gameId: game.id,
        lineitem,
        policy: custom.grade_policy === 'best' ? 'best' : 'latest',
        lastSentOccurredAt: cur?.lastSentOccurredAt ?? null,
        bestNormalized: cur?.bestNormalized ?? null,
        createdAt: cur?.createdAt ?? now,
        updatedAt: now,
      }));
    }

    // Link target: one per resource link (any role). Lets the game send grades for the whole class at once
    // (POST /api/v1/results/bulk); students are found through Names and Role Provisioning.
    let linkTarget: string | undefined;
    if (lineitem && scopes.includes(SCOPE.score)) {
      const nrps = isRecord(payload[CLAIM.nrps]) ? (payload[CLAIM.nrps] as Record<string, unknown>) : undefined;
      linkTarget = hid('lt', platform.id, deploymentId, resourceLinkId);
      await store.update<LinkTarget>(COL.linkTargets, linkTarget, (cur) => ({
        tenantId: tenant.id,
        platformId: platform.id,
        deploymentId,
        contextId: str(ctx?.id),
        resourceLinkId,
        gameId: game.id,
        lineitem,
        nrpsUrl: str(nrps?.context_memberships_url) ?? cur?.nrpsUrl ?? null,
        createdAt: cur?.createdAt ?? now,
        updatedAt: now,
      }));
    }

    const launchId = rid(12);
    await store.set(COL.launches, launchId, {
      tenantId: tenant.id, platformId: platform.id, hubUserId, gameId: game.id, role,
      contextId: str(ctx?.id), resourceLinkId, gradeTarget: gradeTarget ?? null, at: now,
    });

    const iat = nowSec();
    const ticket = await keys.sign(
      {
        iss: cfg.baseUrl,
        aud: game.id,
        sub: hubUserId,
        jti: rid(),
        iat,
        exp: iat + 120,
        ugh: {
          tenantId: tenant.id,
          platform: { issuer: platform.issuer, deploymentId },
          ltiSub: sub,
          name,
          givenName: str(payload.given_name),
          familyName: str(payload.family_name),
          email,
          username,
          role,
          context: ctx ? { id: str(ctx.id), title: str(ctx.title), label: str(ctx.label) } : undefined,
          resourceLink: { id: resourceLinkId, title: str(rl.title) },
          activity: str(custom.activity),
          gradeTarget,
          linkTarget,
          launchId,
          returnUrl: str(lp.return_url),
          locale: str(lp.locale),
        },
      },
      TICKET_TYP,
    );
    await audit(deps, tenant.id, 'launch', { launchId, gameId: game.id, hubUserId, role, gradable: !!gradeTarget });
    return html(reply, redirectWithFragment(game.launchUrl, `ticket=${encodeURIComponent(ticket)}`, `Đang mở ${game.name}…`));
  }

  // ---- Deep Linking: instructor picks a game -----------------------------------------
  async function deepLinkStart(reply: FastifyReply, payload: JWTPayload, platform: Platform, tenant: Tenant, deploymentId: string) {
    if (normalizeRole(payload[CLAIM.roles]) !== 'instructor') throw new HttpError(403, 'not_instructor', 'Chỉ giảng viên mới được chọn nội dung.');
    const settings = (isRecord(payload[CLAIM.dlSettings]) ? payload[CLAIM.dlSettings] : {}) as Record<string, unknown>;
    const returnUrl = str(settings.deep_link_return_url);
    if (!returnUrl) throw new HttpError(400, 'no_return_url', 'Thiếu deep_link_return_url.');
    const dlId = rid();
    await store.set<DlSession>(COL.dlSessions, dlId, {
      platformId: platform.id, tenantId: tenant.id, deploymentId, returnUrl, data: str(settings.data), exp: nowSec() + 1800,
    });
    const ctx = (isRecord(payload[CLAIM.context]) ? payload[CLAIM.context] : {}) as Record<string, unknown>;
    return html(reply, pickerPage(dlId, catalog.enabledFor(tenant.allowedGames), str(ctx.title)));
  }

  app.post('/lti/deeplink/submit', async (req, reply) => {
    const b = (isRecord(req.body) ? req.body : {}) as Record<string, unknown>;
    const dl = await store.take<DlSession>(COL.dlSessions, String(b.dl ?? ''));
    if (!dl || dl.exp < nowSec()) throw new HttpError(400, 'dl_expired', 'Phiên chọn nội dung đã hết hạn. Hãy bấm "Chọn nội dung" lại trong Moodle.');
    const platform = await store.get<Platform>(COL.platforms, dl.platformId);
    const tenant = await store.get<Tenant>(COL.tenants, dl.tenantId);
    if (!platform || !tenant) throw new HttpError(403, 'platform_disabled', 'Kết nối LMS không còn hiệu lực.');
    const game = catalog.get(String(b.game_id ?? ''));
    if (!game || !game.enabled || !isAllowed(tenant, game.id)) throw new HttpError(400, 'bad_game', 'Game không hợp lệ hoặc chưa được cấp phép.');

    const activity = String(b.activity ?? '').trim().slice(0, 200);
    if (activity && game.activities && !game.activities.some((a) => a.id === activity)) throw new HttpError(400, 'bad_activity', 'Bài/nhiệm vụ không hợp lệ.');
    const title = String(b.title ?? '').trim().slice(0, 255) || game.name;
    const maxScore = Math.round(Number(b.max_score ?? game.defaultMaxScore ?? 100));
    if (!(maxScore >= 1 && maxScore <= 1000)) throw new HttpError(400, 'bad_max', 'Điểm tối đa phải từ 1 đến 1000.');
    const gradable = b.gradable === '1';
    const policy = b.grade_policy === 'best' ? 'best' : 'latest';

    const item: Record<string, unknown> = {
      type: 'ltiResourceLink',
      title,
      text: game.description,
      url: `${cfg.baseUrl}/lti/launch`,
      custom: { game_id: game.id, ...(activity ? { activity } : {}), grade_policy: policy },
      window: { targetName: '_blank' },
      ...(gradable ? { lineItem: { scoreMaximum: maxScore, label: title, resourceId: `${game.id}:${activity || 'default'}`, tag: 'unigamehub' } } : {}),
    };
    const iat = nowSec();
    const jwt = await keys.sign({
      iss: platform.clientId,
      aud: platform.issuer,
      iat,
      exp: iat + 600,
      nonce: rid(),
      [CLAIM.deploymentId]: dl.deploymentId,
      [CLAIM.messageType]: 'LtiDeepLinkingResponse',
      [CLAIM.version]: '1.3.0',
      [CLAIM.dlContentItems]: [item],
      ...(dl.data ? { [CLAIM.dlData]: dl.data } : {}),
    });
    await audit(deps, tenant.id, 'deep_link', { gameId: game.id, activity, gradable, maxScore });
    return html(reply, autoPost(dl.returnUrl, { JWT: jwt }, 'Đang thêm hoạt động vào Moodle…'));
  });
}

function pickerPage(dlId: string, games: GameDef[], courseTitle?: string): string {
  const cards = games.length
    ? games
        .map((g, i) => `<label class="game card"><input type="radio" name="game_id" value="${esc(g.id)}" ${i === 0 ? 'checked' : ''}
 data-name="${esc(g.name)}" data-max="${g.defaultMaxScore ?? 100}" data-acts='${esc(JSON.stringify(g.activities ?? []))}'>
<b>${esc(g.name)}</b>${g.alias ? ` <span class="tag">${esc(g.alias)}</span>` : ''}<br><span class="muted">${esc(g.description)}</span>
${g.gradeNote ? `<br><small class="muted">Điểm: ${esc(g.gradeNote)}</small>` : ''}</label>`)
        .join('')
    : '<p class="err">Trường chưa được cấp phép game nào. Liên hệ quản trị UniGame Hub.</p>';
  return page('Chọn game – UniGame Hub', `<h1>Chọn game cho hoạt động</h1>
<p class="muted">${courseTitle ? `Khóa học: <b>${esc(courseTitle)}</b> · ` : ''}Sinh viên sẽ mở game ở tab mới và được đăng nhập tự động bằng tài khoản Moodle.</p>
<form method="post" action="/lti/deeplink/submit"><input type="hidden" name="dl" value="${esc(dlId)}">
<div class="grid">${cards}</div>
<div class="card">
<div class="field" id="actf"><label for="activity">Bài / nhiệm vụ trong game</label><select id="activity" name="activity"></select></div>
<div class="field"><label for="title">Tên hoạt động hiển thị trong Moodle</label><input type="text" id="title" name="title" maxlength="255"></div>
<div class="field"><label><input type="checkbox" name="gradable" value="1" checked> Đồng bộ điểm về Sổ điểm Moodle</label></div>
<div class="field"><label for="max_score">Điểm tối đa</label><input type="number" id="max_score" name="max_score" min="1" max="1000" value="100"></div>
<div class="field"><label for="grade_policy">Khi sinh viên làm nhiều lượt</label><select id="grade_policy" name="grade_policy">
<option value="latest">Lấy điểm lượt gần nhất</option><option value="best">Lấy điểm cao nhất</option></select></div>
<button ${games.length ? '' : 'disabled'}>Thêm vào Moodle</button></div></form>`, {
    script: `(function(){var f=document.forms[0],sel=document.getElementById('activity'),actf=document.getElementById('actf'),t=document.getElementById('title'),mx=document.getElementById('max_score'),last='';
function sync(){var r=f.querySelector('input[name=game_id]:checked');if(!r)return;var acts=JSON.parse(r.dataset.acts||'[]');sel.innerHTML='';
var o=document.createElement('option');o.value='';o.textContent='(Mặc định – toàn bộ game)';sel.appendChild(o);
acts.forEach(function(a){var x=document.createElement('option');x.value=a.id;x.textContent=a.title;sel.appendChild(x);});
actf.style.display=acts.length?'':'none';if(!t.value||t.value===last){t.value=r.dataset.name;last=t.value;}mx.value=r.dataset.max;}
f.addEventListener('change',function(e){if(e.target.name==='game_id')sync();});
sel.addEventListener('change',function(){var r=f.querySelector('input[name=game_id]:checked');var opt=sel.options[sel.selectedIndex];if(t.value===last){t.value=r.dataset.name+(sel.value?' – '+opt.textContent:'');last=t.value;}});sync();})();`,
  });
}
