import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { audit, type Deps } from './deps.ts';
import { PlatformInput, upsertPlatform, type Platform, type Tenant } from './lti/platforms.ts';
import type { SyncJob } from './results.ts';
import { COL } from './store/types.ts';
import type { GradeSync } from './sync.ts';
import { esc, HttpError } from './util.ts';
import { page } from './views.ts';

const TenantInput = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9_-]{1,63}$/),
  name: z.string().min(1).max(200),
  allowedGames: z.array(z.string().min(1)).default(['*']),
  status: z.enum(['active', 'suspended']).default('active'),
});

const isLocal = (req: FastifyRequest) => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.ip);

export function registerAdminRoutes(app: FastifyInstance, deps: Deps, sync: GradeSync): void {
  const { cfg, store, keys, catalog } = deps;

  const requireAdmin = (req: FastifyRequest) => {
    const given = String(req.headers['x-admin-token'] ?? '').trim() || /^Bearer (.+)$/.exec(String(req.headers.authorization ?? ''))?.[1] || '';
    if (cfg.adminToken) {
      const a = Buffer.from(given);
      const b = Buffer.from(cfg.adminToken);
      if (a.length === b.length && timingSafeEqual(a, b)) return;
      throw new HttpError(401, 'unauthorized', 'Admin token required');
    }
    // Dev without ADMIN_TOKEN: localhost only.
    if (cfg.env === 'dev' && isLocal(req)) return;
    throw new HttpError(401, 'unauthorized', 'Admin token required');
  };

  const toolConfig = async () => ({
    toolName: 'UniGame Hub',
    toolUrl: `${cfg.baseUrl}/lti/launch`,
    initiateLoginUrl: `${cfg.baseUrl}/lti/login`,
    redirectionUris: [`${cfg.baseUrl}/lti/launch`],
    deepLinkingUrl: `${cfg.baseUrl}/lti/launch`,
    publicKeysetUrl: `${cfg.baseUrl}/lti/jwks`,
    publicKeyPem: await keys.publicPem(),
    scopes: ['AGS: score + lineitem', 'NRPS (optional)'],
  });

  app.get('/api/v1/admin/setup', async (req) => {
    requireAdmin(req);
    return toolConfig();
  });

  app.get('/admin/setup', async (req, reply) => {
    requireAdmin(req);
    const c = await toolConfig();
    const platforms = await store.find<Platform>(COL.platforms, {}, 50);
    const rows = (pairs: Array<[string, string]>) => pairs.map(([k, v]) => `<tr><th>${esc(k)}</th><td><code>${esc(v)}</code></td></tr>`).join('');
    return reply.header('content-type', 'text/html; charset=utf-8').send(page('UniGame Hub – Cấu hình', `<h1>UniGame Hub · cấu hình LTI 1.3</h1>
<p class="muted">Môi trường: <b>${esc(cfg.env)}</b> · ${esc(cfg.baseUrl)}</p>
<h2>Thông tin khai báo trong Moodle (Site admin → Plugins → External tool → Manage tools → Configure a tool manually)</h2>
<div class="card"><table>${rows([
      ['Tool URL', c.toolUrl], ['LTI version', 'LTI 1.3'], ['Public key type', 'Keyset URL (hoặc RSA key bên dưới)'],
      ['Public keyset', c.publicKeysetUrl], ['Initiate login URL', c.initiateLoginUrl], ['Redirection URI(s)', c.redirectionUris.join('\n')],
      ['Supports Deep Linking', 'Có'], ['Content Selection URL', c.deepLinkingUrl], ['Default launch container', 'New window'],
      ['Services', 'IMS LTI Assignment and Grade Services: "Use this service for grade sync and column management"; Names and Role Provisioning: "Use this service"'],
      ['Privacy', 'Share launcher\'s name: Always · Share email: Always · Accept grades: Always'],
    ])}</table><h2>Public key (RSA)</h2><pre>${esc(c.publicKeyPem)}</pre></div>
<h2>Nền tảng LMS đã đăng ký</h2><div class="card"><table><tr><th>Tên</th><th>Issuer</th><th>Client ID</th><th>Deployment</th><th>Tenant</th></tr>
${platforms.map((p) => `<tr><td>${esc(p.name)}</td><td>${esc(p.issuer)}</td><td><code>${esc(p.clientId)}</code></td><td>${esc(p.deploymentIds.join(', '))}</td><td>${esc(p.tenantId)}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">Chưa có</td></tr>'}
</table></div>
<h2>Game</h2><div class="card"><table><tr><th>ID</th><th>Tên</th><th>Trạng thái</th><th>Adapter URL</th></tr>
${catalog.list().map((g) => `<tr><td><code>${esc(g.id)}</code></td><td>${esc(g.name)}${g.alias ? ` <span class="tag">${esc(g.alias)}</span>` : ''}</td><td>${g.enabled ? '<span class="ok">bật</span>' : '<span class="muted">chưa tích hợp</span>'}</td><td><code>${esc(g.launchUrl)}</code></td></tr>`).join('')}
</table></div>`));
  });

  app.post('/api/v1/admin/tenants', async (req) => {
    requireAdmin(req);
    const t = TenantInput.parse(req.body);
    await store.set<Tenant>(COL.tenants, t.id, t);
    await audit(deps, t.id, 'tenant_upsert', { allowedGames: t.allowedGames });
    return t;
  });

  app.get('/api/v1/admin/tenants', async (req) => {
    requireAdmin(req);
    return store.find<Tenant>(COL.tenants, {}, 200);
  });

  app.post('/api/v1/admin/platforms', async (req) => {
    requireAdmin(req);
    const input = PlatformInput.parse(req.body);
    if (!(await store.get<Tenant>(COL.tenants, input.tenantId))) throw new HttpError(400, 'unknown_tenant', 'Create the tenant first');
    const p = await upsertPlatform(store, input);
    await audit(deps, p.tenantId, 'platform_upsert', { platformId: p.id, issuer: p.issuer, clientId: p.clientId });
    return p;
  });

  app.get('/api/v1/admin/platforms', async (req) => {
    requireAdmin(req);
    return store.find<Platform>(COL.platforms, {}, 200);
  });

  app.get('/api/v1/admin/jobs', async (req) => {
    requireAdmin(req);
    const status = (req.query as Record<string, string>).status;
    return store.find<SyncJob>(COL.jobs, status ? { status } : {}, 200);
  });

  app.post('/api/v1/admin/jobs/:id/retry', async (req) => {
    requireAdmin(req);
    const id = (req.params as { id: string }).id;
    const job = await store.update<SyncJob>(COL.jobs, id, (cur) =>
      cur && (cur.status === 'dead' || cur.status === 'pending') ? { ...cur, status: 'pending', attempts: 0, nextRunAt: Date.now() } : null,
    );
    if (!job) throw new HttpError(404, 'not_found', 'Job not found');
    sync.kick();
    return job;
  });

  /** For Cloud Scheduler on Cloud Run (instances may be idle between requests). */
  app.post('/api/v1/internal/sync', async (req) => {
    requireAdmin(req);
    return { processed: await sync.runOnce() };
  });

  app.get('/api/v1/admin/games/:id/dev-secret', async (req) => {
    requireAdmin(req);
    if (cfg.env !== 'dev') throw new HttpError(404, 'not_found', 'Not available');
    const id = (req.params as { id: string }).id;
    if (!catalog.get(id)) throw new HttpError(404, 'not_found', 'Unknown game');
    return { gameId: id, secret: deps.secrets.get(id) };
  });
}
