import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { audit, type Deps } from './deps.ts';
import { PlatformInput, upsertPlatform, type Platform, type Tenant } from './lti/platforms.ts';
import type { SyncJob } from './results.ts';
import { COL } from './store/types.ts';
import type { GradeSync } from './sync.ts';
import { HttpError } from './util.ts';

export const TenantInput = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9_-]{1,63}$/),
  name: z.string().min(1).max(200),
  allowedGames: z.array(z.string().min(1)).default(['*']),
  status: z.enum(['active', 'suspended']).default('active'),
});

export const isLocal = (req: FastifyRequest) => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.ip);

/** Values an LMS administrator enters when registering the Hub (LTI 1.3). */
export async function toolConfig(deps: Pick<Deps, 'cfg' | 'keys'>) {
  const { cfg, keys } = deps;
  return {
    toolName: 'UniGame Hub',
    toolUrl: `${cfg.baseUrl}/lti/launch`,
    initiateLoginUrl: `${cfg.baseUrl}/lti/login`,
    redirectionUris: [`${cfg.baseUrl}/lti/launch`],
    deepLinkingUrl: `${cfg.baseUrl}/lti/launch`,
    publicKeysetUrl: `${cfg.baseUrl}/lti/jwks`,
    publicKeyPem: await keys.publicPem(),
    scopes: ['AGS: score + lineitem', 'NRPS (optional)'],
  };
}

export function registerAdminRoutes(app: FastifyInstance, deps: Deps, sync: GradeSync): void {
  const { cfg, store, catalog } = deps;

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


  app.get('/api/v1/admin/setup', async (req) => {
    requireAdmin(req);
    return toolConfig(deps);
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
