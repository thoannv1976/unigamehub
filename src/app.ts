import formbody from '@fastify/formbody';
import Fastify, { type FastifyInstance } from 'fastify';
import { ZodError } from 'zod';
import { registerAdminRoutes } from './admin.ts';
import { registerDemoGame } from './demo.ts';
import type { Deps } from './deps.ts';
import { registerLtiRoutes } from './lti/routes.ts';
import { registerResultRoutes } from './results.ts';
import { GradeSync } from './sync.ts';
import { HttpError } from './util.ts';
import { errorPage } from './views.ts';

export interface HubApp {
  app: FastifyInstance;
  sync: GradeSync;
}

export async function buildApp(deps: Deps, opts: { logger?: boolean } = {}): Promise<HubApp> {
  const app = Fastify({
    logger: opts.logger ? { level: deps.cfg.env === 'dev' ? 'info' : 'warn', redact: ['req.headers.authorization', 'req.headers["x-admin-token"]', 'req.headers.cookie'] } : false,
    trustProxy: deps.cfg.env !== 'dev',
    bodyLimit: 256 * 1024,
  });
  await app.register(formbody);

  app.addHook('onSend', async (_req, reply) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('referrer-policy', 'no-referrer');
  });

  app.setErrorHandler((err, req, reply) => {
    const status = err instanceof HttpError ? err.status : err instanceof ZodError ? 400 : (err as { statusCode?: number }).statusCode ?? 500;
    const code = err instanceof HttpError ? err.code : err instanceof ZodError ? 'validation' : 'internal';
    const message = err instanceof HttpError ? err.message : err instanceof ZodError ? err.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ') : status < 500 ? (err as Error).message : 'Lỗi hệ thống';
    if (status >= 500) req.log.error(err);
    const wantsHtml = req.url.startsWith('/lti/') && !req.url.startsWith('/lti/jwks');
    if (wantsHtml) {
      return reply.status(status).header('content-type', 'text/html; charset=utf-8').send(errorPage('Không mở được hoạt động', message));
    }
    return reply.status(status).send({ error: code, message });
  });

  const sync = new GradeSync(deps);
  // Cloud Run reserves /healthz, so /health is the public probe.
  app.get('/health', async () => ({ ok: true, env: deps.cfg.env }));
  app.get('/healthz', async () => ({ ok: true, env: deps.cfg.env }));
  app.get('/', async (_req, reply) => reply.redirect('/admin/setup'));
  registerLtiRoutes(app, deps);
  registerResultRoutes(app, deps, sync);
  registerAdminRoutes(app, deps, sync);
  if (deps.catalog.get('demo')?.enabled) registerDemoGame(app, deps);
  return { app, sync };
}
