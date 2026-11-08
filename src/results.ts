import type { FastifyInstance } from 'fastify';
import { decodeJwt, jwtVerify } from 'jose';
import { z } from 'zod';
import { audit, type Deps } from './deps.ts';
import type { GradeTarget } from './lti/routes.ts';
import { COL } from './store/types.ts';
import { hid, HttpError, isRecord } from './util.ts';
import type { GradeSync } from './sync.ts';

const ResultClaim = z
  .object({
    grade_target: z.string().min(4).max(64),
    attempt_id: z.string().min(1).max(200),
    score: z.number().finite().min(0),
    max_score: z.number().finite().positive(),
    occurred_at: z.string().datetime({ offset: true }),
    activity_progress: z.enum(['Initialized', 'Started', 'InProgress', 'Submitted', 'Completed']).default('Completed'),
    grading_progress: z.enum(['FullyGraded', 'Pending', 'PendingManual', 'Failed', 'NotReady']).default('FullyGraded'),
    comment: z.string().max(1000).optional(),
  })
  .refine((r) => r.score <= r.max_score, { message: 'score > max_score' });

export interface GradeRecord {
  [k: string]: unknown;
  tenantId: string;
  gameId: string;
  gradeTarget: string;
  attemptId: string;
  score: number;
  maxScore: number;
  normalized: number;
  occurredAt: string;
  activityProgress: string;
  gradingProgress: string;
  comment?: string;
  version: number;
  updatedAt: string;
}

export interface SyncJob {
  [k: string]: unknown;
  tenantId: string;
  status: 'pending' | 'done' | 'dead' | 'superseded';
  gradeTarget: string;
  recordId: string;
  attempts: number;
  nextRunAt: number;
  lastError: string | null;
  occurredAt: string;
  payload: { scoreGiven: number; scoreMaximum: number; activityProgress: string; gradingProgress: string; comment?: string };
  createdAt: string;
  doneAt?: string;
}

/**
 * POST /api/v1/results  { result_token }
 * result_token: HS256 JWT signed by the game backend with its shared secret (see sdk/).
 */
export function registerResultRoutes(app: FastifyInstance, deps: Deps, sync: GradeSync): void {
  const { store, catalog, secrets, cfg } = deps;

  app.post('/api/v1/results', async (req, reply) => {
    const token = isRecord(req.body) ? req.body.result_token : undefined;
    if (typeof token !== 'string') throw new HttpError(400, 'missing_token', 'result_token is required');

    let gameId: string;
    try {
      gameId = String(decodeJwt(token).iss ?? '');
    } catch {
      throw new HttpError(401, 'bad_token', 'Malformed result_token');
    }
    const game = catalog.get(gameId);
    const secret = game ? secrets.get(game.id) : undefined;
    if (!game || !secret) throw new HttpError(401, 'unknown_game', 'Unknown game or no secret configured');

    let payload;
    try {
      ({ payload } = await jwtVerify(token, new TextEncoder().encode(secret), {
        issuer: game.id,
        audience: cfg.baseUrl,
        algorithms: ['HS256'],
        maxTokenAge: '10m',
      }));
    } catch {
      throw new HttpError(401, 'bad_signature', 'Invalid result_token signature or claims');
    }
    if (!payload.jti) throw new HttpError(400, 'no_jti', 'jti is required');
    if (!(await store.create(COL.resultJtis, hid('rj', game.id, payload.jti), { exp: payload.exp ?? 0 }))) {
      throw new HttpError(409, 'replay', 'result_token already used');
    }
    const parsed = ResultClaim.safeParse(payload.result);
    if (!parsed.success) throw new HttpError(400, 'bad_result', parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '));
    const r = parsed.data;

    const gt = await store.get<GradeTarget>(COL.gradeTargets, r.grade_target);
    if (!gt) throw new HttpError(404, 'unknown_grade_target', 'Unknown grade_target');
    // A game may only grade launches that were made for it.
    if (gt.gameId !== game.id) throw new HttpError(403, 'wrong_game', 'grade_target belongs to another game');

    const recordId = hid('gr', game.id, gt.hubUserId, r.grade_target, r.attempt_id);
    const normalized = r.score / r.max_score;
    const now = new Date().toISOString();
    let outcome = 'new' as 'new' | 'duplicate' | 'stale';
    const record = await store.update<GradeRecord>(COL.gradeRecords, recordId, (cur) => {
      outcome = 'new'; // reset: Firestore may re-run this function on contention
      if (cur && cur.score === r.score && cur.maxScore === r.max_score && cur.occurredAt === r.occurred_at && cur.gradingProgress === r.grading_progress) {
        outcome = 'duplicate';
        return null;
      }
      if (cur && Date.parse(cur.occurredAt) > Date.parse(r.occurred_at)) {
        outcome = 'stale';
        return null;
      }
      return {
        tenantId: gt.tenantId, gameId: game.id, gradeTarget: r.grade_target, attemptId: r.attempt_id,
        score: r.score, maxScore: r.max_score, normalized, occurredAt: r.occurred_at,
        activityProgress: r.activity_progress, gradingProgress: r.grading_progress, comment: r.comment,
        version: (cur?.version ?? 0) + 1, updatedAt: now,
      };
    });
    if (outcome === 'duplicate') return reply.status(200).send({ status: 'duplicate', record_id: recordId });
    if (outcome === 'stale') return reply.status(200).send({ status: 'stale_ignored', record_id: recordId });

    // Grade policy "best": only push when this attempt beats the best one already sent.
    if (gt.policy === 'best' && gt.bestNormalized !== null && normalized <= gt.bestNormalized) {
      await audit(deps, gt.tenantId, 'result_not_better', { recordId, normalized, best: gt.bestNormalized });
      return reply.status(200).send({ status: 'not_better', record_id: recordId });
    }

    const jobId = hid('job', recordId, String(record!.version));
    await store.create<SyncJob>(COL.jobs, jobId, {
      tenantId: gt.tenantId,
      status: 'pending',
      gradeTarget: r.grade_target,
      recordId,
      attempts: 0,
      nextRunAt: Date.now(),
      lastError: null,
      occurredAt: r.occurred_at,
      payload: {
        scoreGiven: r.score,
        scoreMaximum: r.max_score,
        activityProgress: r.activity_progress,
        gradingProgress: r.grading_progress,
        ...(r.comment ? { comment: r.comment } : {}),
      },
      createdAt: now,
    });
    await audit(deps, gt.tenantId, 'result_received', { gameId: game.id, recordId, jobId, score: r.score, max: r.max_score });
    if (cfg.syncInline) {
      // Cloud Run throttles CPU after the response, so try delivery now (bounded); retries come from the scheduler.
      await Promise.race([sync.runOnce(), new Promise((r) => setTimeout(r, 8000))]);
    } else {
      sync.kick();
    }
    return reply.status(202).send({ status: 'queued', job_id: jobId, record_id: recordId });
  });
}
