import type { FastifyInstance } from 'fastify';
import { decodeJwt, jwtVerify } from 'jose';
import { z } from 'zod';
import type { GameDef } from './catalog.ts';
import { audit, type Deps } from './deps.ts';
import { AgsClient, type NrpsMember } from './lti/ags.ts';
import type { Platform } from './lti/platforms.ts';
import type { GradeTarget, LinkTarget } from './lti/routes.ts';
import { COL } from './store/types.ts';
import type { GradeSync } from './sync.ts';
import { hid, HttpError, isRecord } from './util.ts';

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

const BulkClaim = z
  .object({
    link_target: z.string().min(4).max(64),
    /** Idempotency key of this batch (e.g. the lecturer's score snapshot id). */
    batch_id: z.string().min(1).max(200),
    max_score: z.number().finite().positive(),
    occurred_at: z.string().datetime({ offset: true }),
    rows: z
      .array(
        z
          .object({
            hub_user_id: z.string().max(64).optional(),
            username: z.string().max(200).optional(),
            email: z.string().max(320).optional(),
            score: z.number().finite().min(0),
            comment: z.string().max(1000).optional(),
          })
          .refine((r) => r.hub_user_id || r.username || r.email, { message: 'hub_user_id, username or email is required' }),
      )
      .min(1)
      .max(2000),
  })
  .refine((b) => b.rows.every((r) => r.score <= b.max_score), { message: 'score > max_score' });

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

type Outcome = 'queued' | 'duplicate' | 'stale_ignored' | 'not_better';

interface ResultData {
  attemptId: string;
  score: number;
  maxScore: number;
  occurredAt: string;
  activityProgress: string;
  gradingProgress: string;
  comment?: string;
}

/** Stores a result for one grade target and queues delivery (dedupe, stale protection, "best" policy). */
async function queueResult(deps: Deps, game: GameDef, gtId: string, gt: GradeTarget, r: ResultData): Promise<{ status: Outcome; recordId: string; jobId?: string }> {
  const { store } = deps;
  const recordId = hid('gr', game.id, gt.hubUserId, gtId, r.attemptId);
  const normalized = r.score / r.maxScore;
  const now = new Date().toISOString();
  let outcome = 'new' as 'new' | 'duplicate' | 'stale';
  const record = await store.update<GradeRecord>(COL.gradeRecords, recordId, (cur) => {
    outcome = 'new'; // reset: Firestore may re-run this function on contention
    if (cur && cur.score === r.score && cur.maxScore === r.maxScore && cur.occurredAt === r.occurredAt && cur.gradingProgress === r.gradingProgress) {
      outcome = 'duplicate';
      return null;
    }
    if (cur && Date.parse(cur.occurredAt) > Date.parse(r.occurredAt)) {
      outcome = 'stale';
      return null;
    }
    return {
      tenantId: gt.tenantId, gameId: game.id, gradeTarget: gtId, attemptId: r.attemptId,
      score: r.score, maxScore: r.maxScore, normalized, occurredAt: r.occurredAt,
      activityProgress: r.activityProgress, gradingProgress: r.gradingProgress, comment: r.comment,
      version: (cur?.version ?? 0) + 1, updatedAt: now,
    };
  });
  if (outcome === 'duplicate') return { status: 'duplicate', recordId };
  if (outcome === 'stale') return { status: 'stale_ignored', recordId };

  // Grade policy "best": only push when this attempt beats the best one already sent.
  if (gt.policy === 'best' && gt.bestNormalized !== null && normalized <= gt.bestNormalized) {
    await audit(deps, gt.tenantId, 'result_not_better', { recordId, normalized, best: gt.bestNormalized });
    return { status: 'not_better', recordId };
  }

  const jobId = hid('job', recordId, String(record!.version));
  await store.create<SyncJob>(COL.jobs, jobId, {
    tenantId: gt.tenantId,
    status: 'pending',
    gradeTarget: gtId,
    recordId,
    attempts: 0,
    nextRunAt: Date.now(),
    lastError: null,
    occurredAt: r.occurredAt,
    payload: {
      scoreGiven: r.score,
      scoreMaximum: r.maxScore,
      activityProgress: r.activityProgress,
      gradingProgress: r.gradingProgress,
      ...(r.comment ? { comment: r.comment } : {}),
    },
    createdAt: now,
  });
  return { status: 'queued', recordId, jobId };
}

/**
 * POST /api/v1/results       { result_token }   one learner (grade_target from the launch)
 * POST /api/v1/results/bulk  { result_token }   a whole class (link_target from a launch of the activity)
 * result_token: HS256 JWT signed by the game backend with its shared secret (see sdk/).
 */
export function registerResultRoutes(app: FastifyInstance, deps: Deps, sync: GradeSync): void {
  const { store, catalog, secrets, cfg } = deps;
  const ags = new AgsClient(deps.keys, deps.fetch);

  /** Verifies a game-signed token (issuer = game id, audience = Hub) and burns its jti. */
  async function verifyGameToken(body: unknown): Promise<{ game: GameDef; payload: Record<string, unknown> }> {
    const token = isRecord(body) ? body.result_token : undefined;
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
    return { game, payload: payload as Record<string, unknown> };
  }

  const deliver = async () => {
    if (cfg.syncInline) {
      // Cloud Run throttles CPU after the response, so try delivery now (bounded); retries come from the scheduler.
      await Promise.race([sync.runOnce(), new Promise((r) => setTimeout(r, 8000))]);
    } else {
      sync.kick();
    }
  };

  app.post('/api/v1/results', async (req, reply) => {
    const { game, payload } = await verifyGameToken(req.body);
    const parsed = ResultClaim.safeParse(payload.result);
    if (!parsed.success) throw new HttpError(400, 'bad_result', parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '));
    const r = parsed.data;

    const gt = await store.get<GradeTarget>(COL.gradeTargets, r.grade_target);
    if (!gt) throw new HttpError(404, 'unknown_grade_target', 'Unknown grade_target');
    // A game may only grade launches that were made for it.
    if (gt.gameId !== game.id) throw new HttpError(403, 'wrong_game', 'grade_target belongs to another game');

    const res = await queueResult(deps, game, r.grade_target, gt, {
      attemptId: r.attempt_id, score: r.score, maxScore: r.max_score, occurredAt: r.occurred_at,
      activityProgress: r.activity_progress, gradingProgress: r.grading_progress, comment: r.comment,
    });
    if (res.status !== 'queued') return reply.status(200).send({ status: res.status, record_id: res.recordId });
    await audit(deps, gt.tenantId, 'result_received', { gameId: game.id, recordId: res.recordId, jobId: res.jobId, score: r.score, max: r.max_score });
    await deliver();
    return reply.status(202).send({ status: 'queued', job_id: res.jobId, record_id: res.recordId });
  });

  app.post('/api/v1/results/bulk', async (req, reply) => {
    const { game, payload } = await verifyGameToken(req.body);
    const parsed = BulkClaim.safeParse(payload.bulk);
    if (!parsed.success) throw new HttpError(400, 'bad_bulk', parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '));
    const b = parsed.data;

    const lt = await store.get<LinkTarget>(COL.linkTargets, b.link_target);
    if (!lt) throw new HttpError(404, 'unknown_link_target', 'Unknown link_target');
    if (lt.gameId !== game.id) throw new HttpError(403, 'wrong_game', 'link_target belongs to another game');
    const platform = await store.get<Platform>(COL.platforms, lt.platformId);
    if (!platform) throw new HttpError(409, 'platform_missing', 'LMS platform no longer registered');

    // Resolve each row to an LTI user id: Hub user id (launched before) → username → email (course membership).
    const norm = (v?: string | null) => (v ?? '').trim().toLowerCase();
    let members: NrpsMember[] = [];
    if (b.rows.some((r) => r.username || r.email)) {
      if (!lt.nrpsUrl) throw new HttpError(409, 'no_nrps', 'The LMS did not provide Names and Role Provisioning for this activity');
      try {
        members = (await ags.members(platform, lt.nrpsUrl)).filter((m) => (m.status ?? 'Active') === 'Active');
      } catch (err) {
        throw new HttpError(502, 'nrps_failed', `Could not read the course membership: ${(err as Error).message}`);
      }
    }
    const index = (key: (m: NrpsMember) => string | undefined) => {
      const map = new Map<string, NrpsMember[]>();
      for (const m of members) {
        const k = norm(key(m));
        if (k) map.set(k, [...(map.get(k) ?? []), m]);
      }
      return map;
    };
    const byUsername = index((m) => m.ext_user_username);
    const byEmail = index((m) => m.email);
    const unique = (list?: NrpsMember[]) => (list && list.length === 1 ? list[0]!.user_id : undefined);

    const now = new Date().toISOString();
    const counts: Record<Outcome, number> = { queued: 0, duplicate: 0, stale_ignored: 0, not_better: 0 };
    const unmatched: Array<{ hub_user_id?: string; username?: string; email?: string }> = [];
    const seen = new Set<string>();
    for (const row of b.rows) {
      let sub: string | undefined;
      if (row.hub_user_id) {
        const u = await store.get<{ sub: string; tenantId: string; issuer: string }>(COL.users, row.hub_user_id);
        if (u && u.tenantId === lt.tenantId && u.issuer === platform.issuer) sub = u.sub;
      }
      if (!sub && row.username) sub = unique(byUsername.get(norm(row.username)));
      if (!sub && row.email) sub = unique(byEmail.get(norm(row.email)));
      if (!sub || seen.has(sub)) {
        unmatched.push({ hub_user_id: row.hub_user_id, username: row.username, email: row.email });
        continue;
      }
      seen.add(sub);
      const userSub = sub;
      const hubUserId = hid('u', lt.tenantId, platform.issuer, userSub);
      const gtId = hid('gt', platform.id, lt.deploymentId, lt.resourceLinkId, userSub);
      const gt = await store.update<GradeTarget>(COL.gradeTargets, gtId, (cur) => ({
        tenantId: lt.tenantId, platformId: platform.id, deploymentId: lt.deploymentId, contextId: lt.contextId,
        resourceLinkId: lt.resourceLinkId, userSub, hubUserId, gameId: game.id, lineitem: lt.lineitem,
        policy: 'latest', lastSentOccurredAt: cur?.lastSentOccurredAt ?? null, bestNormalized: cur?.bestNormalized ?? null,
        createdAt: cur?.createdAt ?? now, updatedAt: now,
      }));
      const res = await queueResult(deps, game, gtId, gt!, {
        attemptId: `batch:${b.batch_id}`, score: row.score, maxScore: b.max_score, occurredAt: b.occurred_at,
        activityProgress: 'Completed', gradingProgress: 'FullyGraded', comment: row.comment,
      });
      counts[res.status] += 1;
    }
    await audit(deps, lt.tenantId, 'bulk_result_received', {
      gameId: game.id, linkTarget: b.link_target, batchId: b.batch_id, rows: b.rows.length, ...counts, unmatched: unmatched.length,
    });
    if (counts.queued) await deliver();
    return reply.status(202).send({ status: 'accepted', matched: b.rows.length - unmatched.length, ...counts, unmatched });
  });
}
