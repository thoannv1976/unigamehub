/**
 * UniGame Hub — Game SDK (server side).
 *
 * Used by a game's BACKEND (never the browser) to:
 *  1. verify the launch ticket the Hub sends to the game (`#ticket=...` on the adapter page),
 *  2. sign and submit results that the Hub forwards to the LMS gradebook.
 *
 * Depends only on `jose`. Copy this folder into a game repo or install it as a package.
 */
import { createRemoteJWKSet, decodeJwt, jwtVerify, SignJWT, type JWTVerifyGetKey } from 'jose';

export const TICKET_TYP = 'unigamehub-launch+jwt';

export interface LaunchContext {
  ticketId: string;
  /** Stable pseudonymous id of this LMS user inside the Hub (tenant + issuer + LTI sub). */
  hubUserId: string;
  tenantId: string;
  gameId: string;
  platform: { issuer: string; deploymentId: string };
  ltiSub: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  email?: string;
  role: 'instructor' | 'learner';
  context?: { id: string; title?: string; label?: string };
  resourceLink: { id: string; title?: string };
  /** Game-specific activity id chosen by the instructor (mission, case, exam session...). */
  activity?: string;
  /** Present when this activity sends grades to the LMS. Store it with the attempt. */
  gradeTarget?: string;
  launchId: string;
  returnUrl?: string;
  locale?: string;
}

export interface VerifyOptions {
  /** Hub base URL, e.g. https://gamehub-xxxx.a.run.app (ticket issuer). */
  hubUrl: string;
  gameId: string;
  /** Optional key resolver; defaults to the Hub's /lti/jwks. */
  jwks?: JWTVerifyGetKey;
  /**
   * Replay protection: called once per ticket. Return false if the jti was already used.
   * Implement with an atomic create (e.g. Firestore doc.create(jti)).
   */
  markUsed?: (jti: string, expiresAt: Date) => Promise<boolean>;
}

const jwksCache = new Map<string, JWTVerifyGetKey>();

export async function verifyLaunchTicket(ticket: string, opts: VerifyOptions): Promise<LaunchContext> {
  const hubUrl = opts.hubUrl.replace(/\/+$/, '');
  let jwks = opts.jwks ?? jwksCache.get(hubUrl);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${hubUrl}/lti/jwks`));
    jwksCache.set(hubUrl, jwks);
  }
  const { payload, protectedHeader } = await jwtVerify(ticket, jwks, {
    issuer: hubUrl,
    audience: opts.gameId,
    algorithms: ['RS256'],
    typ: TICKET_TYP,
    maxTokenAge: '5m',
  });
  if (protectedHeader.typ !== TICKET_TYP) throw new Error('Wrong token type');
  if (!payload.jti || !payload.sub || !payload.exp) throw new Error('Ticket missing jti/sub/exp');
  if (opts.markUsed && !(await opts.markUsed(payload.jti, new Date(payload.exp * 1000)))) {
    throw new Error('Ticket already used');
  }
  const c = payload.ugh as Omit<LaunchContext, 'ticketId' | 'hubUserId' | 'gameId'>;
  return { ...c, ticketId: payload.jti, hubUserId: payload.sub, gameId: opts.gameId };
}

export interface ResultInput {
  /** From LaunchContext.gradeTarget. */
  gradeTarget: string;
  /** Your attempt/session id. Re-sending the same attempt updates the grade (e.g. teacher re-score). */
  attemptId: string;
  score: number;
  maxScore: number;
  /** When this score was decided. Older scores never overwrite newer ones. Default: now. */
  occurredAt?: string;
  activityProgress?: 'Initialized' | 'Started' | 'InProgress' | 'Submitted' | 'Completed';
  gradingProgress?: 'FullyGraded' | 'Pending' | 'PendingManual' | 'Failed' | 'NotReady';
  comment?: string;
}

export interface SubmitOptions {
  hubUrl: string;
  gameId: string;
  /** Shared secret from the Hub (GAME_SECRET_<ID>). Keep it in Secret Manager. */
  secret: string;
  fetch?: typeof fetch;
}

export async function createResultToken(opts: SubmitOptions, r: ResultInput): Promise<string> {
  const hubUrl = opts.hubUrl.replace(/\/+$/, '');
  return new SignJWT({
    result: {
      grade_target: r.gradeTarget,
      attempt_id: r.attemptId,
      score: r.score,
      max_score: r.maxScore,
      occurred_at: r.occurredAt ?? new Date().toISOString(),
      activity_progress: r.activityProgress ?? 'Completed',
      grading_progress: r.gradingProgress ?? 'FullyGraded',
      ...(r.comment ? { comment: r.comment } : {}),
    },
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'unigamehub-result+jwt' })
    .setIssuer(opts.gameId)
    .setAudience(hubUrl)
    .setIssuedAt()
    .setExpirationTime('5m')
    .setJti(crypto.randomUUID())
    .sign(new TextEncoder().encode(opts.secret));
}

export interface SubmitResponse {
  status: 'queued' | 'duplicate' | 'stale_ignored' | 'not_better';
  job_id?: string;
  record_id?: string;
}

export async function submitResult(opts: SubmitOptions, r: ResultInput): Promise<SubmitResponse> {
  const token = await createResultToken(opts, r);
  const res = await (opts.fetch ?? fetch)(`${opts.hubUrl.replace(/\/+$/, '')}/api/v1/results`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ result_token: token }),
  });
  const body = (await res.json().catch(() => ({}))) as SubmitResponse & { error?: string };
  if (!res.ok) throw new Error(`Hub rejected result (${res.status}): ${body.error ?? 'unknown'}`);
  return body;
}

/** Read the ticket from the adapter page URL fragment (browser helper). */
export function ticketFromLocation(hash: string): string | null {
  const m = /(?:^#|&)ticket=([^&]+)/.exec(hash);
  return m ? decodeURIComponent(m[1]!) : null;
}

export { decodeJwt };
