import { audit, type Deps } from './deps.ts';
import { AgsClient } from './lti/ags.ts';
import type { Platform } from './lti/platforms.ts';
import type { GradeTarget } from './lti/routes.ts';
import type { SyncJob } from './results.ts';
import { COL } from './store/types.ts';

const MAX_ATTEMPTS = 8;
const backoffMs = (attempt: number): number => Math.min(10_000 * 2 ** (attempt - 1), 3_600_000);

/**
 * Grade sync worker: sends queued scores to the LMS through LTI AGS.
 * Dev: in-process interval. Cloud Run: also triggered after each result (kick) and by
 * Cloud Scheduler hitting POST /api/v1/internal/sync (see admin.ts).
 */
export class GradeSync {
  private deps: Deps;
  private ags: AgsClient;
  private timer?: NodeJS.Timeout;
  private running: Promise<number> | null = null;

  constructor(deps: Deps) {
    this.deps = deps;
    this.ags = new AgsClient(deps.keys, deps.fetch);
  }

  start(intervalMs = 5000): void {
    this.timer = setInterval(() => void this.runOnce(), intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    clearInterval(this.timer);
  }

  kick(): void {
    setImmediate(() => void this.runOnce());
  }

  /** Processes due jobs; returns how many were handled. Never runs twice concurrently. */
  async runOnce(): Promise<number> {
    if (this.running) return this.running;
    this.running = (async () => {
      const due = (await this.deps.store.find<SyncJob>(COL.jobs, { status: 'pending' }, 200))
        .filter((j) => j.nextRunAt <= Date.now())
        .sort((a, b) => Date.parse(a.occurredAt) - Date.parse(b.occurredAt));
      for (const job of due) await this.process(job);
      return due.length;
    })().finally(() => {
      this.running = null;
    });
    return this.running;
  }

  private async process(job: SyncJob & { id: string }): Promise<void> {
    const { store } = this.deps;
    const gt = await store.get<GradeTarget>(COL.gradeTargets, job.gradeTarget);
    const platform = gt ? await store.get<Platform>(COL.platforms, gt.platformId) : null;
    if (!gt || !platform) {
      await store.set(COL.jobs, job.id, { ...job, status: 'dead', lastError: 'grade target or platform missing' });
      return;
    }
    // Never let an older score overwrite a newer one that was already delivered.
    if (gt.lastSentOccurredAt && Date.parse(job.occurredAt) < Date.parse(gt.lastSentOccurredAt)) {
      await store.set(COL.jobs, job.id, { ...job, status: 'superseded' });
      return;
    }
    try {
      await this.ags.postScore(platform, gt.lineitem, {
        userId: gt.userSub,
        scoreGiven: job.payload.scoreGiven,
        scoreMaximum: job.payload.scoreMaximum,
        activityProgress: job.payload.activityProgress,
        gradingProgress: job.payload.gradingProgress,
        timestamp: job.occurredAt,
        ...(job.payload.comment ? { comment: job.payload.comment } : {}),
      });
      const normalized = job.payload.scoreGiven / job.payload.scoreMaximum;
      await store.update<GradeTarget>(COL.gradeTargets, job.gradeTarget, (cur) =>
        cur
          ? {
              ...cur,
              lastSentOccurredAt:
                cur.lastSentOccurredAt && Date.parse(cur.lastSentOccurredAt) > Date.parse(job.occurredAt) ? cur.lastSentOccurredAt : job.occurredAt,
              bestNormalized: Math.max(cur.bestNormalized ?? 0, normalized),
            }
          : null,
      );
      await store.set(COL.jobs, job.id, { ...job, status: 'done', attempts: job.attempts + 1, lastError: null, doneAt: new Date().toISOString() });
      await audit(this.deps, job.tenantId, 'grade_sent', { jobId: job.id, gradeTarget: job.gradeTarget });
    } catch (e) {
      const attempts = job.attempts + 1;
      const dead = attempts >= MAX_ATTEMPTS;
      await store.set(COL.jobs, job.id, {
        ...job,
        attempts,
        status: dead ? 'dead' : 'pending',
        nextRunAt: Date.now() + backoffMs(attempts),
        lastError: (e as Error).message.slice(0, 500),
      });
      await audit(this.deps, job.tenantId, dead ? 'grade_dead' : 'grade_retry', { jobId: job.id, error: (e as Error).message.slice(0, 200) });
    }
  }
}
