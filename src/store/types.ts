/**
 * Minimal document store used by the Hub. Two implementations:
 * - FileStore (local dev / tests, single process)
 * - Firestore (staging / prod)
 * Every business document carries a tenantId; callers must check it.
 */
export type Doc = Record<string, unknown>;

export interface Store {
  get<T extends Doc>(col: string, id: string): Promise<T | null>;
  set<T extends Doc>(col: string, id: string, doc: T): Promise<void>;
  /** Atomic create. Returns false when the id already exists. */
  create<T extends Doc>(col: string, id: string, doc: T): Promise<boolean>;
  delete(col: string, id: string): Promise<void>;
  /** Atomic read-and-delete (single-use tokens such as OIDC state). */
  take<T extends Doc>(col: string, id: string): Promise<T | null>;
  /** Transactional read-modify-write. Return null from fn to leave the doc unchanged. */
  update<T extends Doc>(col: string, id: string, fn: (cur: T | null) => T | null): Promise<T | null>;
  /** Equality query. */
  find<T extends Doc>(col: string, where: Record<string, unknown>, limit?: number): Promise<Array<T & { id: string }>>;
  /** Newest documents first, ordered by a string/number field (single-field index only). */
  recent<T extends Doc>(col: string, orderField: string, limit?: number): Promise<Array<T & { id: string }>>;
}

export const COL = {
  tenants: 'tenants',
  platforms: 'lti_platforms',
  states: 'lti_states',
  nonces: 'lti_nonces',
  users: 'lti_user_mappings',
  launches: 'launches',
  gradeTargets: 'grade_targets',
  dlSessions: 'dl_sessions',
  resultJtis: 'result_jtis',
  gradeRecords: 'grade_records',
  jobs: 'grade_sync_jobs',
  audit: 'audit_logs',
  demoTickets: 'demo_used_tickets',
  demoSessions: 'demo_sessions',
  adminSessions: 'admin_sessions',
} as const;
