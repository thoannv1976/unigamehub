import type { Doc, Store } from './types.ts';

/** Firestore-backed store for staging/prod (uses Application Default Credentials on Cloud Run). */
export async function createFirestoreStore(projectId?: string, databaseId?: string): Promise<Store> {
  const { initializeApp, getApps, applicationDefault } = await import('firebase-admin/app');
  const { getFirestore } = await import('firebase-admin/firestore');
  const app = getApps()[0] ?? initializeApp({ credential: applicationDefault(), projectId });
  const db = databaseId ? getFirestore(app, databaseId) : getFirestore(app);
  db.settings({ ignoreUndefinedProperties: true });
  const ref = (c: string, id: string) => db.collection(c).doc(id);

  return {
    async get<T extends Doc>(c: string, id: string) {
      const s = await ref(c, id).get();
      return s.exists ? (s.data() as T) : null;
    },
    async set<T extends Doc>(c: string, id: string, doc: T) {
      await ref(c, id).set(doc);
    },
    async create<T extends Doc>(c: string, id: string, doc: T) {
      try {
        await ref(c, id).create(doc);
        return true;
      } catch (e) {
        if ((e as { code?: number }).code === 6) return false; // ALREADY_EXISTS
        throw e;
      }
    },
    async delete(c: string, id: string) {
      await ref(c, id).delete();
    },
    async take<T extends Doc>(c: string, id: string) {
      return db.runTransaction(async (tx) => {
        const s = await tx.get(ref(c, id));
        if (!s.exists) return null;
        tx.delete(ref(c, id));
        return s.data() as T;
      });
    },
    async update<T extends Doc>(c: string, id: string, fn: (cur: T | null) => T | null) {
      return db.runTransaction(async (tx) => {
        const s = await tx.get(ref(c, id));
        const cur = s.exists ? (s.data() as T) : null;
        const next = fn(cur);
        if (next === null) return cur;
        tx.set(ref(c, id), next);
        return next;
      });
    },
    async find<T extends Doc>(c: string, where: Record<string, unknown>, limit = 100) {
      let q: FirebaseFirestore.Query = db.collection(c);
      for (const [k, v] of Object.entries(where)) q = q.where(k, '==', v);
      const s = await q.limit(limit).get();
      return s.docs.map((d) => ({ ...(d.data() as T), id: d.id }));
    },
  };
}
