import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Doc, Store } from './types.ts';

/** In-memory store, optionally persisted to <dir>/store.json. Single process only (dev/tests). */
export class FileStore implements Store {
  private data = new Map<string, Map<string, Doc>>();
  private file?: string;
  private timer?: NodeJS.Timeout;

  constructor(dir?: string) {
    if (!dir) return;
    mkdirSync(dir, { recursive: true });
    this.file = join(dir, 'store.json');
    if (existsSync(this.file)) {
      const raw = JSON.parse(readFileSync(this.file, 'utf8')) as Record<string, Record<string, Doc>>;
      for (const [c, docs] of Object.entries(raw)) this.data.set(c, new Map(Object.entries(docs)));
    }
  }

  private col(c: string): Map<string, Doc> {
    let m = this.data.get(c);
    if (!m) {
      m = new Map();
      this.data.set(c, m);
    }
    return m;
  }

  private persist(): void {
    if (!this.file) return;
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.flush(), 50);
    this.timer.unref?.();
  }

  flush(): void {
    if (!this.file) return;
    const obj: Record<string, Record<string, Doc>> = {};
    for (const [c, m] of this.data) obj[c] = Object.fromEntries(m);
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, JSON.stringify(obj));
    renameSync(tmp, this.file);
  }

  async get<T extends Doc>(c: string, id: string): Promise<T | null> {
    const v = this.col(c).get(id);
    return v ? (structuredClone(v) as T) : null;
  }

  async set<T extends Doc>(c: string, id: string, doc: T): Promise<void> {
    this.col(c).set(id, structuredClone(doc));
    this.persist();
  }

  async create<T extends Doc>(c: string, id: string, doc: T): Promise<boolean> {
    const m = this.col(c);
    if (m.has(id)) return false;
    m.set(id, structuredClone(doc));
    this.persist();
    return true;
  }

  async delete(c: string, id: string): Promise<void> {
    this.col(c).delete(id);
    this.persist();
  }

  async take<T extends Doc>(c: string, id: string): Promise<T | null> {
    const m = this.col(c);
    const v = m.get(id);
    if (v === undefined) return null;
    m.delete(id);
    this.persist();
    return v as T;
  }

  async update<T extends Doc>(c: string, id: string, fn: (cur: T | null) => T | null): Promise<T | null> {
    const m = this.col(c);
    const cur = m.has(id) ? (structuredClone(m.get(id)) as T) : null;
    const next = fn(cur);
    if (next === null) return cur;
    m.set(id, structuredClone(next));
    this.persist();
    return next;
  }

  async find<T extends Doc>(c: string, where: Record<string, unknown>, limit = 100): Promise<Array<T & { id: string }>> {
    const out: Array<T & { id: string }> = [];
    for (const [id, d] of this.col(c)) {
      if (Object.entries(where).every(([k, v]) => d[k] === v)) {
        out.push({ ...(structuredClone(d) as T), id });
        if (out.length >= limit) break;
      }
    }
    return out;
  }
}
