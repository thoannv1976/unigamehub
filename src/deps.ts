import type { Catalog, GameSecrets } from './catalog.ts';
import type { Config } from './config.ts';
import type { KeyRing } from './keys.ts';
import type { JwksResolver } from './lti/platforms.ts';
import { COL, type Store } from './store/types.ts';
import { rid } from './util.ts';

/** Everything the routes need. Built once in server.ts (or in tests). */
export interface Deps {
  cfg: Config;
  store: Store;
  keys: KeyRing;
  catalog: Catalog;
  secrets: GameSecrets;
  platformJwks: JwksResolver;
  fetch: typeof fetch;
}

export async function audit(
  deps: Pick<Deps, 'store'>,
  tenantId: string | null,
  action: string,
  data: Record<string, unknown> = {},
): Promise<void> {
  const at = new Date().toISOString();
  await deps.store.set(COL.audit, `${at.replace(/[:.]/g, '')}-${rid(4)}`, { at, tenantId, action, ...data });
}
