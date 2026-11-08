import { resolve } from 'node:path';

export type HubEnv = 'dev' | 'staging' | 'prod';

export interface Config {
  env: HubEnv;
  port: number;
  /** Public base URL (browser + LMS facing), no trailing slash. */
  baseUrl: string;
  /** URL the Hub uses to call itself (demo game). */
  selfUrl: string;
  store: 'file' | 'firestore';
  dataDir: string;
  firestoreProject?: string;
  firestoreDatabase?: string;
  adminToken?: string;
  gamesFile: string;
  signingKeysJson?: string;
  /** Deliver grades inside the results request (Cloud Run). Default: on outside dev. */
  syncInline: boolean;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const hubEnv = (env.HUB_ENV ?? 'dev') as HubEnv;
  if (!['dev', 'staging', 'prod'].includes(hubEnv)) throw new Error(`Invalid HUB_ENV: ${hubEnv}`);
  const port = Number(env.PORT ?? 8787);
  const baseUrl = (env.HUB_BASE_URL ?? `http://localhost:${port}`).replace(/\/+$/, '');
  const cfg: Config = {
    env: hubEnv,
    port,
    baseUrl,
    selfUrl: (env.HUB_SELF_URL ?? `http://127.0.0.1:${port}`).replace(/\/+$/, ''),
    store: (env.HUB_STORE ?? (hubEnv === 'dev' ? 'file' : 'firestore')) as Config['store'],
    dataDir: resolve(env.DATA_DIR ?? '.data'),
    firestoreProject: env.FIRESTORE_PROJECT,
    firestoreDatabase: env.FIRESTORE_DATABASE,
    adminToken: env.ADMIN_TOKEN,
    gamesFile: resolve(env.GAMES_FILE ?? 'config/games.json'),
    signingKeysJson: env.HUB_SIGNING_KEYS,
    syncInline: (env.HUB_SYNC_INLINE ?? (hubEnv === 'dev' ? '0' : '1')) === '1',
  };
  if (hubEnv !== 'dev') {
    if (!cfg.adminToken || cfg.adminToken.length < 24) throw new Error('ADMIN_TOKEN (>=24 chars) is required outside dev');
    if (!cfg.signingKeysJson) throw new Error('HUB_SIGNING_KEYS is required outside dev (use Secret Manager)');
    if (!cfg.baseUrl.startsWith('https://')) throw new Error('HUB_BASE_URL must be https outside dev');
  }
  return cfg;
}
