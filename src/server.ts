import { buildApp } from './app.ts';
import { GameSecrets, loadCatalog } from './catalog.ts';
import { loadConfig } from './config.ts';
import { loadKeyRing } from './keys.ts';
import { remoteJwksResolver } from './lti/platforms.ts';
import { FileStore } from './store/file.ts';
import { createFirestoreStore } from './store/firestore.ts';
import type { Store } from './store/types.ts';

const cfg = loadConfig();
const fileStore = cfg.store === 'file' ? new FileStore(cfg.dataDir) : undefined;
const store: Store = fileStore ?? (await createFirestoreStore(cfg.firestoreProject, cfg.firestoreDatabase));

const { app, sync } = await buildApp(
  {
    cfg,
    store,
    keys: await loadKeyRing(cfg),
    catalog: loadCatalog(cfg),
    secrets: new GameSecrets(cfg),
    platformJwks: remoteJwksResolver(),
    fetch: globalThis.fetch,
  },
  { logger: true },
);

sync.start();
await app.listen({ port: cfg.port, host: cfg.env === 'dev' ? '127.0.0.1' : '0.0.0.0' });
app.log.info(`UniGame Hub (${cfg.env}) listening on ${cfg.baseUrl}`);

const shutdown = async () => {
  sync.stop();
  await app.close();
  fileStore?.flush();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
