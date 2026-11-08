import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Config } from './config.ts';
import { rid } from './util.ts';

export interface GameActivity {
  id: string;
  title: string;
}

export interface GameDef {
  id: string;
  name: string;
  /** Name the users know the game by (e.g. vstep1). */
  alias?: string;
  description: string;
  category: string;
  /** Adapter entry page in the game. The launch ticket is appended as #ticket=... */
  launchUrl: string;
  /** Only enabled games are offered to instructors. */
  enabled: boolean;
  /** How grades are produced (shown to instructors). */
  gradeNote?: string;
  defaultMaxScore?: number;
  activities?: GameActivity[];
  repo?: string;
  firebaseProject?: string;
}

export class Catalog {
  private games: Map<string, GameDef>;
  constructor(games: GameDef[]) {
    this.games = new Map(games.map((g) => [g.id, g]));
  }
  get(id: string): GameDef | undefined {
    return this.games.get(id);
  }
  list(): GameDef[] {
    return [...this.games.values()];
  }
  enabledFor(allowed: string[]): GameDef[] {
    return this.list().filter((g) => g.enabled && (allowed.includes('*') || allowed.includes(g.id)));
  }
}

const envKey = (gameId: string): string => gameId.toUpperCase().replace(/[^A-Z0-9]/g, '_');

/**
 * Loads config/games.json. Per environment it can be adjusted without a rebuild:
 *  - GAMES_ENABLED=demo,k26game1  → exactly these games are enabled (others disabled)
 *  - GAME_LAUNCH_URL_<ID>=https://… → overrides the adapter URL (e.g. a preview channel)
 */
export function loadCatalog(cfg: Config, env: NodeJS.ProcessEnv = process.env): Catalog {
  const raw = JSON.parse(readFileSync(cfg.gamesFile, 'utf8')) as { games: GameDef[] };
  const enabledList = env.GAMES_ENABLED?.split(',').map((s) => s.trim()).filter(Boolean);
  const games = raw.games.map((g) => ({
    ...g,
    enabled: enabledList ? enabledList.includes(g.id) : g.enabled,
    launchUrl: (env[`GAME_LAUNCH_URL_${envKey(g.id)}`] ?? g.launchUrl).replace('${HUB_BASE_URL}', cfg.baseUrl),
  }));
  return new Catalog(games);
}

export const secretEnvName = (gameId: string): string => `GAME_SECRET_${gameId.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;

/** Shared secrets the game backends use to sign result tokens. */
export class GameSecrets {
  private cache = new Map<string, string>();
  private cfg: Config;
  private env: NodeJS.ProcessEnv;
  constructor(cfg: Config, env: NodeJS.ProcessEnv = process.env) {
    this.cfg = cfg;
    this.env = env;
  }

  get(gameId: string): string | undefined {
    const fromEnv = this.env[secretEnvName(gameId)];
    if (fromEnv) return fromEnv;
    if (this.cfg.env !== 'dev') return undefined;
    return this.devSecret(gameId);
  }

  /** Dev only: secrets are generated and kept in DATA_DIR/game-secrets.json. */
  private devSecret(gameId: string): string {
    const hit = this.cache.get(gameId);
    if (hit) return hit;
    mkdirSync(this.cfg.dataDir, { recursive: true });
    const file = join(this.cfg.dataDir, 'game-secrets.json');
    const all: Record<string, string> = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
    if (!all[gameId]) {
      all[gameId] = rid(32);
      writeFileSync(file, JSON.stringify(all, null, 2));
    }
    this.cache.set(gameId, all[gameId]!);
    return all[gameId]!;
  }

  set(gameId: string, secret: string): void {
    this.cache.set(gameId, secret);
    this.env[secretEnvName(gameId)] = secret;
  }
}
