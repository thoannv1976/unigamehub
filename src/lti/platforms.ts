import { createLocalJWKSet, createRemoteJWKSet, type JSONWebKeySet, type JWTVerifyGetKey } from 'jose';
import { z } from 'zod';
import { COL, type Store } from '../store/types.ts';
import { hid } from '../util.ts';

export const PlatformInput = z.object({
  tenantId: z.string().min(1).max(64),
  name: z.string().min(1).max(200),
  issuer: z.string().url(),
  clientId: z.string().min(1).max(200),
  authUrl: z.string().url(),
  tokenUrl: z.string().url(),
  jwksUrl: z.string().url(),
  deploymentIds: z.array(z.string().min(1)).min(1),
  /**
   * Optional: base URL the Hub uses to reach the LMS's services when the issuer URL is not reachable
   * from the Hub (e.g. a local Moodle at http://localhost exposed through a tunnel). Service URLs that
   * start with the issuer are rewritten to start with this instead.
   */
  serviceBaseUrl: z.string().url().optional(),
  /**
   * Optional static copy of the platform's public keys (JWKS). Used instead of fetching jwksUrl when the
   * LMS is not reachable from the Hub (e.g. a local development Moodle). Update it if the LMS rotates keys.
   */
  jwks: z.object({ keys: z.array(z.record(z.string(), z.unknown())).min(1) }).optional(),
});
export type PlatformInput = z.infer<typeof PlatformInput>;

export interface Platform extends PlatformInput {
  [k: string]: unknown;
  id: string;
  status: 'active' | 'disabled';
  createdAt: string;
  updatedAt: string;
}

export interface Tenant {
  [k: string]: unknown;
  id: string;
  name: string;
  /** Game ids licensed to this tenant, or ['*']. */
  allowedGames: string[];
  status: 'active' | 'suspended';
}

export const platformId = (issuer: string, clientId: string): string => hid('pf', issuer, clientId);

export async function upsertPlatform(store: Store, input: PlatformInput): Promise<Platform> {
  const p = PlatformInput.parse(input);
  const id = platformId(p.issuer, p.clientId);
  const now = new Date().toISOString();
  return (await store.update<Platform>(COL.platforms, id, (cur) => ({
    ...p,
    id,
    status: cur?.status ?? 'active',
    createdAt: cur?.createdAt ?? now,
    updatedAt: now,
  })))!;
}

export async function findPlatform(store: Store, issuer: string, clientId?: string): Promise<Platform | null> {
  if (clientId) {
    const p = await store.get<Platform>(COL.platforms, platformId(issuer, clientId));
    return p && p.status === 'active' ? p : null;
  }
  const list = (await store.find<Platform>(COL.platforms, { issuer, status: 'active' }, 2));
  return list.length === 1 ? list[0]! : null;
}

export type JwksResolver = (p: Platform) => JWTVerifyGetKey;

/** Default: fetch and cache the platform's JWKS over HTTP. */
export function remoteJwksResolver(): JwksResolver {
  const cache = new Map<string, JWTVerifyGetKey>();
  return (p) => {
    if (p.jwks) return createLocalJWKSet(p.jwks as unknown as JSONWebKeySet);
    let k = cache.get(p.jwksUrl);
    if (!k) {
      k = createRemoteJWKSet(new URL(p.jwksUrl), {
        cooldownDuration: 30_000,
        cacheMaxAge: 10 * 60_000,
        ...(p.serviceBaseUrl ? { headers: { 'ngrok-skip-browser-warning': '1' } } : {}),
      });
      cache.set(p.jwksUrl, k);
    }
    return k;
  };
}
