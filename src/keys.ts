import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { exportJWK, exportSPKI, generateKeyPair, importJWK, SignJWT, type JWK, type JWTPayload } from 'jose';
import type { Config } from './config.ts';
import { rid } from './util.ts';

interface LoadedKey {
  kid: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: JWK;
}

/** Tool signing keys. The first key is active; the others stay in the JWKS during rotation. */
export class KeyRing {
  private keys: LoadedKey[];
  constructor(keys: LoadedKey[]) {
    if (keys.length === 0) throw new Error('KeyRing needs at least one key');
    this.keys = keys;
  }

  get activeKid(): string {
    return this.keys[0]!.kid;
  }

  jwks(): { keys: JWK[] } {
    return { keys: this.keys.map((k) => ({ ...k.publicJwk, kid: k.kid, alg: 'RS256', use: 'sig' })) };
  }

  /** Local key resolver (used by the built-in demo game instead of fetching our own JWKS). */
  publicKeyFor(kid?: string): CryptoKey {
    const k = this.keys.find((x) => x.kid === kid) ?? this.keys[0]!;
    return k.publicKey;
  }

  async publicPem(): Promise<string> {
    return exportSPKI(this.keys[0]!.publicKey);
  }

  async sign(payload: JWTPayload, typ?: string): Promise<string> {
    const k = this.keys[0]!;
    return new SignJWT(payload).setProtectedHeader({ alg: 'RS256', kid: k.kid, ...(typ ? { typ } : {}) }).sign(k.privateKey);
  }
}

async function load(jwks: JWK[]): Promise<KeyRing> {
  const loaded: LoadedKey[] = [];
  for (const jwk of jwks) {
    if (!jwk.kid) throw new Error('Signing key without kid');
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = jwk;
    loaded.push({
      kid: jwk.kid,
      privateKey: (await importJWK(jwk, 'RS256')) as CryptoKey,
      publicKey: (await importJWK(pub, 'RS256')) as CryptoKey,
      publicJwk: pub,
    });
  }
  return new KeyRing(loaded);
}

export async function generateSigningJwk(): Promise<JWK> {
  const { privateKey } = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const jwk = await exportJWK(privateKey);
  return { ...jwk, kid: `k-${new Date().toISOString().slice(0, 10)}-${rid(4)}`, alg: 'RS256' };
}

export async function loadKeyRing(cfg: Config): Promise<KeyRing> {
  if (cfg.signingKeysJson) return load(JSON.parse(cfg.signingKeysJson) as JWK[]);
  if (cfg.env !== 'dev') throw new Error('HUB_SIGNING_KEYS missing');
  mkdirSync(cfg.dataDir, { recursive: true });
  const file = join(cfg.dataDir, 'signing-keys.json');
  if (!existsSync(file)) writeFileSync(file, JSON.stringify([await generateSigningJwk()], null, 2));
  return load(JSON.parse(readFileSync(file, 'utf8')) as JWK[]);
}

export async function ephemeralKeyRing(): Promise<KeyRing> {
  return load([await generateSigningJwk()]);
}
