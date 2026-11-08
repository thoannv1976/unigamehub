import type { KeyRing } from '../keys.ts';
import { nowSec, rid } from '../util.ts';
import { SCOPE } from './claims.ts';
import type { Platform } from './platforms.ts';

export interface AgsScore {
  userId: string;
  scoreGiven: number;
  scoreMaximum: number;
  activityProgress: string;
  gradingProgress: string;
  timestamp: string;
  comment?: string;
}

/** Insert "/scores" into the line item path, keeping any query string (Moodle uses ?type_id=). */
export function scoresUrl(lineitem: string): string {
  const u = new URL(lineitem);
  u.pathname = `${u.pathname.replace(/\/+$/, '')}/scores`;
  return u.toString();
}

/** Apply the platform's serviceBaseUrl (tunnel) to a service URL that starts with the issuer. */
export function serviceUrl(platform: Pick<Platform, 'issuer' | 'serviceBaseUrl'>, url: string): string {
  const base = platform.serviceBaseUrl?.replace(/\/+$/, '');
  const iss = platform.issuer.replace(/\/+$/, '');
  return base && url.startsWith(`${iss}/`) ? base + url.slice(iss.length) : url;
}

const extraHeaders = (p: Platform): Record<string, string> => (p.serviceBaseUrl ? { 'ngrok-skip-browser-warning': '1' } : {});

/** LTI Advantage service client (OAuth2 client_credentials with a signed JWT assertion). */
export class AgsClient {
  private tokens = new Map<string, { token: string; exp: number }>();
  private keys: KeyRing;
  private fetchFn: typeof fetch;

  constructor(keys: KeyRing, fetchFn: typeof fetch) {
    this.keys = keys;
    this.fetchFn = fetchFn;
  }

  async token(platform: Platform, scopes: string[]): Promise<string> {
    const key = `${platform.id}|${[...scopes].sort().join(' ')}`;
    const hit = this.tokens.get(key);
    if (hit && hit.exp > nowSec() + 30) return hit.token;
    const iat = nowSec();
    const assertion = await this.keys.sign({
      iss: platform.clientId,
      sub: platform.clientId,
      aud: platform.tokenUrl,
      iat,
      exp: iat + 300,
      jti: rid(),
    });
    const res = await this.fetchFn(platform.tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', ...extraHeaders(platform) },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
        scope: scopes.join(' '),
      }),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`token endpoint ${res.status}: ${text.slice(0, 300)}`);
    const json = JSON.parse(text) as { access_token?: string; expires_in?: number };
    if (!json.access_token) throw new Error('token endpoint returned no access_token');
    this.tokens.set(key, { token: json.access_token, exp: iat + (json.expires_in ?? 3600) });
    return json.access_token;
  }

  async postScore(platform: Platform, lineitem: string, score: AgsScore): Promise<void> {
    const send = async (token: string) =>
      this.fetchFn(serviceUrl(platform, scoresUrl(lineitem)), {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/vnd.ims.lis.v1.score+json', ...extraHeaders(platform) },
        body: JSON.stringify(score),
      });
    let res = await send(await this.token(platform, [SCOPE.score]));
    if (res.status === 401) {
      this.tokens.clear();
      res = await send(await this.token(platform, [SCOPE.score]));
    }
    if (!res.ok) throw new Error(`score POST ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
}
