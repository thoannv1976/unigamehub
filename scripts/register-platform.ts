/**
 * Registers a tenant + LMS platform on a running Hub, from the JSON printed by scripts/moodle/register_tool.php.
 * Usage: node scripts/register-platform.ts <platform.json> --tenant=aiedu-local --tenant-name="AIEDU (local)" [--hub=http://localhost:8787] [--games=*]
 * Outside dev set ADMIN_TOKEN in the environment.
 */
import { readFileSync } from 'node:fs';

const args = Object.fromEntries(process.argv.slice(3).map((a) => a.replace(/^--/, '').split('=')) as Array<[string, string]>);
const file = process.argv[2];
if (!file || !args.tenant) {
  console.error('Usage: node scripts/register-platform.ts <platform.json> --tenant=<id> [--tenant-name=..] [--hub=..] [--games=a,b|*]');
  process.exit(1);
}
const hub = (args.hub ?? 'http://localhost:8787').replace(/\/+$/, '');
const p = JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, ''));
const headers = { 'content-type': 'application/json', ...(process.env.ADMIN_TOKEN ? { 'x-admin-token': process.env.ADMIN_TOKEN } : {}) };

async function post(path: string, body: unknown) {
  const res = await fetch(`${hub}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
  const json = await res.json();
  if (!res.ok) throw new Error(`${path} ${res.status}: ${JSON.stringify(json)}`);
  return json;
}

await post('/api/v1/admin/tenants', { id: args.tenant, name: args['tenant-name'] ?? args.tenant, allowedGames: (args.games ?? '*').split(','), status: 'active' });
// --service-base=https://xxxx.ngrok-free.app : the Hub reaches this LMS's services through a tunnel.
const serviceBase = args['service-base']?.replace(/\/+$/, '');
const viaTunnel = (u: string) => (serviceBase && u.startsWith(`${p.issuer}/`) ? serviceBase + u.slice(p.issuer.length) : u);
const platform = await post('/api/v1/admin/platforms', {
  tenantId: args.tenant,
  name: p.name ?? 'Moodle',
  issuer: p.issuer,
  clientId: p.clientId,
  authUrl: p.authUrl,
  tokenUrl: viaTunnel(p.tokenUrl),
  jwksUrl: viaTunnel(p.jwksUrl),
  deploymentIds: p.deploymentIds,
  ...(serviceBase ? { serviceBaseUrl: serviceBase } : {}),
  // --static-jwks: embed the LMS's current public keys (for an LMS the Hub cannot reach, e.g. local Moodle).
  ...('static-jwks' in args ? { jwks: await (await fetch(p.jwksUrl)).json() } : {}),
});
console.log(`Registered platform ${platform.id} (${platform.issuer}, client ${platform.clientId}) for tenant ${args.tenant}`);
