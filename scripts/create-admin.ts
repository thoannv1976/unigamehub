/**
 * Creates an admin console account on a running Hub and prints its temporary password (shown once).
 * Usage: node scripts/create-admin.ts --username=<name> [--role=owner|admin] [--name="Full name"] [--hub=https://…]
 * Outside dev set ADMIN_TOKEN in the environment, e.g. (PowerShell):
 *   $env:ADMIN_TOKEN = gcloud secrets versions access latest --secret hub-admin-token --project gamehub-514101
 * Easier alternative: open /admin/login?mode=token in a browser and use the "Tài khoản" page.
 */
const args = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, '').split('=')) as Array<[string, string]>);
if (!args.username) {
  console.error('Usage: node scripts/create-admin.ts --username=<name> [--role=owner|admin] [--name="Full name"] [--hub=URL]');
  process.exit(1);
}
const hub = (args.hub ?? 'http://localhost:8787').replace(/\/+$/, '');
const res = await fetch(`${hub}/api/v1/admin/users`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(process.env.ADMIN_TOKEN ? { 'x-admin-token': process.env.ADMIN_TOKEN } : {}) },
  body: JSON.stringify({ username: args.username, role: args.role ?? 'owner', ...(args.name ? { displayName: args.name } : {}) }),
});
const json = await res.json();
if (!res.ok) {
  console.error(`Failed (${res.status}): ${JSON.stringify(json)}`);
  process.exit(1);
}
console.log(`Created ${json.username} (${json.role}). Temporary password (change at first sign-in): ${json.temporaryPassword}`);
