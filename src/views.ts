import { esc } from './util.ts';

/*
 * One stylesheet for every server-rendered page (admin console, LTI pages, demo game).
 * No external assets and no scripts on admin pages (CSP: default-src 'none'; style-src 'unsafe-inline').
 */
const CSS = `
:root{color-scheme:light;
--bg:#f4f5f8;--surface:#fff;--surface-2:#f8f9fb;--ink:#161a21;--ink-2:#3b4350;--muted:#667085;--line:#e3e6ec;--line-2:#eef0f4;
--accent:#3d5afe;--accent-ink:#fff;--accent-soft:#eef1ff;--accent-line:#c9d1ff;
--ok:#12805c;--ok-soft:#e7f6ef;--warn:#a15c00;--warn-soft:#fff4e0;--err:#c8283a;--err-soft:#fdecee;
--shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.04);--radius:12px;--sidebar:248px}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;
--bg:#0f1115;--surface:#171a20;--surface-2:#1c2027;--ink:#eceef2;--ink-2:#c5cad3;--muted:#9099a8;--line:#2a2f38;--line-2:#22262e;
--accent:#8c9eff;--accent-ink:#0f1115;--accent-soft:#1f2440;--accent-line:#3a4378;
--ok:#4cc38a;--ok-soft:#14291f;--warn:#f0b35a;--warn-soft:#2d2313;--err:#ff7a88;--err-soft:#331a1e;--shadow:none}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif}
a{color:var(--accent);text-underline-offset:2px}a:hover{text-decoration-thickness:2px}
main{max-width:880px;margin:0 auto;padding:28px 16px}
h1{font-size:24px;line-height:1.25;margin:0 0 6px;letter-spacing:-.01em}h2{font-size:17px;margin:28px 0 10px}h3{font-size:15px;margin:0}
p{margin:.4em 0}.muted{color:var(--muted)}.small{font-size:13px}.ok{color:var(--ok)}.err{color:var(--err)}
code,pre,.mono{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:13px}
code{background:var(--surface-2);border:1px solid var(--line-2);border-radius:5px;padding:0 5px;word-break:break-all}
pre{white-space:pre-wrap;word-break:break-all;background:var(--surface-2);border:1px solid var(--line);border-radius:8px;padding:12px;margin:8px 0}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:18px;margin:14px 0;box-shadow:var(--shadow)}
.card.flush{padding:0;overflow:hidden}.card-h{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--line)}
.card-h h2,.card-h h3{margin:0;font-size:15px}.card-b{padding:18px}.card-f{padding:12px 18px;border-top:1px solid var(--line);background:var(--surface-2)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.cols{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:16px;align-items:start}@media (max-width:1100px){.cols{grid-template-columns:1fr}}
label.game{display:block;cursor:pointer}label.game input{margin-right:8px}label.game:has(input:checked){outline:2px solid var(--accent)}
.field{margin:12px 0}.field>label{display:block;font-weight:600;font-size:14px;margin-bottom:5px}.hint{font-size:13px;color:var(--muted);margin-top:4px}
input[type=text],input[type=number],input[type=password],input[type=search],select{width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--ink);font:inherit;min-height:40px}
input:focus-visible,select:focus-visible,button:focus-visible,a:focus-visible,summary:focus-visible,label.navbtn:focus-within{outline:3px solid var(--accent-line);outline-offset:1px;border-color:var(--accent)}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;background:var(--accent);color:var(--accent-ink);border:1px solid transparent;border-radius:8px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;min-height:40px;white-space:nowrap}
button:hover,.btn:hover{filter:brightness(1.07)}button:disabled{opacity:.5;cursor:default}
button.small,.btn.small{padding:5px 11px;font-size:13px;min-height:32px}
button.ghost,.btn.ghost{background:var(--surface);color:var(--ink-2);border-color:var(--line)}button.ghost:hover,.btn.ghost:hover{background:var(--surface-2);filter:none}
button.danger,.btn.danger{background:var(--surface);color:var(--err);border-color:var(--line)}button.danger:hover{background:var(--err-soft);filter:none}
button.link{background:none;border:0;color:var(--muted);padding:6px 8px;font-weight:500;min-height:0}button.link:hover{color:var(--ink);filter:none}
.ico{width:18px;height:18px;flex:none;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px}
.tag{display:inline-block;font-size:12px;border:1px solid var(--line);border-radius:999px;padding:0 8px;color:var(--muted);white-space:nowrap}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;border-radius:999px;padding:2px 10px;background:var(--surface-2);color:var(--ink-2);white-space:nowrap}
.badge::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.8}
.badge.done,.badge.active{background:var(--ok-soft);color:var(--ok)}.badge.dead,.badge.suspended,.badge.disabled{background:var(--err-soft);color:var(--err)}
.badge.pending{background:var(--warn-soft);color:var(--warn)}.badge.superseded{color:var(--muted)}
.tablewrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px}
th{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);background:var(--surface-2);white-space:nowrap}
td,th{border-bottom:1px solid var(--line-2);padding:10px 12px;text-align:left;vertical-align:top}tr:last-child td{border-bottom:0}
tbody tr:hover td{background:var(--surface-2)}td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}td.nowrap{white-space:nowrap}
td.wrap{min-width:150px;max-width:340px;overflow-wrap:anywhere}td.actions{text-align:right;min-width:150px}td.actions form{display:inline-block;margin:2px 0 2px 4px}
.notice{display:flex;gap:12px;align-items:flex-start;border:1px solid var(--accent-line);background:var(--accent-soft);color:var(--ink);border-radius:10px;padding:12px 14px;margin:14px 0}
.notice .ico{color:var(--accent);margin-top:2px}.notice p{margin:0}.notice.ok{border-color:transparent;background:var(--ok-soft)}.notice.ok .ico{color:var(--ok)}
.notice.err{border-color:transparent;background:var(--err-soft)}.notice.err .ico,.notice.err p.err{color:var(--err)}.notice.warn{border-color:transparent;background:var(--warn-soft)}.notice.warn .ico{color:var(--warn)}
.notice.card{padding:12px 14px}pre.secret{font-size:20px;letter-spacing:1px;user-select:all;background:var(--surface);text-align:center}
.empty{text-align:center;padding:36px 16px;color:var(--muted)}.empty .ico{width:32px;height:32px;stroke-width:1.5;margin-bottom:8px;opacity:.7}
.empty p{margin:2px 0}.empty b{color:var(--ink-2)}
.stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px;margin:16px 0}
.stat{display:flex;gap:14px;align-items:center;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow);text-decoration:none;color:var(--ink)}
a.stat:hover{border-color:var(--accent-line)}.stat .ic{display:grid;place-items:center;width:42px;height:42px;border-radius:10px;background:var(--accent-soft);color:var(--accent);flex:none}
.stat .ic .ico{width:21px;height:21px}.stat b{display:block;font-size:26px;line-height:1.1;font-variant-numeric:tabular-nums}.stat .lbl{display:block;font-size:13px;color:var(--muted)}
.stat.ok .ic{background:var(--ok-soft);color:var(--ok)}.stat.warn .ic{background:var(--warn-soft);color:var(--warn)}.stat.err .ic{background:var(--err-soft);color:var(--err)}.stat.err b{color:var(--err)}
.filters{display:flex;flex-wrap:wrap;gap:6px}.filters a{padding:5px 12px;border:1px solid var(--line);border-radius:999px;text-decoration:none;color:var(--ink-2);font-size:13px;font-weight:500;background:var(--surface)}
.filters a:hover{border-color:var(--accent-line)}.filters a.on{border-color:var(--accent);background:var(--accent-soft);color:var(--accent);font-weight:600}
.filters a .n{color:var(--muted);font-weight:500;margin-left:4px}.filters a.on .n{color:inherit}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px 18px;border-bottom:1px solid var(--line);background:var(--surface-2)}
.toolbar form{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-left:auto}.toolbar input[type=search]{width:240px;min-height:36px;padding:6px 10px}
.toolbar select{width:auto;min-height:36px;padding:6px 10px}.toolbar .filters{flex:1 1 auto}
.pager{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;padding:12px 18px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}
.pager nav{display:flex;gap:6px}
.kv th{width:240px;text-transform:none;letter-spacing:0;font-size:13px;color:var(--ink-2);background:transparent;white-space:normal}.kv td code{font-size:13px}
details.more>summary{cursor:pointer;list-style:none;display:inline-flex;align-items:center;gap:6px;font-weight:600;color:var(--accent)}details.more>summary::-webkit-details-marker{display:none}
details.more[open]>summary{margin-bottom:8px}.checks{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:6px}
.checks label{display:flex;gap:8px;align-items:flex-start;padding:8px 10px;border:1px solid var(--line);border-radius:8px;cursor:pointer;font-weight:500;font-size:14px}
.checks label:has(input:checked){border-color:var(--accent);background:var(--accent-soft)}.checks input{margin-top:3px}
.row{display:flex;flex-wrap:wrap;gap:12px}.row>.field{flex:1 1 220px;margin:0}.actions-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:14px}

/* ----- admin shell ----- */
body.admin{min-height:100vh}
.shell{display:grid;grid-template-columns:var(--sidebar) minmax(0,1fr);min-height:100vh}
.side{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;background:var(--surface);border-right:1px solid var(--line);padding:16px 12px}
.brand{display:flex;align-items:center;gap:10px;padding:4px 8px 16px;font-weight:700;font-size:16px;color:var(--ink);text-decoration:none}
.logo{display:grid;place-items:center;width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,#3d5afe,#7c4dff);color:#fff;flex:none}
.logo .ico{width:18px;height:18px;stroke-width:2.1}.brand small{display:block;font-size:12px;font-weight:500;color:var(--muted)}
.nav{display:flex;flex-direction:column;gap:2px}.nav a{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;color:var(--ink-2);text-decoration:none;font-weight:500;font-size:14px}
.nav a:hover{background:var(--surface-2);color:var(--ink)}.nav a.on{background:var(--accent-soft);color:var(--accent);font-weight:600}.nav .sep{height:1px;background:var(--line);margin:8px 6px}
.me{margin-top:auto;border-top:1px solid var(--line);padding:12px 6px 0}.me .who{display:flex;gap:10px;align-items:center;margin-bottom:8px}
.avatar{display:grid;place-items:center;width:34px;height:34px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-weight:700;font-size:13px;flex:none}
.me .name{font-weight:600;font-size:14px;line-height:1.2;overflow-wrap:anywhere}.me .role{font-size:12px;color:var(--muted)}
.me .links{display:flex;flex-wrap:wrap;gap:2px}.me .links a,.me .links button{font-size:13px;padding:5px 8px;border-radius:6px;color:var(--muted);text-decoration:none;display:inline-flex;gap:6px;align-items:center}
.me .links a:hover,.me .links button:hover{background:var(--surface-2);color:var(--ink)}.me .links .ico{width:15px;height:15px}
.content{min-width:0;padding:28px 32px 48px;max-width:1240px;width:100%}
.ph{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;justify-content:space-between;margin-bottom:6px}.ph p{color:var(--muted);max-width:760px}
.topbar{display:none}.navtoggle{position:absolute;opacity:0;pointer-events:none}
@media (max-width:900px){
.shell{display:block}.topbar{display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:5;background:var(--surface);border-bottom:1px solid var(--line);padding:8px 16px}
.topbar .brand{padding:0}.navbtn{display:inline-flex;align-items:center;gap:6px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;color:var(--ink-2)}
.side{display:none;position:static;height:auto;border-right:0;border-bottom:1px solid var(--line)}.side .brand{display:none}
.navtoggle:checked~.shell .side{display:flex}.stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.stat{padding:12px;gap:10px}.stat .ic{width:36px;height:36px}.stat b{font-size:22px}.content{padding:20px 16px 40px}h1{font-size:21px}
.toolbar form{margin-left:0;width:100%}.toolbar input[type=search]{flex:1 1 160px;width:auto}td,th{padding:9px 10px}}

/* ----- sign-in and standalone pages ----- */
body.center{display:grid;place-items:center;min-height:100vh;padding:24px 16px;background:radial-gradient(1200px 600px at 10% -10%,var(--accent-soft),transparent 60%),var(--bg)}
body.center main{width:100%;max-width:420px;padding:0}.center .brand{justify-content:center;padding-bottom:20px;font-size:18px}.center .logo{width:40px;height:40px;border-radius:11px}
.center .card{padding:24px}.center h1{font-size:20px;text-align:center}.center .lead{text-align:center;color:var(--muted);margin-bottom:8px}
.center button.wide{width:100%;margin-top:6px}.center .foot{text-align:center;font-size:13px;color:var(--muted);margin-top:14px}
.state{text-align:center}.state .big{display:grid;place-items:center;width:52px;height:52px;border-radius:50%;margin:0 auto 12px;background:var(--err-soft);color:var(--err)}
.state .big .ico{width:26px;height:26px}.state.info .big{background:var(--accent-soft);color:var(--accent)}
`;

export function page(title: string, body: string, opts: { script?: string; wide?: boolean; bodyClass?: string; bare?: boolean } = {}): string {
  const inner = opts.bare ? body : `<main${opts.wide ? ' class="wide"' : ''}>${body}</main>`;
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>${esc(title)}</title><style>${CSS}</style></head><body${opts.bodyClass ? ` class="${esc(opts.bodyClass)}"` : ''}>${inner}${opts.script ? `<script>${opts.script}</script>` : ''}</body></html>`;
}

// ---------- icons (inline SVG, stroke style) ----------
const ICONS: Record<string, string> = {
  home: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  send: '<path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4z"/>',
  school: '<path d="M2 9l10-5 10 5-10 5z"/><path d="M6 11v5c0 1.5 3 3 6 3s6-1.5 6-3v-5"/><path d="M22 9v6"/>',
  plug: '<path d="M9 2v6M15 2v6"/><path d="M6 8h12v3a6 6 0 0 1-12 0z"/><path d="M12 17v5"/>',
  game: '<rect x="2" y="7" width="20" height="11" rx="4"/><path d="M7 11v3M5.5 12.5h3"/><circle cx="15.5" cy="11.5" r=".8"/><circle cx="17.5" cy="13.5" r=".8"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 21 2M17 6l3 3M14 9l2 2"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>',
  menu: '<path d="M3 6h18M3 12h18M3 18h18"/>',
  alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
  check: '<circle cx="12" cy="12" r="10"/><path d="m8 12 3 3 5-6"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
  clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.1z"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  refresh: '<path d="M21 12a9 9 0 0 1-15.5 6.3L3 16"/><path d="M3 12A9 9 0 0 1 18.5 5.7L21 8"/><path d="M21 3v5h-5M3 21v-5h5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  bolt: '<path d="M13 2 3 14h9l-1 8 10-12h-9z"/>',
};
export const icon = (name: string, cls = 'ico'): string => `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] ?? ''}</svg>`;

const logo = `<span class="logo">${icon('game')}</span>`;
const brand = (sub?: string) => `<span class="brand">${logo}<span>UniGame Hub${sub ? `<small>${esc(sub)}</small>` : ''}</span></span>`;

// ---------- small building blocks shared by console pages ----------
export type Tone = 'info' | 'ok' | 'warn' | 'err';
const TONE_ICON: Record<Tone, string> = { info: 'info', ok: 'check', warn: 'alert', err: 'alert' };
/** Inline message box. `html` is trusted markup (escape user data before passing it). */
export const notice = (tone: Tone, html: string): string =>
  `<div class="notice ${tone}" role="${tone === 'err' ? 'alert' : 'status'}">${icon(TONE_ICON[tone])}<div><p${tone === 'err' ? ' class="err"' : ''}>${html}</p></div></div>`;
export const emptyState = (title: string, hint = '', ic = 'inbox'): string =>
  `<div class="empty">${icon(ic)}<p><b>${esc(title)}</b></p>${hint ? `<p class="small">${hint}</p>` : ''}</div>`;

export const ADMIN_NAV: Array<[string, string, string]> = [
  ['/admin', 'Tổng quan', 'home'],
  ['/admin/jobs', 'Gửi điểm', 'send'],
  ['/admin/tenants', 'Trường', 'school'],
  ['/admin/platforms', 'Moodle / LMS', 'plug'],
  ['/admin/games', 'Game', 'game'],
  ['/admin/setup', 'Cấu hình LTI', 'settings'],
  ['/admin/audit', 'Nhật ký', 'list'],
];

export interface AdminViewer {
  csrf: string;
  username: string;
  displayName: string;
  role: 'owner' | 'admin';
  viaToken: boolean;
}

const initials = (name: string): string =>
  name
    .split(/\s+/)
    .filter(Boolean)
    .slice(-2)
    .map((w) => w[0]!.toUpperCase())
    .join('') || '?';

/**
 * Admin console page: sidebar (role-aware) + signed-in account + logout form (CSRF-protected).
 * On narrow screens the sidebar collapses behind a CSS-only menu toggle. No scripts.
 */
export function adminPage(title: string, active: string, who: AdminViewer, body: string, opts: { lead?: string; actions?: string } = {}): string {
  const link = ([href, label, ic]: [string, string, string]) =>
    `<a href="${href}"${href === active ? ' class="on" aria-current="page"' : ''}>${icon(ic)}${esc(label)}</a>`;
  const ownerLinks = who.role === 'owner' ? `<div class="sep"></div>${link(['/admin/users', 'Tài khoản', 'users'])}` : '';
  const name = who.viaToken ? 'Mã khẩn cấp' : who.displayName;
  const role = who.viaToken ? 'ADMIN_TOKEN' : who.role === 'owner' ? 'Chủ hệ thống' : 'Quản trị viên';
  const me = `<div class="me"><div class="who"><span class="avatar">${who.viaToken ? icon('key') : esc(initials(name))}</span><div><div class="name">${esc(name)}</div><div class="role">${esc(role)}</div></div></div>
<div class="links">${who.viaToken ? '' : `<a href="/admin/password"${active === '/admin/password' ? ' aria-current="page"' : ''}>${icon('key')}Đổi mật khẩu</a>`}
<form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="${esc(who.csrf)}"><button class="link">${icon('logout')}Đăng xuất</button></form></div></div>`;
  const shell = `<input type="checkbox" id="navtoggle" class="navtoggle" aria-label="Mở menu">
<header class="topbar"><a class="brand" href="/admin">${logo}<span>UniGame Hub</span></a><label class="navbtn" for="navtoggle">${icon('menu')}Menu</label></header>
<div class="shell"><aside class="side"><a class="brand" href="/admin">${logo}<span>UniGame Hub<small>Quản trị</small></span></a>
<nav class="nav" aria-label="Điều hướng">${ADMIN_NAV.map(link).join('')}${ownerLinks}</nav>${me}</aside>
<main class="content"><div class="ph"><div><h1>${esc(title)}</h1>${opts.lead ? `<p>${opts.lead}</p>` : ''}</div>${opts.actions ? `<div class="actions-row">${opts.actions}</div>` : ''}</div>${body}</main></div>`;
  return page(`${title} · UniGame Hub`, shell, { bare: true, bodyClass: 'admin' });
}

/** Centered single-card page (sign-in, standalone states). */
export function centerPage(title: string, body: string, sub?: string): string {
  return page(title, `${brand(sub)}${body}`, { bodyClass: 'center' });
}

export function errorPage(title: string, detail: string): string {
  return centerPage(title, `<div class="card state"><div class="big">${icon('alert')}</div><h1>${esc(title)}</h1><p>${esc(detail)}</p>
<p class="muted small">Vui lòng quay lại Moodle và thử lại. Nếu lỗi lặp lại, hãy báo quản trị viên kèm thời điểm xảy ra lỗi.</p></div>`);
}

export function adminErrorPage(detail: string): string {
  return centerPage('Lỗi · UniGame Hub', `<div class="card state"><div class="big">${icon('alert')}</div><h1>Không thực hiện được</h1><p>${esc(detail)}</p>
<div class="actions-row" style="justify-content:center"><a class="btn small" href="/admin">Về trang quản trị</a><a class="btn small ghost" href="/admin/login">Đăng nhập lại</a></div></div>`, 'Quản trị');
}

/** Auto-submitting form (used for the Deep Linking response back to the LMS). */
export function autoPost(action: string, fields: Record<string, string>, message: string): string {
  const inputs = Object.entries(fields)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join('');
  return page(message, `<p>${esc(message)}</p><form id="f" method="post" action="${esc(action)}">${inputs}<noscript><button>Tiếp tục</button></noscript></form>`, {
    script: `document.getElementById('f').submit();`,
  });
}

/** Redirect via location.replace so the ticket in the fragment is not kept in history. */
export function redirectWithFragment(url: string, fragment: string, message: string): string {
  const target = `${url}#${fragment}`;
  return page(message, `<p>${esc(message)}</p><p class="muted"><a href="${esc(target)}">Bấm vào đây nếu trình duyệt không tự chuyển.</a></p>`, {
    script: `location.replace(${JSON.stringify(target)});`,
  });
}
