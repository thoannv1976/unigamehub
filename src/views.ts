import { esc } from './util.ts';

const CSS = `
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b1f24;--muted:#5b6470;--line:#dde1e6;--accent:#0f62fe;--ok:#198038;--err:#da1e28}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--card:#1c1f24;--ink:#eef0f3;--muted:#a3abb5;--line:#30353c;--accent:#78a9ff;--ok:#42be65;--err:#ff8389}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:880px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:24px 0 8px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
label.game{display:block;cursor:pointer}label.game input{margin-right:8px}label.game:has(input:checked){outline:2px solid var(--accent)}
.field{margin:10px 0}.field label{display:block;font-weight:600;margin-bottom:4px}
input[type=text],input[type=number],select{width:100%;padding:8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink);font:inherit}
button{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:10px 18px;font:inherit;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:default}code,pre{font-family:ui-monospace,Consolas,monospace;font-size:13px}
pre{white-space:pre-wrap;word-break:break-all;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px}
.ok{color:var(--ok)}.err{color:var(--err)}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top}
.tag{display:inline-block;font-size:12px;border:1px solid var(--line);border-radius:999px;padding:0 8px;color:var(--muted)}
main.wide{max-width:1180px}
nav.admin{display:flex;flex-wrap:wrap;gap:4px;align-items:center;margin:0 0 16px;padding-bottom:12px;border-bottom:1px solid var(--line)}
nav.admin a{color:var(--ink);text-decoration:none;padding:6px 10px;border-radius:6px}nav.admin a:hover{background:var(--card)}
nav.admin a.on{background:var(--accent);color:#fff}nav.admin .brand{font-weight:700;margin-right:12px}
nav.admin form{margin-left:auto}button.link{background:none;color:var(--muted);padding:6px 10px;font-weight:500}
button.small{padding:4px 10px;font-size:13px}
.stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}.stat b{display:block;font-size:26px}
.badge{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:1px 9px;background:var(--bg);border:1px solid var(--line)}
.badge.done,.badge.active{color:var(--ok);border-color:var(--ok)}.badge.dead,.badge.suspended,.badge.disabled{color:var(--err);border-color:var(--err)}
.badge.pending{color:#b28600;border-color:#b28600}
.tablewrap{overflow-x:auto}.filters{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
.filters a{padding:4px 10px;border:1px solid var(--line);border-radius:999px;text-decoration:none;color:var(--ink)}.filters a.on{border-color:var(--accent);color:var(--accent);font-weight:600}
input[type=password]{width:100%;padding:8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink);font:inherit}
.notice{border-left:4px solid var(--accent)}.notice.err{border-left-color:var(--err)}
`;

export function page(title: string, body: string, opts: { script?: string; wide?: boolean } = {}): string {
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${CSS}</style></head><body><main${opts.wide ? ' class="wide"' : ''}>${body}</main>${opts.script ? `<script>${opts.script}</script>` : ''}</body></html>`;
}

export const ADMIN_NAV: Array<[string, string]> = [
  ['/admin', 'Tổng quan'],
  ['/admin/jobs', 'Gửi điểm'],
  ['/admin/tenants', 'Trường'],
  ['/admin/platforms', 'Moodle / LMS'],
  ['/admin/games', 'Game'],
  ['/admin/setup', 'Cấu hình LTI'],
  ['/admin/audit', 'Nhật ký'],
];

/** Admin console page: navigation bar + logout form (CSRF-protected). No scripts. */
export function adminPage(title: string, active: string, csrf: string, body: string): string {
  const links = ADMIN_NAV.map(([href, label]) => `<a href="${href}"${href === active ? ' class="on"' : ''}>${esc(label)}</a>`).join('');
  const nav = `<nav class="admin"><span class="brand">UniGame Hub</span>${links}
<form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="link">Đăng xuất</button></form></nav>`;
  return page(`${title} · UniGame Hub`, `${nav}<h1>${esc(title)}</h1>${body}`, { wide: true });
}

export function errorPage(title: string, detail: string): string {
  return page(title, `<h1 class="err">${esc(title)}</h1><div class="card"><p>${esc(detail)}</p>
<p class="muted">Vui lòng quay lại Moodle và thử lại. Nếu lỗi lặp lại, hãy báo quản trị viên kèm thời điểm xảy ra lỗi.</p></div>`);
}

export function adminErrorPage(detail: string): string {
  return page('Lỗi · UniGame Hub', `<h1 class="err">Không thực hiện được</h1><div class="card"><p>${esc(detail)}</p>
<p><a href="/admin">Về trang quản trị</a> · <a href="/admin/login">Đăng nhập lại</a></p></div>`);
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
