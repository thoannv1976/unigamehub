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
`;

export function page(title: string, body: string, opts: { script?: string } = {}): string {
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${CSS}</style></head><body><main>${body}</main>${opts.script ? `<script>${opts.script}</script>` : ''}</body></html>`;
}

export function errorPage(title: string, detail: string): string {
  return page(title, `<h1 class="err">${esc(title)}</h1><div class="card"><p>${esc(detail)}</p>
<p class="muted">Vui lòng quay lại Moodle và thử lại. Nếu lỗi lặp lại, hãy báo quản trị viên kèm thời điểm xảy ra lỗi.</p></div>`);
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
