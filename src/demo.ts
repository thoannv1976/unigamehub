import type { FastifyInstance } from 'fastify';
import { submitResult, verifyLaunchTicket, type LaunchContext } from '../sdk/index.ts';
import type { Deps } from './deps.ts';
import type { SyncJob } from './results.ts';
import { COL } from './store/types.ts';
import { HttpError, isRecord, rid } from './util.ts';
import { page } from './views.ts';

/**
 * Built-in demo game. It plays the role of a real game adapter:
 * its "backend" verifies the ticket with the SDK and submits scores through the public results API.
 */
export function registerDemoGame(app: FastifyInstance, deps: Deps): void {
  const { cfg, store, keys, secrets } = deps;
  const GAME_ID = 'demo';

  app.get('/demo/', async (_req, reply) =>
    reply.header('content-type', 'text/html; charset=utf-8').header('cache-control', 'no-store').send(page('Demo game – UniGame Hub', `
<h1>🎯 Demo game</h1><p class="muted">Game mẫu để kiểm thử đăng nhập một lần và đồng bộ điểm.</p>
<div id="out" class="card">Đang xác thực…</div>
<div id="play" class="card" hidden>
<div class="field"><label for="score">Điểm đạt được (0–100)</label><input type="number" id="score" min="0" max="100" value="85"></div>
<button id="finish">Hoàn thành &amp; nộp điểm</button> <span id="st" class="muted"></span></div>`, {
      script: `(async function(){
var m=/(?:^#|&)ticket=([^&]+)/.exec(location.hash);history.replaceState(null,'',location.pathname);
var out=document.getElementById('out');if(!m){out.innerHTML='<span class="err">Không có vé đăng nhập. Hãy mở game từ Moodle.</span>';return;}
var r=await fetch('/demo/api/exchange',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({ticket:decodeURIComponent(m[1])})});
var d=await r.json();if(!r.ok){out.innerHTML='<span class="err">'+(d.message||d.error)+'</span>';return;}
function e(s){var x=document.createElement('span');x.textContent=s==null?'':s;return x.innerHTML;}
out.innerHTML='<b class="ok">Đã đăng nhập qua Moodle</b><br>Xin chào <b>'+e(d.name||'(không có tên)')+'</b> · vai trò: '+e(d.role)+'<br>Email: '+e(d.email||'-')+'<br>Khóa học: '+e(d.course||'-')+'<br>Hoạt động: '+e(d.resource||'-')+(d.activity?' · bài: '+e(d.activity):'')+'<br>'+(d.gradable?'<span class="ok">Điểm sẽ được đồng bộ về Sổ điểm Moodle.</span>':'<span class="muted">Hoạt động không đồng bộ điểm (giảng viên hoặc chưa bật chấm điểm).</span>');
var play=document.getElementById('play');play.hidden=!d.gradable;
document.getElementById('finish').onclick=async function(){var st=document.getElementById('st');st.textContent='Đang nộp…';
var f=await fetch('/demo/api/finish',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({session:d.session,score:Number(document.getElementById('score').value)})});
var j=await f.json();if(!f.ok){st.innerHTML='<span class="err">'+e(j.message||j.error)+'</span>';return;}
st.textContent='Đã gửi ('+j.status+'), đang chuyển về Moodle…';
for(var i=0;i<20&&j.job_id;i++){await new Promise(function(res){setTimeout(res,1000)});var s=await (await fetch('/demo/api/job?session='+encodeURIComponent(d.session)+'&id='+encodeURIComponent(j.job_id))).json();
if(s.status==='done'){st.innerHTML='<span class="ok">✔ Điểm đã vào Sổ điểm Moodle.</span>';return;} if(s.status==='dead'){st.innerHTML='<span class="err">Lỗi đồng bộ: '+e(s.lastError)+'</span>';return;} st.textContent='Đang đồng bộ… (lần thử '+s.attempts+')'+(s.lastError?' – '+s.lastError:'');}
};})();`,
    })),
  );

  app.post('/demo/api/exchange', async (req) => {
    const ticket = isRecord(req.body) ? String(req.body.ticket ?? '') : '';
    let ctx: LaunchContext;
    try {
      ctx = await verifyLaunchTicket(ticket, {
        hubUrl: cfg.baseUrl,
        gameId: GAME_ID,
        jwks: async (header) => keys.publicKeyFor(header.kid),
        markUsed: (jti) => store.create(COL.demoTickets, jti, { at: new Date().toISOString() }),
      });
    } catch (e) {
      throw new HttpError(401, 'bad_ticket', `Vé đăng nhập không hợp lệ: ${(e as Error).message}`);
    }
    const session = rid();
    await store.set(COL.demoSessions, session, { ctx: ctx as unknown as Record<string, unknown>, createdAt: new Date().toISOString() });
    return {
      session,
      name: ctx.name,
      email: ctx.email,
      role: ctx.role,
      course: ctx.context?.title,
      resource: ctx.resourceLink.title,
      activity: ctx.activity,
      gradable: !!ctx.gradeTarget,
    };
  });

  app.post('/demo/api/finish', async (req) => {
    const b = isRecord(req.body) ? req.body : {};
    const s = await store.get<{ ctx: LaunchContext }>(COL.demoSessions, String(b.session ?? ''));
    if (!s) throw new HttpError(404, 'no_session', 'Phiên chơi không tồn tại');
    if (!s.ctx.gradeTarget) throw new HttpError(400, 'not_gradable', 'Hoạt động không chấm điểm');
    const score = Number(b.score);
    if (!(score >= 0 && score <= 100)) throw new HttpError(400, 'bad_score', 'Điểm phải từ 0 đến 100');
    // The game backend calls the Hub's public API exactly like a real game would.
    return submitResult(
      { hubUrl: cfg.baseUrl, gameId: GAME_ID, secret: secrets.get(GAME_ID)!, fetch: (url, init) => deps.fetch(String(url).replace(cfg.baseUrl, cfg.selfUrl), init) },
      { gradeTarget: s.ctx.gradeTarget, attemptId: `${String(b.session)}`, score, maxScore: 100, comment: 'Demo game' },
    );
  });

  app.get('/demo/api/job', async (req) => {
    const q = req.query as Record<string, string>;
    const s = await store.get<{ ctx: LaunchContext }>(COL.demoSessions, q.session ?? '');
    const job = await store.get<SyncJob>(COL.jobs, q.id ?? '');
    if (!s || !job || job.gradeTarget !== s.ctx.gradeTarget) throw new HttpError(404, 'not_found', 'Không tìm thấy');
    return { status: job.status, attempts: job.attempts, lastError: job.lastError };
  });
}
