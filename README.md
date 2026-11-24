# UniGame Hub

Cổng LTI 1.3 Advantage nối Moodle 4.5 với các game trên GCP/Firebase: **đăng nhập một lần** (SSO) và **đồng bộ điểm** về Sổ điểm Moodle (AGS). Không sửa logic game; mỗi game chỉ thêm một adapter nhỏ dùng `sdk/`.

```
Moodle ──LTI 1.3 (OIDC, Deep Linking, AGS)──► Hub ──vé đăng nhập (JWT 2 phút, dùng 1 lần)──► Game adapter
   ▲                                            │                                               │
   └──────────── AGS score (hàng đợi, retry) ◄──┴──── POST /api/v1/results (JWT HS256) ◄────────┘
```

## Chạy local (dev)

```bash
npm install
npm test            # 10 test: launch, chữ ký, nonce/replay, deep linking, chống trùng/ghi đè điểm, retry
npm run dev         # http://localhost:8787 — trang quản trị: /admin (đăng nhập bằng ADMIN_TOKEN)
```

Dữ liệu dev nằm trong `.data/` (khóa ký, bí mật game, store JSON). `.dev/` chứa thông tin Moodle local và tài khoản test. Cả hai đều không đưa vào Git.

## Kết nối một Moodle

1. Đăng ký tool trong Moodle (chạy trong thư mục gốc Moodle):
   `php <hub>/scripts/moodle/register_tool.php --hub=<HUB_URL> --pem=<public.pem>` (hoặc `--keyset` khi Moodle gọi được Hub qua HTTPS).
   Script in ra JSON gồm issuer, client id, deployment id.
2. Khai báo Moodle đó với Hub:
   `node scripts/register-platform.ts platform.json --tenant=<ma-truong> --tenant-name="..." --hub=<HUB_URL> [--games=demo,k26game1]`
3. Trong khóa học: *Thêm hoạt động → UniGame Hub → Chọn nội dung* → chọn game → Lưu.

Có thể khai báo thủ công qua giao diện Moodle; thông số xem tại trang quản trị `/admin/setup`.

## Tích hợp một game (adapter)

Phía backend của game (không làm trong trình duyệt):

```ts
import { verifyLaunchTicket, submitResult } from './unigame-sdk';
// 1) Trang /lti-launch đọc #ticket=... rồi POST lên backend:
const ctx = await verifyLaunchTicket(ticket, { hubUrl, gameId: 'k26game1', markUsed });
//    → tìm/tạo user theo ctx.hubUserId, ghi danh lớp theo ctx.context, trả Firebase custom token
// 2) Khi chốt điểm (hoặc giảng viên chấm lại):
await submitResult({ hubUrl, gameId: 'k26game1', secret }, {
  gradeTarget: ctx.gradeTarget, attemptId, score, maxScore, occurredAt });
```

Hub bảo đảm: điểm cũ không đè điểm mới; gửi trùng không tạo điểm trùng; game A không ghi điểm được cho hoạt động của game B; lỗi mạng được thử lại (backoff, tối đa 8 lần), có nhật ký kiểm tra.

## Môi trường

| | DEV | STAGING / PROD (Cloud Run, project `gamehub-514101`) |
|---|---|---|
| Store | `HUB_STORE=file` | Firestore |
| Khóa ký | tự sinh trong `.data/` | `HUB_SIGNING_KEYS` từ Secret Manager |
| Bí mật game | tự sinh | `GAME_SECRET_<ID>` từ Secret Manager |
| Admin API | chỉ localhost | `ADMIN_TOKEN` (header `x-admin-token`) |
| Trang quản trị `/admin` | đăng nhập (localhost) | đăng nhập bằng `ADMIN_TOKEN` → cookie phiên 8 giờ |

### Trang quản trị (`/admin`)
Đăng nhập bằng mã quản trị (`ADMIN_TOKEN`, secret `hub-admin-token`). Phiên lưu trên server (collection `admin_sessions`, chỉ lưu bản băm của mã phiên), cookie `HttpOnly; Secure; SameSite=Strict; Path=/admin`, hết hạn sau 8 giờ. Mọi form có mã CSRF; nhập sai mã 10 lần trong 15 phút bị khóa tạm thời; đăng nhập được ghi nhật ký.
- **Tổng quan**: số trường, LMS, game đang bật, điểm đang chờ / lỗi; lượt gửi điểm gần đây; nút chạy gửi điểm ngay.
- **Gửi điểm**: lọc theo trạng thái, xem lỗi gần nhất, **Gửi lại** lượt bị lỗi.
- **Trường**: tạo trường, chọn game được dùng, tạm dừng.
- **Moodle / LMS**, **Game**, **Cấu hình LTI**, **Nhật ký**: chỉ xem.

Xem `.env.example`.

## Deploy

- Mỗi PR: GitHub Actions chạy `typecheck` + `test` (`.github/workflows/deploy.yml`).
- Mỗi commit vào `main`: test → build image (tag = commit SHA) → push Artifact Registry → `gcloud run deploy --image` → smoke test.
  Revision được gắn nhãn `commit-sha`, xem bằng:
  `gcloud run revisions list --service unigame-hub --region asia-southeast1 --project gamehub-514101 --format="table(metadata.name,metadata.labels.commit-sha)"`
- CI chỉ đổi image: biến môi trường (`GAMES_ENABLED`, `GAME_LAUNCH_URL_*`) và secret giữ nguyên trên service.
  Bản chụp cấu hình: `deploy/cloudrun-service.yaml`. Đổi env/secret: `gcloud run services update unigame-hub --update-env-vars …`.
- Xác thực GCP: Workload Identity Federation (pool `github`, provider `unigamehub`, chỉ nhận repo này trên `refs/heads/main`),
  tài khoản dịch vụ `github-deployer` (run.developer, artifactregistry.writer trên repo `cloud-run-source-deploy`, actAs `unigame-hub`).
- Rollback: `gcloud run services update-traffic unigame-hub --region asia-southeast1 --project gamehub-514101 --to-revisions=<revision>=100`.
- `deploy/deploy-cloudrun.sh` chỉ dùng khi dựng service mới: nó dùng `--set-env-vars` nên sẽ ghi đè toàn bộ env hiện có.

## Tài khoản quản trị

- Trang `/admin` đăng nhập bằng **tên đăng nhập + mật khẩu** (scrypt, Firestore `admin_users`). Phiên 8 giờ, CSRF trên mọi form.
- Vai trò: **Chủ hệ thống** (`owner`, quản lý tài khoản ở `/admin/users`) và **Quản trị viên** (`admin`, mọi chức năng còn lại).
- Tài khoản mới nhận mật khẩu tạm (hiện một lần) và phải đổi ở lần đăng nhập đầu. Sai mật khẩu 5 lần → khóa 15 phút; sai 10 lần/IP/15 phút → chặn IP.
- Luôn còn ít nhất một Chủ hệ thống hoạt động; không tự hạ quyền/vô hiệu hóa chính mình.
- **Tài khoản đầu tiên / khẩn cấp:** mở `/admin/login?mode=token`, nhập `ADMIN_TOKEN` (Secret Manager `hub-admin-token`), vào **Tài khoản** để tạo.
  Hoặc dòng lệnh: `ADMIN_TOKEN=… npm run create-admin -- --username=<ten> --role=owner --hub=<URL>`.
- API JSON `/api/v1/admin/*` vẫn dùng header `x-admin-token`.
