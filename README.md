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
