# CLAUDE.md - Tuấn WireGuard

Giao diện web tiếng Việt quản lý máy chủ WireGuard, viết bằng C (một binary tĩnh duy nhất,
giao diện web nhúng sẵn). Tác giả: **Tuandethuong**. Repo: https://github.com/tlearnvn/tuan-wg

## Lệnh thường dùng

```bash
make                 # build bản phát triển -> build/tuan-wg
make test            # kiểm thử đơn vị (ASan + UBSan)
make static          # binary tĩnh musl -> build/static/tuan-wg (cần musl-tools)
make deb dist        # đóng gói dist/*.deb và dist/*.tar.gz
make demo            # chạy thử giao diện với dữ liệu mẫu (admin/admin) tại 127.0.0.1:51821
sudo tests/e2e_wireguard.sh build/tuan-wg     # kiểm thử VPN thật (root + wireguard-go/kernel)
NODE_PATH=$(npm root -g) node scripts/screenshots.cjs http://127.0.0.1:18080 docs/images   # chụp ảnh tài liệu
```

## Cấu trúc

- `src/main.c` - điểm vào, lệnh `serve`; `src/cli.c` - lệnh client/passwd/status/backup; `src/installer.c` - install/uninstall/service
- `src/http.c` - máy chủ HTTP/1.1 tự viết; `src/api.c` - REST API + phục vụ file tĩnh nhúng
- `src/store.c` - mô hình dữ liệu `db.json` + kiểm tra đầu vào; `src/app.c` - khóa (mutex + flock) và tự nạp lại khi CLI sửa file
- `src/wg.c` - sinh `wg0.conf`, `wg syncconf`, `wg-quick`, đọc `wg show dump`; `src/stats.c` - bộ thu thập thống kê chạy nền 2 giây/lần
- `src/auth.c` - PBKDF2, phiên, chặn dò mật khẩu, TOTP; `src/crypto.c` - SHA-256/SHA-1/HMAC/X25519/Base64/Base32 tự viết
- `src/qrcodegen.*` - thư viện QR của Nayuki (MIT, không sửa); `src/demo.c` - chế độ demo
- `web/` - SPA JavaScript thuần (ES modules, không build step), được `tools/embed.c` nhúng vào binary
- `packaging/` - unit systemd, script .deb/.tar.gz; `scripts/install.sh` - cài 1 lệnh từ GitHub Releases

## Quy ước

- Toàn bộ chữ hiển thị cho người dùng (web, CLI, log) viết **tiếng Việt có dấu**.
- C11, 4 dấu cách, không dùng `system()`/shell cho dữ liệu người dùng - chỉ `run_cmd()` với argv.
  Mọi chuỗi từ người dùng phải qua `store.c` (bỏ ký tự điều khiển, kiểm tra CIDR/DNS/host) trước khi ghi vào `wg0.conf`.
- Giao diện: chèn nội dung bằng `h()`/`add()` trong `web/js/ui.js` (textContent) để chống XSS; không dùng `Element.append` với giá trị có thể `null`.
- Không giữ `g_lock` khi gọi `wg_apply()` (hàm tự khóa bên trong).

## Phiên bản & CHANGELOG (bắt buộc)

- Commit theo **Conventional Commits**: `feat: ...` (tính năng, tăng minor), `fix: ...` (sửa lỗi, tăng patch),
  `feat!: ...` hoặc có `BREAKING CHANGE` (tăng major); `docs:`, `chore:`, `refactor:`, `perf:`, `test:`...
- Git hook `.githooks/post-commit` tự tăng `VERSION` và thêm mục vào `CHANGELOG.md` khi commit chạm `src/`, `web/`,
  `tools/`, `packaging/`, `Makefile` hoặc `scripts/install.sh` (hook được bật tự động bởi `.claude/settings.json`;
  bật thủ công: `scripts/setup-hooks.sh`).
- Nếu hook chưa bật, sau khi commit hãy chạy: `scripts/bump-version.sh auto --last --amend`.
- Ghi chú viết tay có thể đặt dưới `## [Chưa phát hành]` trong CHANGELOG - sẽ được gộp vào phiên bản kế tiếp.
- Trên `main`, GitHub Actions (`release.yml`) tự gắn tag `vX.Y.Z` và tạo Release kèm `.deb`/`.tar.gz`.
