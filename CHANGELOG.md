# Nhật ký thay đổi

Mọi thay đổi đáng chú ý của **Tuấn WireGuard** được ghi lại tại đây.
Định dạng theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/), phiên bản theo [Semantic Versioning](https://semver.org/lang/vi/).
Phiên bản được **tự động tăng** và mục mới được **tự động ghi** mỗi khi mã nguồn thay đổi
(git hook `.githooks/post-commit` và GitHub Actions `release.yml`).

## [Chưa phát hành]

## [1.0.0] - 2026-09-27

### ✨ Tính năng mới
- **Giao diện web tiếng Việt** hiện đại, có chế độ sáng/tối, tương thích điện thoại, font Be Vietnam Pro nhúng sẵn
- **Tổng quan**: số người dùng, số thiết bị online, dung lượng hôm nay/tháng này, biểu đồ băng thông thời gian thực (cập nhật mỗi 2 giây), biểu đồ 7 ngày, top người dùng, tài nguyên hệ thống (CPU, RAM, ổ đĩa)
- **Quản lý người dùng (CRUD)**: thêm, sửa, xóa, bật/tắt tức thì không ảnh hưởng người khác (`wg syncconf`), tìm kiếm, lọc, sắp xếp, thao tác hàng loạt
- **Xuất cấu hình**: tải file `.conf`, mã QR để quét bằng điện thoại, tải tất cả cấu hình dạng `.zip`
- **Link chia sẻ có thời hạn** (1 giờ - 7 ngày): người dùng mở link để quét QR/tải cấu hình mà không cần đăng nhập, có thể thu hồi
- **Thống kê dung lượng**: theo giờ, ngày, tháng; theo từng người dùng; tốc độ hiện tại; kết nối gần nhất; IP thật của thiết bị; xuất CSV
- **Giới hạn sử dụng**: ngày hết hạn và hạn mức dung lượng (tổng hoặc làm mới hằng tháng) - tự khóa khi vượt, tự mở khi gia hạn/sang tháng mới
- **Tùy chọn nâng cao cho từng người dùng**: IP cố định, định tuyến toàn bộ/chỉ mạng VPN/tùy chỉnh, DNS, Keepalive, MTU, tạo lại khóa, PresharedKey
- **Cài đặt máy chủ** trên web: Endpoint (tự phát hiện IP công khai), cổng, dải IPv4, IPv6, DNS, MTU, card mạng WAN, cách ly client, múi giờ thống kê, PostUp/PostDown tùy chỉnh
- **Bảo mật**: mật khẩu băm PBKDF2-SHA256, xác thực 2 lớp TOTP (Google Authenticator), chặn dò mật khẩu, chống CSRF, cookie HttpOnly/SameSite, quản lý và đăng xuất phiên từ xa
- **Nhật ký hoạt động**: ghi lại đăng nhập, thao tác quản trị, sự kiện tự động khóa/mở khóa
- **Sao lưu & khôi phục** toàn bộ dữ liệu bằng một file JSON (web hoặc dòng lệnh)
- **Trình cài đặt** `tuan-wg install`: cài gói phụ thuộc, bật IP forwarding, mở tường lửa (ufw/firewalld), nhập cấu hình WireGuard có sẵn, tạo dịch vụ systemd **tự khởi động cùng máy chủ**
- **Dòng lệnh đầy đủ**: `client add/list/show/del/enable/disable` (in mã QR ra terminal), `passwd`, `reset-2fa`, `status`, `backup`, `restore`, `service`, `uninstall`
- **Gói cài đặt** `.deb` cho Debian/Ubuntu và bản `.tar.gz` chạy mọi bản Linux amd64 (binary tĩnh ~730 KB, không phụ thuộc thư viện)
- **Chế độ demo** (`--demo`) với dữ liệu mẫu để dùng thử giao diện
- **Tự động tăng phiên bản & ghi CHANGELOG** theo Conventional Commits; GitHub Actions tự phát hành bản mới kèm file cài đặt
