/*
 * Tuấn WireGuard - các lệnh dòng lệnh (CLI)
 * Tác giả: Tuandethuong
 */
#ifndef TWG_CLI_H
#define TWG_CLI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int cmd_client(int argc, char **argv);
int cmd_passwd(int argc, char **argv);
int cmd_status(int argc, char **argv);
int cmd_backup(int argc, char **argv);
int cmd_restore(int argc, char **argv);
int cmd_reset_2fa(int argc, char **argv);
int cmd_install(int argc, char **argv);
int cmd_uninstall(int argc, char **argv);
int cmd_service(int argc, char **argv);

/* tiện ích dùng chung cho CLI */
void cli_prompt(const char *q, const char *def, char *out, size_t n);
bool cli_yesno(const char *q, bool def);
int cli_read_password(const char *q, char *out, size_t n);
void fmt_bytes(uint64_t b, char *out, size_t n);
bool cli_is_root(void);
/* Đảm bảo có thư mục dữ liệu, nạp db. must_exist: báo lỗi nếu chưa cài đặt */
int cli_open_db(bool must_exist);
/* Khởi tạo lần đầu: khóa máy chủ + mật khẩu quản trị (in ra nếu tạo mới) */
bool cli_first_run_init(char *generated_password, size_t n);

/* màu terminal */
extern const char *C_RESET, *C_BOLD, *C_DIM, *C_GREEN, *C_RED, *C_YELLOW, *C_CYAN, *C_MAGENTA;
void cli_colors_init(void);

#endif
