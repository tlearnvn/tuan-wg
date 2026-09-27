/*
 * Tuấn WireGuard - xác thực: mật khẩu, phiên đăng nhập, chống dò mật khẩu, 2FA
 * Tác giả: Tuandethuong
 */
#ifndef TWG_AUTH_H
#define TWG_AUTH_H

#include <stdbool.h>
#include <stdint.h>

#include "json.h"

#define TWG_PBKDF2_ITER 210000

int auth_hash_password(const char *pw, char *out, size_t n);
bool auth_verify_password(const char *pw, const char *hash);
/* Sinh mật khẩu ngẫu nhiên dễ đọc (không có ký tự dễ nhầm) */
void auth_random_password(char *out, size_t len);

/* ---------- phiên đăng nhập ---------- */
void auth_sessions_load(const char *path);
void auth_sessions_save(void);
/* token_out: 64 ký tự hex + NUL */
int auth_session_create(const char *ip, const char *ua, int hours, char token_out[65]);
bool auth_session_valid(const char *token);
void auth_session_destroy(const char *token);
int auth_sessions_revoke_others(const char *keep_token);
void auth_sessions_revoke_all(void);
void auth_sessions_json(jw_t *w, const char *current_token);

/* ---------- giới hạn đăng nhập sai ---------- */
/* trả về số giây phải chờ (0 = được phép thử) */
int auth_rate_check(const char *ip);
void auth_rate_fail(const char *ip);
void auth_rate_success(const char *ip);

/* ---------- TOTP 2FA ---------- */
void auth_totp_new_secret(char out[40]);
void auth_totp_uri(const char *secret, const char *user, char *out, size_t n);
/* Kiểm tra mã và chống dùng lại cùng một mã */
bool auth_totp_check(const char *secret, const char *code);

#endif
