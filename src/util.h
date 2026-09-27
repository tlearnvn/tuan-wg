/*
 * Tuấn WireGuard - tiện ích dùng chung
 * Tác giả: Tuandethuong
 */
#ifndef TWG_UTIL_H
#define TWG_UTIL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* ---------- string builder ---------- */
typedef struct {
    char *s;
    size_t len, cap;
} sb_t;

void sb_init(sb_t *b);
void sb_free(sb_t *b);
void sb_clear(sb_t *b);
void sb_reserve(sb_t *b, size_t extra);
void sb_append(sb_t *b, const char *s);
void sb_appendn(sb_t *b, const char *s, size_t n);
void sb_appendc(sb_t *b, char c);
void sb_printf(sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sb_vprintf(sb_t *b, const char *fmt, va_list ap);
char *sb_steal(sb_t *b);
void sb_html_escape(sb_t *b, const char *s);

/* ---------- logging ---------- */
enum { LOG_DEBUG = 0, LOG_INFO, LOG_WARN, LOG_ERROR };
extern int g_log_level;
void log_msg(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#define LOGD(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define LOGI(...) log_msg(LOG_INFO, __VA_ARGS__)
#define LOGW(...) log_msg(LOG_WARN, __VA_ARGS__)
#define LOGE(...) log_msg(LOG_ERROR, __VA_ARGS__)

/* ---------- memory ---------- */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t m);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

/* ---------- strings ---------- */
size_t str_copy(char *dst, const char *src, size_t size);
void str_trim(char *s);
bool str_starts(const char *s, const char *prefix);
bool str_ends(const char *s, const char *suffix);
bool str_eq(const char *a, const char *b);
bool str_ieq(const char *a, const char *b);
/* Xóa ký tự điều khiển (xuống dòng, tab...) - chống chèn cấu hình */
void str_strip_ctrl(char *s);
bool utf8_valid(const char *s);
size_t utf8_len(const char *s);
/* Cắt chuỗi UTF-8 an toàn (không cắt giữa ký tự) */
void utf8_truncate(char *s, size_t max_bytes);
/* Bỏ dấu tiếng Việt -> ASCII */
void ascii_fold(const char *in, char *out, size_t outsz);
/* Tạo tên file an toàn cho cấu hình WireGuard (tối đa maxlen ký tự) */
void safe_filename(const char *name, char *out, size_t outsz, size_t maxlen);
bool str_is_digits(const char *s);
int64_t str_to_i64(const char *s, int64_t def);

/* ---------- files ---------- */
char *file_read(const char *path, size_t *len);
int file_write_atomic(const char *path, const char *data, size_t len, int mode);
int file_append(const char *path, const char *data, size_t len, int mode);
int mkdir_p(const char *path, int mode);
bool file_exists(const char *path);
bool is_dir(const char *path);
int64_t file_mtime_ns(const char *path);
int64_t file_size(const char *path);

/* ---------- random & encoding ---------- */
int random_bytes(void *buf, size_t n);
uint32_t random_u32(void);
void hex_encode(const uint8_t *in, size_t n, char *out);
void random_hex(char *out, size_t nbytes);

/* ---------- time ---------- */
int64_t now_unix(void);
double now_mono(void);
void sleep_ms(int ms);
/* Ngày dân dụng từ số ngày kể từ 1970-01-01 */
void civil_from_days(int64_t z, int *y, int *m, int *d);
int64_t days_from_civil(int y, int m, int d);

/* ---------- exec (không qua shell) ---------- */
typedef struct {
    int status;   /* mã thoát, -1 nếu lỗi/timeout */
    char *out;    /* stdout + stderr */
    size_t outlen;
} cmd_result_t;

int run_cmd(const char *const argv[], const char *const extra_env[], const char *input,
            int timeout_ms, cmd_result_t *res);
void cmd_result_free(cmd_result_t *r);
char *find_in_path(const char *prog);
bool have_cmd(const char *prog);

#endif
