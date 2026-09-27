/*
 * Tuấn WireGuard - nhật ký hoạt động (audit log), lưu dạng JSON mỗi dòng
 * Tác giả: Tuandethuong
 */
#include "audit.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#define AUDIT_MAX_BYTES (2 * 1024 * 1024)
#define AUDIT_KEEP_LINES 5000

static char g_audit_path[320];
static pthread_mutex_t g_audit_lock = PTHREAD_MUTEX_INITIALIZER;

void audit_init(const char *path)
{
    str_copy(g_audit_path, path, sizeof g_audit_path);
}

static void audit_trim_locked(void)
{
    size_t len;
    char *data = file_read(g_audit_path, &len);
    if (!data)
        return;
    int lines = 0;
    for (size_t i = 0; i < len; i++)
        if (data[i] == '\n')
            lines++;
    if (lines > AUDIT_KEEP_LINES) {
        int skip = lines - AUDIT_KEEP_LINES;
        char *p = data;
        while (skip > 0 && (p = strchr(p, '\n')) != NULL) {
            p++;
            skip--;
        }
        if (p)
            file_write_atomic(g_audit_path, p, len - (size_t)(p - data), 0600);
    }
    free(data);
}

void audit_log(const char *ip, const char *action, const char *fmt, ...)
{
    if (!g_audit_path[0])
        return;
    char detail[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof detail, fmt, ap);
    va_end(ap);
    str_strip_ctrl(detail);
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    jw_obj(&w);
    jw_kint(&w, "t", now_unix());
    jw_kstr(&w, "ip", ip ? ip : "");
    jw_kstr(&w, "action", action);
    jw_kstr(&w, "detail", detail);
    jw_obj_end(&w);
    sb_appendc(&b, '\n');
    pthread_mutex_lock(&g_audit_lock);
    file_append(g_audit_path, b.s, b.len, 0600);
    if (file_size(g_audit_path) > AUDIT_MAX_BYTES)
        audit_trim_locked();
    pthread_mutex_unlock(&g_audit_lock);
    sb_free(&b);
    LOGI("[audit] %s %s %s", ip ? ip : "-", action, detail);
}

void audit_json(jw_t *w, int limit, const char *filter)
{
    pthread_mutex_lock(&g_audit_lock);
    size_t len = 0;
    char *data = file_read(g_audit_path, &len);
    pthread_mutex_unlock(&g_audit_lock);
    jw_arr(w);
    if (data) {
        int count = 0;
        /* duyệt từ cuối file lên */
        size_t end = len;
        while (end > 0 && count < limit) {
            size_t start = end;
            if (start > 0 && data[start - 1] == '\n')
                start--;
            size_t line_end = start;
            while (start > 0 && data[start - 1] != '\n')
                start--;
            if (line_end > start) {
                char save = data[line_end];
                data[line_end] = 0;
                const char *line = data + start;
                bool match = !filter || !*filter || strcasestr(line, filter) != NULL;
                if (match && line[0] == '{') {
                    json_t *j = json_parse(line, line_end - start, NULL, 0);
                    if (j) {
                        jw_obj(w);
                        jw_kint(w, "t", json_int(j, "t", 0));
                        jw_kstr(w, "ip", json_str(j, "ip", ""));
                        jw_kstr(w, "action", json_str(j, "action", ""));
                        jw_kstr(w, "detail", json_str(j, "detail", ""));
                        jw_obj_end(w);
                        json_free(j);
                        count++;
                    }
                }
                data[line_end] = save;
            }
            end = start;
        }
        free(data);
    }
    jw_arr_end(w);
}
