/*
 * Tuấn WireGuard - nhật ký hoạt động (audit log)
 * Tác giả: Tuandethuong
 */
#ifndef TWG_AUDIT_H
#define TWG_AUDIT_H

#include "json.h"

void audit_init(const char *path);
void audit_log(const char *ip, const char *action, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
/* Ghi danh sách mục mới nhất trước; filter rỗng = tất cả */
void audit_json(jw_t *w, int limit, const char *filter);

#endif
