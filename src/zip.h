/*
 * Tuấn WireGuard - tạo file ZIP (phương thức store, không nén)
 * Tác giả: Tuandethuong
 */
#ifndef TWG_ZIP_H
#define TWG_ZIP_H

#include <stdint.h>
#include <time.h>

#include "util.h"

typedef struct {
    sb_t data;
    sb_t central;
    int count;
} zip_t;

void zip_init(zip_t *z);
void zip_add(zip_t *z, const char *name, const void *data, size_t len, time_t mtime);
/* Kết thúc và chuyển dữ liệu ZIP sang out (z được giải phóng) */
void zip_finish(zip_t *z, sb_t *out);

#endif
