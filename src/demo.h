/*
 * Tuấn WireGuard - chế độ trình diễn (dữ liệu mẫu, mô phỏng lưu lượng)
 * Tác giả: Tuandethuong
 */
#ifndef TWG_DEMO_H
#define TWG_DEMO_H

#include "wg.h"

/* Tạo dữ liệu mẫu nếu chưa có người dùng (gọi trước khi chạy server) */
void demo_seed(void);
int demo_dump(wg_status_t *st);

#endif
