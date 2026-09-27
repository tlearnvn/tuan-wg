/*
 * Tuấn WireGuard - REST API & phục vụ giao diện web
 * Tác giả: Tuandethuong
 */
#ifndef TWG_API_H
#define TWG_API_H

#include "http.h"

void api_handle(http_req_t *r);
/* Hàm được gọi khi cần khởi động lại tiến trình (đổi cổng web...) */
void api_set_restart_cb(void (*cb)(void));

#endif
