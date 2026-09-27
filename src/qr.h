/*
 * Tuấn WireGuard - mã QR (SVG / terminal) dựa trên thư viện Nayuki (MIT)
 * Tác giả: Tuandethuong
 */
#ifndef TWG_QR_H
#define TWG_QR_H

#include <stdio.h>

#include "util.h"

int qr_svg(const char *text, sb_t *out);
int qr_print_terminal(const char *text, FILE *f);
/* Xuất ảnh PBM (P1) - dùng cho kiểm thử với zbarimg */
int qr_pbm(const char *text, int scale, sb_t *out);

#endif
