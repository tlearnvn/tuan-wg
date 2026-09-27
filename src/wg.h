/*
 * Tuấn WireGuard - điều khiển WireGuard (wg, wg-quick)
 * Tác giả: Tuandethuong
 */
#ifndef TWG_WG_H
#define TWG_WG_H

#include <stdbool.h>
#include <stdint.h>

#include "store.h"
#include "util.h"

typedef struct {
    char public_key[48];
    char endpoint[64];
    int64_t handshake;
    uint64_t rx, tx;
} wg_peer_t;

typedef struct {
    bool up;
    int listen_port;
    char public_key[48];
    wg_peer_t *peers;
    int npeers;
} wg_status_t;

int wg_dump(const char *iface, wg_status_t *st, char *err, size_t errsz);
void wg_status_free(wg_status_t *st);

void wg_auto_postup(const settings_t *s, char *out, size_t n);
void wg_auto_postdown(const settings_t *s, char *out, size_t n);
/* strip = chỉ các khóa mà `wg syncconf` hiểu */
void wg_build_server_conf(const db_t *db, sb_t *out, bool strip);
/* with_comment = thêm dòng chú thích đầu file (không dùng cho QR) */
void wg_build_client_conf(const db_t *db, const client_t *c, sb_t *out, bool with_comment);
void wg_endpoint_string(const settings_t *s, char *out, size_t n);

/* Ghi cấu hình và áp dụng. restart = khởi động lại interface (đổi cổng, dải IP...) */
int wg_apply(bool restart, char *err, size_t errsz);
int wg_down(char *err, size_t errsz);
bool wg_tools_installed(void);
const char *wg_version(void);
bool wg_iface_up(const char *iface);

#endif
