/*
 * Tuấn WireGuard - mô hình dữ liệu & lưu trữ (db.json)
 * Tác giả: Tuandethuong
 */
#ifndef TWG_STORE_H
#define TWG_STORE_H

#include <stdbool.h>
#include <stdint.h>

#include "json.h"
#include "util.h"

#define TWG_MAX_CLIENTS 4000
#define TWG_NAME_MAX 64     /* ký tự */
#define TWG_NOTE_MAX 200

typedef struct {
    char id[24];
    char name[256];
    char note[640];
    bool enabled;
    char disabled_reason[16]; /* "", "manual", "expired", "quota" */
    char private_key[48];
    char public_key[48];
    char preshared_key[48];
    char address[16];
    char address6[48];
    char dns[256];
    char allowed_ips[512];
    int keepalive; /* -1 = theo mặc định máy chủ */
    int mtu;       /* 0 = theo mặc định */
    int64_t created_at, updated_at;
    int64_t expires_at; /* 0 = không hết hạn */
    int64_t data_limit; /* byte, 0 = không giới hạn */
    bool limit_monthly;  /* reset hạn mức mỗi tháng */
} client_t;

typedef struct {
    char token[48];
    char client_id[24];
    int64_t created_at, expires_at;
    int max_downloads; /* 0 = không giới hạn */
    int downloads;
} share_t;

typedef struct {
    /* WireGuard */
    char iface[16];
    int listen_port;
    char private_key[48];
    char public_key[48];
    char address[48];  /* 10.8.0.1/24 */
    bool ipv6;
    char address6[64]; /* fd42:42:42::1/64 */
    char endpoint[256];
    char dns[256];
    int mtu;
    int keepalive;
    char allowed_ips[512];
    char wan_iface[32];
    char post_up[2048];
    char post_down[2048];
    bool client_isolation;
    bool use_psk;
    int tz_offset; /* phút lệch so với UTC, VN = 420 */
    /* Web */
    char web_listen[64];
    int web_port;
    int session_hours;
    /* Quản trị */
    char admin_user[64];
    char admin_hash[192];
    char totp_secret[64];
    bool totp_enabled;
    int64_t installed_at;
} settings_t;

typedef struct {
    settings_t s;
    client_t *clients;
    int nclients, capclients;
    share_t *shares;
    int nshares, capshares;
    int64_t file_sig;
} db_t;

void db_defaults(db_t *db);
void db_free(db_t *db);
int db_from_json(db_t *db, const json_t *j, char *err, size_t errsz);
void db_to_json(const db_t *db, sb_t *out);
/* 0 = ok, 1 = chưa có file, -1 = lỗi */
int db_load_file(db_t *db, const char *path, char *err, size_t errsz);
int db_save_file(db_t *db, const char *path);

client_t *db_client_by_id(db_t *db, const char *id);
int db_client_index(const db_t *db, const char *id);
client_t *db_client_by_name(db_t *db, const char *name);
client_t *db_client_by_pubkey(db_t *db, const char *pk);
client_t *db_client_find(db_t *db, const char *id_or_name);
client_t *db_client_add(db_t *db);
void db_client_remove(db_t *db, int idx);

int db_subnet(const db_t *db, uint32_t *network, int *prefix, uint32_t *server_ip);
int db_alloc_ipv4(const db_t *db, char *out, size_t n);
int db_ipv6_for(const db_t *db, const char *ipv4, char *out, size_t n);
/* Đánh lại địa chỉ khi đổi dải mạng */
void db_renumber(db_t *db, const char *old_address);
void db_refresh_ipv6(db_t *db);

share_t *db_share_by_token(db_t *db, const char *token);
share_t *db_share_add(db_t *db);
void db_share_remove(db_t *db, int idx);
void db_shares_prune(db_t *db, int64_t now);
void db_client_shares_remove(db_t *db, const char *client_id);

/* Kiểm tra & áp dụng dữ liệu người dùng từ JSON (API/CLI) */
/* c có thể là bản sao; self = chỉ số của người dùng trong db (-1 nếu chưa thêm) */
int client_apply_json(db_t *db, client_t *c, int self, const json_t *in, bool creating, char *err,
                      size_t errsz);
int client_init_new(db_t *db, client_t *c, char *err, size_t errsz);
/* flags trả về: bit0 = cần khởi động lại WireGuard, bit1 = cần khởi động lại web */
#define APPLY_RESTART_WG 1
#define APPLY_RESTART_WEB 2
int settings_apply_json(db_t *db, const json_t *in, int *flags, char *err, size_t errsz);

bool client_expired(const client_t *c, int64_t now);

#endif
