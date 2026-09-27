/*
 * Tuấn WireGuard - thống kê dung lượng & bộ thu thập chạy nền
 * Tác giả: Tuandethuong
 */
#ifndef TWG_STATS_H
#define TWG_STATS_H

#include <stdbool.h>
#include <stdint.h>

#include "json.h"
#include "store.h"

#define ST_HOURS 168  /* 7 ngày theo giờ (toàn máy chủ) */
#define ST_DAYS 400   /* theo ngày (toàn máy chủ) */
#define ST_CDAYS 120  /* theo ngày cho từng người dùng */
#define ST_CHOURS 48  /* theo giờ cho từng người dùng */
#define ST_LIVE 150   /* mẫu thời gian thực (2 giây/mẫu = 5 phút) */
#define ST_INTERVAL_MS 2000
#define ONLINE_WINDOW 180

typedef struct {
    int32_t k;
    uint64_t rx, tx;
} bucket_t;

typedef struct {
    bucket_t *b;
    int n, cap;
} series_t;

typedef struct {
    char id[24];
    uint64_t rx, tx;   /* tổng tích lũy (rx = máy chủ nhận = người dùng tải lên) */
    uint64_t prx, ptx; /* trong tháng hiện tại */
    int32_t pkey;
    uint64_t lrx, ltx; /* bộ đếm WireGuard lần trước */
    char lpk[48];
    int64_t handshake;
    char endpoint[64];
    double rate_rx, rate_tx;
    int64_t last_active;
    bool present;
    series_t days, hours;
} cstat_t;

typedef struct {
    int64_t t;
    double rx, tx;
} live_t;

typedef struct {
    cstat_t *c;
    int n, cap;
    series_t days, hours;
    live_t live[ST_LIVE];
    int live_n, live_pos;
    bool wg_up;
    int wg_listen_port;
    char wg_error[512];
    double cpu;
    uint64_t cpu_total, cpu_idle;
    double rate_rx, rate_tx;
    int64_t started_at;
    int64_t last_sample;
} stats_t;

extern stats_t g_stats;

int32_t key_hour(int64_t t, int tz);
int32_t key_day(int64_t t, int tz);
int32_t key_month(int64_t t, int tz);
void key_day_label(int32_t k, char *out, size_t n);

void series_add(series_t *s, int32_t key, uint64_t rx, uint64_t tx, int keep);
void series_sum_range(const series_t *s, int32_t from, int32_t to, uint64_t *rx, uint64_t *tx);

/* Các hàm dưới đây yêu cầu đang giữ g_lock */
cstat_t *stats_client(const char *id, bool create);
void stats_remove_client(const char *id);
void stats_reset_client(const char *id);
uint64_t stats_used(const client_t *c, const cstat_t *cs, int64_t now, int tz);
bool stats_online(const client_t *c, const cstat_t *cs, int64_t now);
void stats_client_json(jw_t *w, const client_t *c, int64_t now, int tz);
void stats_to_json(sb_t *out);
int stats_from_json(const json_t *j);

int stats_load(const char *path);
int stats_save(const char *path); /* tự khóa */

void collector_start(void);
void collector_stop(void);
/* Đánh thức bộ thu thập để kiểm tra ngay (sau khi thay đổi cấu hình) */
void collector_poke(void);

#endif
