/*
 * Tuấn WireGuard - chế độ trình diễn (dữ liệu mẫu, mô phỏng lưu lượng)
 * Tác giả: Tuandethuong
 */
#include "demo.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"
#include "auth.h"
#include "crypto.h"
#include "stats.h"

typedef struct {
    char pk[48];
    uint64_t rx, tx;
    double base;  /* byte/giây trung bình (tải xuống) */
    double phase;
    bool online;
    int64_t hs_fixed;
    char ep[48];
    double last;
} demo_peer_t;

static demo_peer_t g_dp[512];
static int g_ndp = 0;
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;

static uint64_t rng(void)
{
    g_rng ^= g_rng >> 12;
    g_rng ^= g_rng << 25;
    g_rng ^= g_rng >> 27;
    return g_rng * 0x2545F4914F6CDD1DULL;
}

static double frand(void)
{
    return (double)(rng() >> 11) * (1.0 / 9007199254740992.0);
}

static uint32_t hash_str(const char *s)
{
    uint32_t h = 2166136261u;
    for (; *s; s++) {
        h ^= (uint8_t)*s;
        h *= 16777619u;
    }
    return h;
}

static demo_peer_t *dp_get(const client_t *c)
{
    for (int i = 0; i < g_ndp; i++)
        if (strcmp(g_dp[i].pk, c->public_key) == 0)
            return &g_dp[i];
    if (g_ndp >= (int)ARRAY_LEN(g_dp))
        return NULL;
    demo_peer_t *d = &g_dp[g_ndp++];
    memset(d, 0, sizeof *d);
    str_copy(d->pk, c->public_key, sizeof d->pk);
    uint32_t h = hash_str(c->id);
    d->online = true;
    d->base = 40000 + (h % 900) * 1000.0;
    d->phase = (h % 628) / 100.0;
    snprintf(d->ep, sizeof d->ep, "203.0.113.%u:%u", 10 + h % 200, 40000 + (h >> 8) % 20000);
    d->last = 0; /* lần lấy mẫu đầu tiên chưa có lưu lượng */
    return d;
}

int demo_dump(wg_status_t *st)
{
    memset(st, 0, sizeof *st);
    st->up = true;
    int64_t now = now_unix();
    double tm = now_mono();
    app_rlock();
    st->listen_port = g_db.s.listen_port;
    str_copy(st->public_key, g_db.s.public_key, sizeof st->public_key);
    st->peers = xcalloc((size_t)g_db.nclients + 1, sizeof(wg_peer_t));
    for (int i = 0; i < g_db.nclients; i++) {
        client_t *c = &g_db.clients[i];
        if (!c->enabled)
            continue;
        demo_peer_t *d = dp_get(c);
        if (!d)
            continue;
        wg_peer_t *p = &st->peers[st->npeers++];
        str_copy(p->public_key, c->public_key, sizeof p->public_key);
        double dt = d->last > 0 ? tm - d->last : 0;
        if (dt < 0)
            dt = 0;
        d->last = tm;
        if (d->online) {
            double f = 0.55 + 0.45 * sin(tm / 17.0 + d->phase) + 0.35 * frand();
            if (frand() < 0.08)
                f *= 3.5; /* thỉnh thoảng tăng đột biến */
            d->tx += (uint64_t)(d->base * f * dt);
            d->rx += (uint64_t)(d->base * 0.18 * f * dt);
            p->handshake = now - (int64_t)((now + (int64_t)(d->phase * 10)) % 115);
            str_copy(p->endpoint, d->ep, sizeof p->endpoint);
        } else {
            p->handshake = d->hs_fixed;
            if (d->hs_fixed)
                str_copy(p->endpoint, d->ep, sizeof p->endpoint);
        }
        p->rx = d->rx;
        p->tx = d->tx;
    }
    app_runlock();
    return 0;
}

typedef struct {
    const char *name;
    const char *note;
    double gb_day;   /* dung lượng trung bình mỗi ngày */
    int online;      /* 1 = online, 0 = offline */
    int offline_min; /* phút kể từ lần bắt tay cuối */
    const char *state; /* "", "manual", "expired", "quota" */
    int expire_days;   /* >0: còn N ngày; <0: đã hết hạn N ngày trước */
    double limit_gb;
    int monthly;
} demo_spec_t;

static const demo_spec_t SPECS[] = {
    {"Laptop Tuấn", "MacBook làm việc", 6.5, 1, 0, "", 0, 0, 0},
    {"iPhone Tuấn", "Điện thoại cá nhân", 1.8, 1, 0, "", 0, 0, 0},
    {"iPad Mai", "Học online", 1.2, 1, 0, "", 0, 50, 1},
    {"Văn phòng Quận 1", "Máy chủ văn phòng", 4.2, 1, 0, "", 0, 0, 0},
    {"PC Gaming Nam", "", 3.1, 0, 185, "", 0, 0, 0},
    {"Điện thoại Bố", "Samsung A54", 0.6, 1, 0, "", 20, 0, 0},
    {"Máy tính Lan", "Tạm khóa theo yêu cầu", 0.9, 0, 4320, "manual", 0, 0, 0},
    {"Khách - Hùng", "Tài khoản dùng thử 7 ngày", 0.4, 0, 2880, "expired", -2, 0, 0},
    {"Tablet Minh", "Gói 20 GB/tháng", 1.1, 0, 600, "quota", 0, 20, 1},
    {"Smart TV phòng khách", "Xem Netflix", 2.4, 1, 0, "", 0, 0, 0},
    {"Camera an ninh", "Truy cập từ xa", 0.3, 1, 0, "", 365, 0, 0},
    {"Laptop Hoa", "Kế toán", 0.8, 0, 42, "", 90, 100, 1},
};

void demo_seed(void)
{
    app_begin();
    settings_t *s = &g_db.s;
    if (!s->private_key[0])
        wg_genkey(s->private_key, s->public_key);
    if (!s->endpoint[0])
        str_copy(s->endpoint, "vpn.example.com", sizeof s->endpoint);
    if (!s->admin_hash[0])
        auth_hash_password("admin", s->admin_hash, sizeof s->admin_hash);
    if (!s->installed_at)
        s->installed_at = now_unix() - 45 * 86400;
    if (g_db.nclients > 0) {
        app_commit();
        return;
    }
    int64_t now = now_unix();
    int tz = s->tz_offset;
    for (size_t i = 0; i < ARRAY_LEN(SPECS); i++) {
        const demo_spec_t *sp = &SPECS[i];
        client_t tmp;
        memset(&tmp, 0, sizeof tmp);
        char err[128];
        if (client_init_new(&g_db, &tmp, err, sizeof err) != 0)
            break;
        str_copy(tmp.name, sp->name, sizeof tmp.name);
        str_copy(tmp.note, sp->note, sizeof tmp.note);
        tmp.created_at = now - (int64_t)(40 - i * 3) * 86400;
        tmp.updated_at = tmp.created_at;
        if (sp->state[0]) {
            tmp.enabled = false;
            str_copy(tmp.disabled_reason, sp->state, sizeof tmp.disabled_reason);
        }
        if (sp->expire_days)
            tmp.expires_at = now + (int64_t)sp->expire_days * 86400;
        if (sp->limit_gb > 0) {
            tmp.data_limit = (int64_t)(sp->limit_gb * 1073741824.0);
            tmp.limit_monthly = sp->monthly;
        }
        client_t *c = db_client_add(&g_db);
        *c = tmp;

        demo_peer_t *d = dp_get(c);
        if (d) {
            d->online = sp->online && !sp->state[0];
            d->base = sp->gb_day * 1073741824.0 / 86400.0 * 1.4;
            d->hs_fixed = sp->online ? 0 : now - (int64_t)sp->offline_min * 60;
        }
        /* lịch sử 30 ngày */
        cstat_t *cs = stats_client(c->id, true);
        int32_t today = key_day(now, tz);
        int days_alive = (int)((now - c->created_at) / 86400);
        if (days_alive > 30)
            days_alive = 30;
        uint64_t month_rx = 0, month_tx = 0;
        int32_t mk = key_month(now, tz);
        for (int dd = days_alive; dd >= 1; dd--) {
            int32_t k = today - dd;
            if (sp->state[0] && strcmp(sp->state, "quota") != 0 && dd < 3)
                continue; /* đã khóa vài ngày gần đây */
            double wk = 0.7 + 0.6 * frand();
            uint64_t tx = (uint64_t)(sp->gb_day * wk * 1073741824.0);
            uint64_t rx = (uint64_t)((double)tx * (0.12 + 0.1 * frand()));
            series_add(&cs->days, k, rx, tx, ST_CDAYS);
            series_add(&g_stats.days, k, rx, tx, ST_DAYS);
            cs->rx += rx;
            cs->tx += tx;
            int y, m, d2;
            civil_from_days(k, &y, &m, &d2);
            if (y * 12 + m - 1 == mk) {
                month_rx += rx;
                month_tx += tx;
            }
        }
        /* 48 giờ gần nhất theo nhịp sinh hoạt (cao điểm buổi tối) */
        int32_t hnow = key_hour(now, tz);
        for (int hh = 47; hh >= 1; hh--) {
            int32_t k = hnow - hh;
            int hour_of_day = ((k % 24) + 24) % 24;
            double curve = 0.25 + 0.75 * exp(-pow((hour_of_day - 21) / 4.0, 2)) +
                           0.35 * exp(-pow((hour_of_day - 12) / 3.0, 2));
            if (!sp->online && (hh < sp->offline_min / 60 + 1))
                continue;
            double tx = sp->gb_day * 1073741824.0 / 24.0 * curve * (0.6 + 0.8 * frand()) * 1.3;
            uint64_t htx = (uint64_t)tx, hrx = (uint64_t)(tx * 0.15);
            series_add(&cs->hours, k, hrx, htx, ST_CHOURS);
            series_add(&g_stats.hours, k, hrx, htx, ST_HOURS);
            if (k / 24 == today && (!sp->state[0] || !strcmp(sp->state, "quota"))) {
                /* các giờ đã qua của hôm nay cũng được tính vào ngày hôm nay */
                series_add(&cs->days, today, hrx, htx, ST_CDAYS);
                series_add(&g_stats.days, today, hrx, htx, ST_DAYS);
                cs->rx += hrx;
                cs->tx += htx;
                month_rx += hrx;
                month_tx += htx;
            }
        }
        cs->pkey = mk;
        cs->prx = month_rx;
        cs->ptx = month_tx;
        if (strcmp(sp->state, "quota") == 0 && tmp.data_limit) {
            /* đảm bảo đã vượt hạn mức */
            cs->ptx = (uint64_t)tmp.data_limit;
            cs->prx = (uint64_t)(tmp.data_limit / 20);
        } else if (sp->limit_gb > 0) {
            uint64_t target = (uint64_t)(tmp.data_limit * (i == 2 ? 0.66 : 0.31));
            cs->ptx = target;
            cs->prx = target / 7;
        }
        cs->handshake = sp->online ? now - 30 : now - (int64_t)sp->offline_min * 60;
        cs->last_active = cs->handshake;
        snprintf(cs->endpoint, sizeof cs->endpoint, "%s", d ? d->ep : "");
    }
    app_commit();
}
