/*
 * Tuấn WireGuard - thống kê dung lượng & bộ thu thập chạy nền
 * Tác giả: Tuandethuong
 */
#include "stats.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app.h"
#include "audit.h"
#include "demo.h"
#include "sysinfo.h"
#include "wg.h"

stats_t g_stats;

/* ================= khóa thời gian ================= */

static int64_t floordiv(int64_t a, int64_t b)
{
    int64_t q = a / b;
    if ((a % b != 0) && ((a < 0) != (b < 0)))
        q--;
    return q;
}

int32_t key_hour(int64_t t, int tz)
{
    return (int32_t)floordiv(t + (int64_t)tz * 60, 3600);
}

int32_t key_day(int64_t t, int tz)
{
    return (int32_t)floordiv(t + (int64_t)tz * 60, 86400);
}

int32_t key_month(int64_t t, int tz)
{
    int y, m, d;
    civil_from_days(key_day(t, tz), &y, &m, &d);
    return (int32_t)(y * 12 + (m - 1));
}

void key_day_label(int32_t k, char *out, size_t n)
{
    int y, m, d;
    civil_from_days(k, &y, &m, &d);
    snprintf(out, n, "%04d-%02d-%02d", y, m, d);
}

/* ================= chuỗi dữ liệu ================= */

void series_add(series_t *s, int32_t key, uint64_t rx, uint64_t tx, int keep)
{
    if (s->n && s->b[s->n - 1].k == key) {
        s->b[s->n - 1].rx += rx;
        s->b[s->n - 1].tx += tx;
        return;
    }
    if (s->n && key < s->b[s->n - 1].k) {
        /* đồng hồ lùi: cộng vào bucket khớp hoặc bucket cuối */
        for (int i = s->n - 1; i >= 0; i--) {
            if (s->b[i].k == key) {
                s->b[i].rx += rx;
                s->b[i].tx += tx;
                return;
            }
        }
        s->b[s->n - 1].rx += rx;
        s->b[s->n - 1].tx += tx;
        return;
    }
    if (s->n >= keep) {
        memmove(s->b, s->b + 1, (size_t)(s->n - 1) * sizeof(bucket_t));
        s->n--;
    }
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 16;
        if (s->cap > keep)
            s->cap = keep;
        s->b = xrealloc(s->b, (size_t)s->cap * sizeof(bucket_t));
    }
    s->b[s->n].k = key;
    s->b[s->n].rx = rx;
    s->b[s->n].tx = tx;
    s->n++;
}

void series_sum_range(const series_t *s, int32_t from, int32_t to, uint64_t *rx, uint64_t *tx)
{
    uint64_t r = 0, t = 0;
    for (int i = 0; i < s->n; i++) {
        if (s->b[i].k >= from && s->b[i].k <= to) {
            r += s->b[i].rx;
            t += s->b[i].tx;
        }
    }
    *rx = r;
    *tx = t;
}

static void series_free(series_t *s)
{
    free(s->b);
    memset(s, 0, sizeof *s);
}

/* ================= theo người dùng ================= */

cstat_t *stats_client(const char *id, bool create)
{
    for (int i = 0; i < g_stats.n; i++)
        if (strcmp(g_stats.c[i].id, id) == 0)
            return &g_stats.c[i];
    if (!create)
        return NULL;
    if (g_stats.n == g_stats.cap) {
        g_stats.cap = g_stats.cap ? g_stats.cap * 2 : 32;
        g_stats.c = xrealloc(g_stats.c, (size_t)g_stats.cap * sizeof(cstat_t));
    }
    cstat_t *c = &g_stats.c[g_stats.n++];
    memset(c, 0, sizeof *c);
    str_copy(c->id, id, sizeof c->id);
    return c;
}

void stats_remove_client(const char *id)
{
    for (int i = 0; i < g_stats.n; i++) {
        if (strcmp(g_stats.c[i].id, id) == 0) {
            series_free(&g_stats.c[i].days);
            series_free(&g_stats.c[i].hours);
            memmove(&g_stats.c[i], &g_stats.c[i + 1], (size_t)(g_stats.n - i - 1) * sizeof(cstat_t));
            g_stats.n--;
            return;
        }
    }
}

void stats_reset_client(const char *id)
{
    cstat_t *c = stats_client(id, false);
    if (!c)
        return;
    c->rx = c->tx = c->prx = c->ptx = 0;
}

uint64_t stats_used(const client_t *c, const cstat_t *cs, int64_t now, int tz)
{
    if (!cs)
        return 0;
    if (c->limit_monthly)
        return cs->pkey == key_month(now, tz) ? cs->prx + cs->ptx : 0;
    return cs->rx + cs->tx;
}

bool stats_online(const client_t *c, const cstat_t *cs, int64_t now)
{
    return c->enabled && cs && cs->present && cs->handshake > 0 &&
           now - cs->handshake < ONLINE_WINDOW;
}

void stats_client_json(jw_t *w, const client_t *c, int64_t now, int tz)
{
    cstat_t *cs = stats_client(c->id, false);
    jw_obj(w);
    uint64_t trx = 0, ttx = 0, mrx = 0, mtx = 0;
    if (cs) {
        int32_t today = key_day(now, tz);
        series_sum_range(&cs->days, today, today, &trx, &ttx);
        if (cs->pkey == key_month(now, tz)) {
            mrx = cs->prx;
            mtx = cs->ptx;
        }
    }
    jw_kuint(w, "rx", cs ? cs->rx : 0);
    jw_kuint(w, "tx", cs ? cs->tx : 0);
    jw_kuint(w, "month_rx", mrx);
    jw_kuint(w, "month_tx", mtx);
    jw_kuint(w, "today_rx", trx);
    jw_kuint(w, "today_tx", ttx);
    jw_kuint(w, "used", stats_used(c, cs, now, tz));
    jw_kint(w, "handshake", cs ? cs->handshake : 0);
    jw_kstr(w, "endpoint", cs ? cs->endpoint : "");
    jw_kbool(w, "online", stats_online(c, cs, now));
    jw_knum(w, "rate_rx", cs && cs->present ? cs->rate_rx : 0);
    jw_knum(w, "rate_tx", cs && cs->present ? cs->rate_tx : 0);
    jw_kint(w, "last_active", cs ? cs->last_active : 0);
    jw_obj_end(w);
}

/* ================= lưu / nạp ================= */

static void series_json(jw_t *w, const series_t *s)
{
    jw_arr(w);
    for (int i = 0; i < s->n; i++) {
        jw_arr(w);
        jw_int(w, s->b[i].k);
        jw_uint(w, s->b[i].rx);
        jw_uint(w, s->b[i].tx);
        jw_arr_end(w);
    }
    jw_arr_end(w);
}

static void series_load(series_t *s, const json_t *arr, int keep)
{
    series_free(s);
    for (int i = 0; i < json_len(arr); i++) {
        const json_t *e = json_at(arr, i);
        if (json_len(e) < 3)
            continue;
        const json_t *k = json_at(e, 0), *r = json_at(e, 1), *t = json_at(e, 2);
        if (k->type != J_NUM || r->type != J_NUM || t->type != J_NUM)
            continue;
        series_add(s, (int32_t)k->n, (uint64_t)r->n, (uint64_t)t->n, keep);
    }
}

void stats_to_json(sb_t *out)
{
    jw_t w;
    jw_init(&w, out);
    jw_obj(&w);
    jw_kint(&w, "v", 1);
    jw_key(&w, "days");
    series_json(&w, &g_stats.days);
    jw_key(&w, "hours");
    series_json(&w, &g_stats.hours);
    jw_key(&w, "clients");
    jw_obj(&w);
    for (int i = 0; i < g_stats.n; i++) {
        cstat_t *c = &g_stats.c[i];
        jw_key(&w, c->id);
        jw_obj(&w);
        jw_kuint(&w, "rx", c->rx);
        jw_kuint(&w, "tx", c->tx);
        jw_kuint(&w, "prx", c->prx);
        jw_kuint(&w, "ptx", c->ptx);
        jw_kint(&w, "pkey", c->pkey);
        jw_kuint(&w, "lrx", c->lrx);
        jw_kuint(&w, "ltx", c->ltx);
        jw_kstr(&w, "lpk", c->lpk);
        jw_kint(&w, "hs", c->handshake);
        jw_kstr(&w, "ep", c->endpoint);
        jw_kint(&w, "la", c->last_active);
        jw_key(&w, "days");
        series_json(&w, &c->days);
        jw_key(&w, "hours");
        series_json(&w, &c->hours);
        jw_obj_end(&w);
    }
    jw_obj_end(&w);
    jw_obj_end(&w);
}

int stats_from_json(const json_t *j)
{
    if (!j || j->type != J_OBJ)
        return -1;
    series_load(&g_stats.days, json_get(j, "days"), ST_DAYS);
    series_load(&g_stats.hours, json_get(j, "hours"), ST_HOURS);
    for (int i = 0; i < g_stats.n; i++) {
        series_free(&g_stats.c[i].days);
        series_free(&g_stats.c[i].hours);
    }
    g_stats.n = 0;
    const json_t *cl = json_get(j, "clients");
    for (int i = 0; i < json_len(cl); i++) {
        const json_t *o = json_at(cl, i);
        cstat_t *c = stats_client(cl->keys[i], true);
        c->rx = (uint64_t)json_num(o, "rx", 0);
        c->tx = (uint64_t)json_num(o, "tx", 0);
        c->prx = (uint64_t)json_num(o, "prx", 0);
        c->ptx = (uint64_t)json_num(o, "ptx", 0);
        c->pkey = (int32_t)json_int(o, "pkey", 0);
        c->lrx = (uint64_t)json_num(o, "lrx", 0);
        c->ltx = (uint64_t)json_num(o, "ltx", 0);
        str_copy(c->lpk, json_str(o, "lpk", ""), sizeof c->lpk);
        c->handshake = json_int(o, "hs", 0);
        str_copy(c->endpoint, json_str(o, "ep", ""), sizeof c->endpoint);
        c->last_active = json_int(o, "la", 0);
        series_load(&c->days, json_get(o, "days"), ST_CDAYS);
        series_load(&c->hours, json_get(o, "hours"), ST_CHOURS);
    }
    return 0;
}

int stats_load(const char *path)
{
    size_t len;
    char *data = file_read(path, &len);
    if (!data)
        return 1;
    json_t *j = json_parse(data, len, NULL, 0);
    free(data);
    if (!j) {
        LOGW("stats.json bị hỏng, bắt đầu thống kê mới");
        return -1;
    }
    int r = stats_from_json(j);
    json_free(j);
    return r;
}

int stats_save(const char *path)
{
    sb_t b;
    sb_init(&b);
    pthread_mutex_lock(&g_lock);
    stats_to_json(&b);
    pthread_mutex_unlock(&g_lock);
    int r = file_write_atomic(path, b.s, b.len, 0600);
    sb_free(&b);
    return r;
}

/* ================= bộ thu thập ================= */

static pthread_t g_collector;
static volatile int g_collector_stop = 0;
static int g_wake_pipe[2] = {-1, -1};

void collector_poke(void)
{
    if (g_wake_pipe[1] >= 0) {
        char c = 1;
        ssize_t r = write(g_wake_pipe[1], &c, 1);
        (void)r;
    }
}

typedef struct {
    char id[24];
    char reason[16];
    bool enable;
} action_t;

static void live_push(int64_t t, double rx, double tx)
{
    g_stats.live[g_stats.live_pos].t = t;
    g_stats.live[g_stats.live_pos].rx = rx;
    g_stats.live[g_stats.live_pos].tx = tx;
    g_stats.live_pos = (g_stats.live_pos + 1) % ST_LIVE;
    if (g_stats.live_n < ST_LIVE)
        g_stats.live_n++;
}

static void collect_once(double dt)
{
    int64_t now = now_unix();
    char iface[16];
    app_rlock();
    str_copy(iface, g_db.s.iface, sizeof iface);
    app_runlock();

    wg_status_t st;
    char err[512] = "";
    int rc = g_app.demo ? demo_dump(&st) : wg_dump(iface, &st, err, sizeof err);

    action_t *acts = NULL;
    int nacts = 0, capacts = 0;

    app_rlock();
    int tz = g_db.s.tz_offset;
    g_stats.wg_up = st.up;
    g_stats.wg_listen_port = st.listen_port;
    if (rc != 0)
        str_copy(g_stats.wg_error, err, sizeof g_stats.wg_error);
    else if (st.up)
        g_stats.wg_error[0] = 0;
    for (int i = 0; i < g_stats.n; i++)
        g_stats.c[i].present = false;

    uint64_t sum_rx = 0, sum_tx = 0;
    double rate_rx = 0, rate_tx = 0;
    int32_t hk = key_hour(now, tz), dk = key_day(now, tz), mk = key_month(now, tz);
    for (int i = 0; i < st.npeers; i++) {
        wg_peer_t *p = &st.peers[i];
        client_t *c = db_client_by_pubkey(&g_db, p->public_key);
        if (!c)
            continue;
        cstat_t *cs = stats_client(c->id, true);
        uint64_t drx, dtx;
        if (strcmp(cs->lpk, p->public_key) != 0) {
            drx = p->rx;
            dtx = p->tx;
            str_copy(cs->lpk, p->public_key, sizeof cs->lpk);
        } else {
            drx = p->rx >= cs->lrx ? p->rx - cs->lrx : p->rx;
            dtx = p->tx >= cs->ltx ? p->tx - cs->ltx : p->tx;
        }
        cs->lrx = p->rx;
        cs->ltx = p->tx;
        cs->present = true;
        if (p->handshake)
            cs->handshake = p->handshake;
        if (p->endpoint[0])
            str_copy(cs->endpoint, p->endpoint, sizeof cs->endpoint);
        cs->rate_rx = dt > 0 ? (double)drx / dt : 0;
        cs->rate_tx = dt > 0 ? (double)dtx / dt : 0;
        if (drx || dtx) {
            cs->rx += drx;
            cs->tx += dtx;
            if (cs->pkey != mk) {
                cs->pkey = mk;
                cs->prx = cs->ptx = 0;
            }
            cs->prx += drx;
            cs->ptx += dtx;
            cs->last_active = now;
            series_add(&cs->days, dk, drx, dtx, ST_CDAYS);
            series_add(&cs->hours, hk, drx, dtx, ST_CHOURS);
            sum_rx += drx;
            sum_tx += dtx;
        }
        rate_rx += cs->rate_rx;
        rate_tx += cs->rate_tx;
    }
    for (int i = 0; i < g_stats.n; i++)
        if (!g_stats.c[i].present)
            g_stats.c[i].rate_rx = g_stats.c[i].rate_tx = 0;
    if (sum_rx || sum_tx || g_stats.days.n == 0) {
        series_add(&g_stats.days, dk, sum_rx, sum_tx, ST_DAYS);
        series_add(&g_stats.hours, hk, sum_rx, sum_tx, ST_HOURS);
    }
    g_stats.rate_rx = rate_rx;
    g_stats.rate_tx = rate_tx;
    g_stats.last_sample = now;
    live_push(now, rate_rx, rate_tx);

    /* kiểm tra hết hạn / vượt hạn mức */
    for (int i = 0; i < g_db.nclients; i++) {
        client_t *c = &g_db.clients[i];
        cstat_t *cs = stats_client(c->id, false);
        uint64_t used = stats_used(c, cs, now, tz);
        action_t a;
        memset(&a, 0, sizeof a);
        if (c->enabled && client_expired(c, now)) {
            str_copy(a.reason, "expired", sizeof a.reason);
        } else if (c->enabled && c->data_limit > 0 && used >= (uint64_t)c->data_limit) {
            str_copy(a.reason, "quota", sizeof a.reason);
        } else if (!c->enabled && strcmp(c->disabled_reason, "quota") == 0 &&
                   (c->data_limit == 0 || used < (uint64_t)c->data_limit) && !client_expired(c, now)) {
            a.enable = true; /* sang tháng mới hoặc đã tăng hạn mức */
        } else {
            continue;
        }
        str_copy(a.id, c->id, sizeof a.id);
        if (nacts == capacts) {
            capacts = capacts ? capacts * 2 : 8;
            acts = xrealloc(acts, (size_t)capacts * sizeof(action_t));
        }
        acts[nacts++] = a;
    }
    app_runlock();
    wg_status_free(&st);

    if (nacts) {
        app_begin();
        for (int i = 0; i < nacts; i++) {
            client_t *c = db_client_by_id(&g_db, acts[i].id);
            if (!c)
                continue;
            if (acts[i].enable) {
                c->enabled = true;
                c->disabled_reason[0] = 0;
                audit_log("hệ thống", "client_auto_enable", "%s (hạn mức đã được làm mới)", c->name);
            } else {
                c->enabled = false;
                str_copy(c->disabled_reason, acts[i].reason, sizeof c->disabled_reason);
                audit_log("hệ thống", "client_auto_disable", "%s (%s)", c->name,
                          strcmp(acts[i].reason, "expired") == 0 ? "hết hạn" : "vượt hạn mức dung lượng");
            }
            c->updated_at = now;
        }
        app_commit();
        char e[512];
        if (wg_apply(false, e, sizeof e) != 0)
            LOGW("Áp dụng cấu hình WireGuard lỗi: %s", e);
    }
    free(acts);
}

static void *collector_main(void *arg)
{
    (void)arg;
    double last = now_mono();
    int tick = 0;
    int64_t last_save = now_unix();
    sysinfo_cpu_sample(&g_stats.cpu_total, &g_stats.cpu_idle);
    while (!g_collector_stop) {
        struct pollfd pfd = {g_wake_pipe[0], POLLIN, 0};
        int r = poll(&pfd, 1, ST_INTERVAL_MS);
        if (r > 0) {
            char buf[64];
            ssize_t k = read(g_wake_pipe[0], buf, sizeof buf);
            (void)k;
        }
        if (g_collector_stop)
            break;
        double now_m = now_mono();
        double dt = now_m - last;
        if (dt < 0.5 && r > 0)
            continue; /* bị đánh thức quá sớm - đợi lần sau */
        last = now_m;
        collect_once(dt);
        double cpu = sysinfo_cpu_sample(&g_stats.cpu_total, &g_stats.cpu_idle);
        pthread_mutex_lock(&g_lock);
        g_stats.cpu = cpu;
        pthread_mutex_unlock(&g_lock);
        tick++;
        int64_t now = now_unix();
        if (now - last_save >= 60) {
            if (stats_save(g_app.stats_path) != 0)
                LOGW("Không lưu được %s", g_app.stats_path);
            last_save = now;
            /* dọn các link chia sẻ đã hết hạn */
            app_rlock();
            bool has_dead = false;
            for (int i = 0; i < g_db.nshares; i++)
                if (g_db.shares[i].expires_at && now >= g_db.shares[i].expires_at)
                    has_dead = true;
            app_runlock();
            if (has_dead) {
                app_begin();
                db_shares_prune(&g_db, now);
                app_commit();
            }
        }
    }
    return NULL;
}

void collector_start(void)
{
    if (pipe2(g_wake_pipe, O_CLOEXEC | O_NONBLOCK) != 0)
        g_wake_pipe[0] = g_wake_pipe[1] = -1;
    g_stats.started_at = now_unix();
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 512 * 1024);
    pthread_create(&g_collector, &attr, collector_main, NULL);
    pthread_attr_destroy(&attr);
}

void collector_stop(void)
{
    g_collector_stop = 1;
    collector_poke();
    pthread_join(g_collector, NULL);
}
