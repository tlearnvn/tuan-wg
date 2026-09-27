/*
 * Tuấn WireGuard - REST API & phục vụ giao diện web
 * Tác giả: Tuandethuong
 */
#include "api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"
#include "assets.h"
#include "audit.h"
#include "auth.h"
#include "crypto.h"
#include "json.h"
#include "net.h"
#include "qr.h"
#include "stats.h"
#include "sysinfo.h"
#include "wg.h"
#include "zip.h"

#define COOKIE "twg_sid"

static void (*g_restart_cb)(void) = NULL;
static char g_totp_pending[40];

void api_set_restart_cb(void (*cb)(void))
{
    g_restart_cb = cb;
}

/* ================= tiện ích ================= */

static bool m_is(const http_req_t *r, const char *m)
{
    return strcmp(r->method, m) == 0;
}

/* So khớp đường dẫn với mẫu, '*' bắt một đoạn */
static bool route(const char *path, const char *pat, char caps[][128], int maxcaps)
{
    int nc = 0;
    const char *p = path, *q = pat;
    while (*q) {
        if (*q == '*') {
            const char *e = strchr(p, '/');
            size_t len = e ? (size_t)(e - p) : strlen(p);
            if (len == 0 || len >= 128 || nc >= maxcaps)
                return false;
            memcpy(caps[nc], p, len);
            caps[nc][len] = 0;
            nc++;
            p += len;
            q++;
            continue;
        }
        if (*p != *q)
            return false;
        p++;
        q++;
    }
    return *p == 0;
}

static json_t *body_json(http_req_t *r)
{
    char err[128];
    if (!r->body || r->body_len == 0) {
        json_t *j = json_parse("{}", 2, err, sizeof err);
        return j;
    }
    json_t *j = json_parse(r->body, r->body_len, err, sizeof err);
    if (!j || j->type != J_OBJ) {
        char msg[200];
        snprintf(msg, sizeof msg, "Dữ liệu gửi lên không hợp lệ: %s", err[0] ? err : "cần đối tượng JSON");
        http_send_error(r, 400, msg);
        json_free(j);
        return NULL;
    }
    return j;
}

static void send_ok(http_req_t *r)
{
    sb_t b;
    sb_init(&b);
    sb_append(&b, "{\"ok\":true}");
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static bool session_token(http_req_t *r, char *tok, size_t n)
{
    return http_cookie(r, COOKIE, tok, n) && auth_session_valid(tok);
}

static const char *CSP_HTML =
    "Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' "
    "'unsafe-inline'; script-src 'self'; connect-src 'self' https://api.github.com; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\n";

/* ================= tài nguyên tĩnh ================= */

static void serve_asset(http_req_t *r, const asset_t *a)
{
    const char *inm = http_header(r, "If-None-Match");
    char extra[1024];
    int n = snprintf(extra, sizeof extra, "ETag: %s\r\nCache-Control: no-cache\r\nVary: Accept-Encoding\r\n",
                     g_assets_etag);
    if (strstr(a->mime, "text/html"))
        snprintf(extra + n, sizeof extra - (size_t)n, "%s", CSP_HTML);
    if (inm && strcmp(inm, g_assets_etag) == 0) {
        http_respond(r, 304, NULL, "", 0, extra);
        return;
    }
    const char *ae = http_header(r, "Accept-Encoding");
    if (a->gz && a->gzlen && ae && strstr(ae, "gzip")) {
        size_t l = strlen(extra);
        snprintf(extra + l, sizeof extra - l, "Content-Encoding: gzip\r\n");
        http_respond(r, 200, a->mime, a->gz, a->gzlen, extra);
    } else {
        http_respond(r, 200, a->mime, a->data, a->len, extra);
    }
}

static void serve_static(http_req_t *r)
{
    const char *p = r->path;
    const asset_t *a = NULL;
    if (strcmp(p, "/") == 0 || strcmp(p, "/index.html") == 0)
        a = asset_find("/index.html");
    else if (str_starts(p, "/s/") && !strchr(p + 3, '/'))
        a = asset_find("/share.html");
    else
        a = asset_find(p);
    if (!a) {
        http_send_error(r, 404, "Không tìm thấy");
        return;
    }
    serve_asset(r, a);
}

/* ================= JSON helpers ================= */

static void client_json(jw_t *w, const client_t *c, int64_t now, int tz)
{
    jw_obj(w);
    jw_kstr(w, "id", c->id);
    jw_kstr(w, "name", c->name);
    jw_kstr(w, "note", c->note);
    jw_kbool(w, "enabled", c->enabled);
    jw_kstr(w, "disabled_reason", c->disabled_reason);
    jw_kstr(w, "address", c->address);
    jw_kstr(w, "address6", c->address6);
    jw_kstr(w, "public_key", c->public_key);
    jw_kbool(w, "has_psk", c->preshared_key[0] != 0);
    jw_kstr(w, "dns", c->dns);
    jw_kstr(w, "allowed_ips", c->allowed_ips);
    jw_kint(w, "keepalive", c->keepalive);
    jw_kint(w, "mtu", c->mtu);
    jw_kint(w, "created_at", c->created_at);
    jw_kint(w, "updated_at", c->updated_at);
    jw_kint(w, "expires_at", c->expires_at);
    jw_kbool(w, "expired", client_expired(c, now));
    jw_kint(w, "data_limit", c->data_limit);
    jw_kbool(w, "limit_monthly", c->limit_monthly);
    jw_key(w, "stats");
    stats_client_json(w, c, now, tz);
    jw_obj_end(w);
}

static uint64_t series_get(const series_t *s, int32_t k, bool want_tx)
{
    for (int i = s->n - 1; i >= 0; i--) {
        if (s->b[i].k == k)
            return want_tx ? s->b[i].tx : s->b[i].rx;
        if (s->b[i].k < k)
            break;
    }
    return 0;
}

static void label_for(int32_t k, bool hourly, char *out, size_t n)
{
    if (hourly) {
        int32_t day = (int32_t)(k >= 0 ? k / 24 : (k - 23) / 24);
        int hod = (int)(((k % 24) + 24) % 24);
        char d[16];
        key_day_label(day, d, sizeof d);
        snprintf(out, n, "%s %02d:00", d, hod);
    } else {
        key_day_label(k, out, n);
    }
}

/* chuỗi [from..to] đầy đủ (điền 0 cho bucket trống) */
static void window_json(jw_t *w, const series_t *s, int32_t from, int32_t to, bool hourly)
{
    jw_arr(w);
    for (int32_t k = from; k <= to; k++) {
        char lab[32];
        label_for(k, hourly, lab, sizeof lab);
        jw_obj(w);
        jw_kstr(w, "label", lab);
        jw_kuint(w, "rx", s ? series_get(s, k, false) : 0);
        jw_kuint(w, "tx", s ? series_get(s, k, true) : 0);
        jw_obj_end(w);
    }
    jw_arr_end(w);
}

static void month_window_json(jw_t *w, const series_t *s, int32_t mfrom, int32_t mto)
{
    jw_arr(w);
    for (int32_t mk = mfrom; mk <= mto; mk++) {
        int y = mk / 12, m = mk % 12 + 1;
        int32_t d0 = (int32_t)days_from_civil(y, m, 1);
        int32_t d1 = (int32_t)days_from_civil(m == 12 ? y + 1 : y, m == 12 ? 1 : m + 1, 1) - 1;
        uint64_t rx = 0, tx = 0;
        if (s)
            series_sum_range(s, d0, d1, &rx, &tx);
        char lab[16];
        snprintf(lab, sizeof lab, "%04d-%02d", y, m);
        jw_obj(w);
        jw_kstr(w, "label", lab);
        jw_kuint(w, "rx", rx);
        jw_kuint(w, "tx", tx);
        jw_obj_end(w);
    }
    jw_arr_end(w);
}

static void month_bounds(int64_t now, int tz, int32_t *d0, int32_t *d1)
{
    int y, m, d;
    civil_from_days(key_day(now, tz), &y, &m, &d);
    *d0 = (int32_t)days_from_civil(y, m, 1);
    *d1 = key_day(now, tz);
}

/* ================= công khai ================= */

static void h_public_info(http_req_t *r)
{
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    app_rlock();
    bool totp = g_db.s.totp_enabled;
    app_runlock();
    jw_obj(&w);
    jw_kstr(&w, "app", TWG_NAME);
    jw_kstr(&w, "version", TWG_VERSION);
    jw_kstr(&w, "author", TWG_AUTHOR);
    jw_kstr(&w, "repo", TWG_REPO);
    jw_kbool(&w, "totp_required", totp);
    jw_kbool(&w, "demo", g_app.demo);
    jw_obj_end(&w);
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void set_cookie_header(http_req_t *r, const char *token, int max_age, char *out, size_t n)
{
    snprintf(out, n, "Set-Cookie: %s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s\r\n", COOKIE,
             token, max_age, r->https ? "; Secure" : "");
}

static void h_login(http_req_t *r)
{
    json_t *j = body_json(r);
    if (!j)
        return;
    int wait = auth_rate_check(r->ip);
    if (wait > 0) {
        char msg[160];
        snprintf(msg, sizeof msg, "Bạn đã nhập sai quá nhiều lần. Vui lòng thử lại sau %d phút.",
                 (wait + 59) / 60);
        http_send_error(r, 429, msg);
        json_free(j);
        return;
    }
    const char *user = json_str(j, "username", "");
    const char *pass = json_str(j, "password", "");
    const char *otp = json_str(j, "otp", "");
    char hash[192], secret[64], admin[64];
    bool totp;
    int hours;
    app_rlock();
    str_copy(hash, g_db.s.admin_hash, sizeof hash);
    str_copy(secret, g_db.s.totp_secret, sizeof secret);
    str_copy(admin, g_db.s.admin_user, sizeof admin);
    totp = g_db.s.totp_enabled;
    hours = g_db.s.session_hours;
    app_runlock();
    bool ok = strcmp(user, admin) == 0;
    ok = auth_verify_password(pass, hash) && ok;
    if (ok && totp && !auth_totp_check(secret, otp))
        ok = false;
    if (!ok) {
        auth_rate_fail(r->ip);
        audit_log(r->ip, "login_fail", "tài khoản: %.60s", user);
        sleep_ms(400);
        http_send_error(r, 401, totp ? "Sai tên đăng nhập, mật khẩu hoặc mã xác thực"
                                     : "Sai tên đăng nhập hoặc mật khẩu");
        json_free(j);
        return;
    }
    auth_rate_success(r->ip);
    char token[65];
    auth_session_create(r->ip, http_header(r, "User-Agent"), hours, token);
    audit_log(r->ip, "login", "%s", user);
    char cookie[256];
    set_cookie_header(r, token, hours * 3600, cookie, sizeof cookie);
    sb_t b;
    sb_init(&b);
    sb_append(&b, "{\"ok\":true}");
    http_send_json(r, 200, &b, cookie);
    sb_free(&b);
    secure_zero(token, sizeof token);
    json_free(j);
}

static void h_logout(http_req_t *r, const char *token)
{
    auth_session_destroy(token);
    audit_log(r->ip, "logout", "%s", "");
    char cookie[256];
    set_cookie_header(r, "", 0, cookie, sizeof cookie);
    sb_t b;
    sb_init(&b);
    sb_append(&b, "{\"ok\":true}");
    http_send_json(r, 200, &b, cookie);
    sb_free(&b);
}

static void h_session(http_req_t *r)
{
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    app_rlock();
    jw_obj(&w);
    jw_kstr(&w, "username", g_db.s.admin_user);
    jw_kbool(&w, "totp_enabled", g_db.s.totp_enabled);
    jw_kstr(&w, "app", TWG_NAME);
    jw_kstr(&w, "version", TWG_VERSION);
    jw_kstr(&w, "build", TWG_BUILD);
    jw_kstr(&w, "author", TWG_AUTHOR);
    jw_kstr(&w, "repo", TWG_REPO);
    jw_kbool(&w, "demo", g_app.demo);
    jw_kint(&w, "tz_offset", g_db.s.tz_offset);
    jw_obj_end(&w);
    app_runlock();
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

/* ================= tổng quan ================= */

static void live_json(jw_t *w)
{
    jw_arr(w);
    int start = (g_stats.live_pos - g_stats.live_n + ST_LIVE) % ST_LIVE;
    for (int i = 0; i < g_stats.live_n; i++) {
        live_t *l = &g_stats.live[(start + i) % ST_LIVE];
        jw_arr(w);
        jw_int(w, l->t);
        jw_num(w, (double)(int64_t)l->rx);
        jw_num(w, (double)(int64_t)l->tx);
        jw_arr_end(w);
    }
    jw_arr_end(w);
}

static void h_dashboard(http_req_t *r)
{
    sysinfo_t si;
    sysinfo_get(&si);
    int64_t now = now_unix();
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    app_rlock();
    const settings_t *s = &g_db.s;
    int tz = s->tz_offset;
    jw_obj(&w);
    jw_kint(&w, "now", now);
    jw_kbool(&w, "demo", g_app.demo);

    jw_key(&w, "server");
    jw_obj(&w);
    jw_kstr(&w, "interface", s->iface);
    jw_kbool(&w, "up", g_stats.wg_up);
    jw_kint(&w, "listen_port", s->listen_port);
    jw_kstr(&w, "public_key", s->public_key);
    char ep[320];
    wg_endpoint_string(s, ep, sizeof ep);
    jw_kstr(&w, "endpoint", ep);
    jw_kbool(&w, "endpoint_set", s->endpoint[0] != 0);
    jw_kstr(&w, "address", s->address);
    jw_kbool(&w, "ipv6", s->ipv6);
    jw_kstr(&w, "address6", s->address6);
    jw_kstr(&w, "dns", s->dns);
    jw_kstr(&w, "wg_version", g_app.demo ? "1.0.20210914" : wg_version());
    jw_kbool(&w, "tools", g_app.demo || wg_tools_installed());
    jw_kstr(&w, "error", g_stats.wg_error);
    jw_kint(&w, "panel_started", g_stats.started_at);
    jw_obj_end(&w);

    int total = g_db.nclients, enabled = 0, online = 0, expired = 0, quota = 0, disabled = 0;
    for (int i = 0; i < g_db.nclients; i++) {
        client_t *c = &g_db.clients[i];
        cstat_t *cs = stats_client(c->id, false);
        if (c->enabled)
            enabled++;
        else
            disabled++;
        if (stats_online(c, cs, now))
            online++;
        if (!strcmp(c->disabled_reason, "expired") || (c->enabled && client_expired(c, now)))
            expired++;
        if (!strcmp(c->disabled_reason, "quota"))
            quota++;
    }
    jw_key(&w, "counts");
    jw_obj(&w);
    jw_kint(&w, "total", total);
    jw_kint(&w, "enabled", enabled);
    jw_kint(&w, "disabled", disabled);
    jw_kint(&w, "online", online);
    jw_kint(&w, "expired", expired);
    jw_kint(&w, "quota", quota);
    jw_obj_end(&w);

    int32_t today = key_day(now, tz), m0, m1;
    month_bounds(now, tz, &m0, &m1);
    uint64_t trx, ttx, mrx, mtx, arx = 0, atx = 0;
    series_sum_range(&g_stats.days, today, today, &trx, &ttx);
    series_sum_range(&g_stats.days, m0, m1, &mrx, &mtx);
    for (int i = 0; i < g_stats.n; i++) {
        arx += g_stats.c[i].rx;
        atx += g_stats.c[i].tx;
    }
    jw_key(&w, "traffic");
    jw_obj(&w);
    jw_kuint(&w, "today_rx", trx);
    jw_kuint(&w, "today_tx", ttx);
    jw_kuint(&w, "month_rx", mrx);
    jw_kuint(&w, "month_tx", mtx);
    jw_kuint(&w, "total_rx", arx);
    jw_kuint(&w, "total_tx", atx);
    jw_knum(&w, "rate_rx", g_stats.rate_rx);
    jw_knum(&w, "rate_tx", g_stats.rate_tx);
    jw_obj_end(&w);

    jw_key(&w, "week");
    window_json(&w, &g_stats.days, today - 6, today, false);

    /* top 5 người dùng theo dung lượng tháng này */
    typedef struct {
        int idx;
        uint64_t v;
    } top_t;
    top_t top[5];
    int ntop = 0;
    int32_t mk = key_month(now, tz);
    for (int i = 0; i < g_db.nclients; i++) {
        cstat_t *cs = stats_client(g_db.clients[i].id, false);
        uint64_t v = (cs && cs->pkey == mk) ? cs->prx + cs->ptx : 0;
        if (!v)
            continue;
        int pos = ntop < 5 ? ntop++ : 5;
        if (pos == 5) {
            if (v <= top[4].v)
                continue;
            pos = 4;
        }
        top[pos].idx = i;
        top[pos].v = v;
        while (pos > 0 && top[pos].v > top[pos - 1].v) {
            top_t t = top[pos];
            top[pos] = top[pos - 1];
            top[pos - 1] = t;
            pos--;
        }
    }
    jw_key(&w, "top");
    jw_arr(&w);
    for (int i = 0; i < ntop; i++) {
        client_t *c = &g_db.clients[top[i].idx];
        cstat_t *cs = stats_client(c->id, false);
        jw_obj(&w);
        jw_kstr(&w, "id", c->id);
        jw_kstr(&w, "name", c->name);
        jw_kuint(&w, "rx", cs ? cs->prx : 0);
        jw_kuint(&w, "tx", cs ? cs->ptx : 0);
        jw_kbool(&w, "online", stats_online(c, cs, now));
        jw_obj_end(&w);
    }
    jw_arr_end(&w);

    jw_key(&w, "system");
    jw_obj(&w);
    jw_kstr(&w, "hostname", si.hostname);
    jw_kstr(&w, "os", si.os);
    jw_kstr(&w, "kernel", si.kernel);
    jw_kint(&w, "cpus", si.cpus);
    jw_knum(&w, "cpu", g_stats.cpu);
    jw_knum(&w, "load1", si.load1);
    jw_knum(&w, "load5", si.load5);
    jw_knum(&w, "load15", si.load15);
    jw_kuint(&w, "mem_total", si.mem_total);
    jw_kuint(&w, "mem_avail", si.mem_avail);
    jw_kuint(&w, "disk_total", si.disk_total);
    jw_kuint(&w, "disk_free", si.disk_free);
    jw_kint(&w, "uptime", si.uptime);
    jw_obj_end(&w);

    jw_key(&w, "live");
    live_json(&w);
    jw_obj_end(&w);
    app_runlock();
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void h_live(http_req_t *r)
{
    int64_t now = now_unix();
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    app_rlock();
    jw_obj(&w);
    jw_kint(&w, "now", now);
    jw_knum(&w, "rate_rx", g_stats.rate_rx);
    jw_knum(&w, "rate_tx", g_stats.rate_tx);
    jw_kbool(&w, "up", g_stats.wg_up);
    jw_key(&w, "points");
    live_json(&w);
    jw_key(&w, "clients");
    jw_arr(&w);
    for (int i = 0; i < g_db.nclients; i++) {
        client_t *c = &g_db.clients[i];
        cstat_t *cs = stats_client(c->id, false);
        jw_obj(&w);
        jw_kstr(&w, "id", c->id);
        jw_kbool(&w, "online", stats_online(c, cs, now));
        jw_knum(&w, "rate_rx", cs && cs->present ? cs->rate_rx : 0);
        jw_knum(&w, "rate_tx", cs && cs->present ? cs->rate_tx : 0);
        jw_kint(&w, "handshake", cs ? cs->handshake : 0);
        jw_obj_end(&w);
    }
    jw_arr_end(&w);
    jw_obj_end(&w);
    app_runlock();
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

/* ================= người dùng ================= */

static void h_clients_list(http_req_t *r)
{
    int64_t now = now_unix();
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    app_rlock();
    jw_obj(&w);
    jw_kint(&w, "now", now);
    jw_key(&w, "server");
    jw_obj(&w);
    jw_kstr(&w, "address", g_db.s.address);
    jw_kstr(&w, "dns", g_db.s.dns);
    jw_kstr(&w, "allowed_ips", g_db.s.allowed_ips);
    jw_kint(&w, "keepalive", g_db.s.keepalive);
    jw_kint(&w, "mtu", g_db.s.mtu);
    jw_kbool(&w, "ipv6", g_db.s.ipv6);
    jw_obj_end(&w);
    jw_key(&w, "clients");
    jw_arr(&w);
    for (int i = 0; i < g_db.nclients; i++)
        client_json(&w, &g_db.clients[i], now, g_db.s.tz_offset);
    jw_arr_end(&w);
    jw_obj_end(&w);
    app_runlock();
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void apply_and_report(http_req_t *r, bool restart, sb_t *resp)
{
    char err[512];
    if (wg_apply(restart, err, sizeof err) != 0) {
        /* dữ liệu đã lưu nhưng áp dụng lỗi: báo kèm cảnh báo */
        LOGW("wg_apply: %s", err);
        if (resp && resp->len && resp->s[resp->len - 1] == '}') {
            resp->len--;
            resp->s[resp->len] = 0;
            sb_append(resp, ",\"warning\":");
            sb_json_str(resp, err);
            sb_append(resp, "}");
        }
    }
    collector_poke();
    if (resp)
        http_send_json(r, 200, resp, NULL);
    (void)r;
}

static void h_client_create(http_req_t *r)
{
    json_t *j = body_json(r);
    if (!j)
        return;
    char err[256];
    client_t tmp;
    memset(&tmp, 0, sizeof tmp);
    app_begin();
    if (g_db.nclients >= TWG_MAX_CLIENTS) {
        app_abort();
        http_send_error(r, 400, "Đã đạt số lượng người dùng tối đa");
        json_free(j);
        return;
    }
    if (client_init_new(&g_db, &tmp, err, sizeof err) != 0 ||
        client_apply_json(&g_db, &tmp, -1, j, true, err, sizeof err) != 0) {
        app_abort();
        http_send_error(r, 400, err);
        json_free(j);
        return;
    }
    client_t *c = db_client_add(&g_db);
    *c = tmp;
    stats_remove_client(c->id);
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    client_json(&w, c, now_unix(), g_db.s.tz_offset);
    char name[256];
    str_copy(name, c->name, sizeof name);
    char addr[16];
    str_copy(addr, c->address, sizeof addr);
    int rc = app_commit();
    json_free(j);
    if (rc != 0) {
        sb_free(&b);
        http_send_error(r, 500, "Không lưu được dữ liệu");
        return;
    }
    audit_log(r->ip, "client_create", "%s (%s)", name, addr);
    apply_and_report(r, false, &b);
    sb_free(&b);
}

static void h_client_get(http_req_t *r, const char *id)
{
    int64_t now = now_unix();
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    app_rlock();
    client_t *c = db_client_by_id(&g_db, id);
    if (!c) {
        app_runlock();
        sb_free(&b);
        http_send_error(r, 404, "Không tìm thấy người dùng");
        return;
    }
    int tz = g_db.s.tz_offset;
    jw_obj(&w);
    jw_key(&w, "client");
    client_json(&w, c, now, tz);
    cstat_t *cs = stats_client(c->id, false);
    int32_t today = key_day(now, tz), hnow = key_hour(now, tz);
    jw_key(&w, "days");
    window_json(&w, cs ? &cs->days : NULL, today - 29, today, false);
    jw_key(&w, "hours");
    window_json(&w, cs ? &cs->hours : NULL, hnow - 23, hnow, true);
    jw_key(&w, "shares");
    jw_arr(&w);
    for (int i = 0; i < g_db.nshares; i++) {
        share_t *x = &g_db.shares[i];
        if (strcmp(x->client_id, c->id) != 0 || (x->expires_at && x->expires_at <= now))
            continue;
        jw_obj(&w);
        jw_kstr(&w, "token", x->token);
        jw_kint(&w, "created_at", x->created_at);
        jw_kint(&w, "expires_at", x->expires_at);
        jw_kint(&w, "views", x->downloads);
        jw_obj_end(&w);
    }
    jw_arr_end(&w);
    jw_obj_end(&w);
    app_runlock();
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void h_client_update(http_req_t *r, const char *id)
{
    json_t *j = body_json(r);
    if (!j)
        return;
    char err[256];
    app_begin();
    int idx = db_client_index(&g_db, id);
    if (idx < 0) {
        app_abort();
        json_free(j);
        http_send_error(r, 404, "Không tìm thấy người dùng");
        return;
    }
    client_t tmp = g_db.clients[idx];
    bool was_enabled = tmp.enabled;
    char old_addr[16];
    str_copy(old_addr, tmp.address, sizeof old_addr);
    if (client_apply_json(&g_db, &tmp, idx, j, false, err, sizeof err) != 0) {
        app_abort();
        json_free(j);
        http_send_error(r, 400, err);
        return;
    }
    /* đã tăng hạn mức -> mở khóa */
    int64_t now = now_unix();
    if (!tmp.enabled && strcmp(tmp.disabled_reason, "quota") == 0) {
        cstat_t *cs = stats_client(tmp.id, false);
        if (tmp.data_limit == 0 || stats_used(&tmp, cs, now, g_db.s.tz_offset) < (uint64_t)tmp.data_limit) {
            tmp.enabled = true;
            tmp.disabled_reason[0] = 0;
        }
    }
    g_db.clients[idx] = tmp;
    client_t *c = &g_db.clients[idx];
    bool toggled = was_enabled != c->enabled;
    bool changed_peer = toggled || strcmp(old_addr, c->address) != 0;
    char name[256];
    str_copy(name, c->name, sizeof name);
    bool en = c->enabled;
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    client_json(&w, c, now, g_db.s.tz_offset);
    int rc = app_commit();
    bool only_toggle = json_len(j) == 1 && json_has(j, "enabled");
    json_free(j);
    if (rc != 0) {
        sb_free(&b);
        http_send_error(r, 500, "Không lưu được dữ liệu");
        return;
    }
    if (toggled)
        audit_log(r->ip, en ? "client_enable" : "client_disable", "%s", name);
    if (!only_toggle)
        audit_log(r->ip, "client_update", "%s", name);
    if (changed_peer)
        apply_and_report(r, false, &b);
    else
        http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void h_client_delete(http_req_t *r, const char *id)
{
    app_begin();
    int idx = db_client_index(&g_db, id);
    if (idx < 0) {
        app_abort();
        http_send_error(r, 404, "Không tìm thấy người dùng");
        return;
    }
    char name[256];
    str_copy(name, g_db.clients[idx].name, sizeof name);
    db_client_shares_remove(&g_db, id);
    db_client_remove(&g_db, idx);
    stats_remove_client(id);
    int rc = app_commit();
    if (rc != 0) {
        http_send_error(r, 500, "Không lưu được dữ liệu");
        return;
    }
    audit_log(r->ip, "client_delete", "%s", name);
    sb_t b;
    sb_init(&b);
    sb_append(&b, "{\"ok\":true}");
    apply_and_report(r, false, &b);
    sb_free(&b);
}

static void h_client_reset(http_req_t *r, const char *id)
{
    app_begin();
    client_t *c = db_client_by_id(&g_db, id);
    if (!c) {
        app_abort();
        http_send_error(r, 404, "Không tìm thấy người dùng");
        return;
    }
    stats_reset_client(id);
    bool reenable = !c->enabled && strcmp(c->disabled_reason, "quota") == 0;
    if (reenable) {
        c->enabled = true;
        c->disabled_reason[0] = 0;
    }
    char name[256];
    str_copy(name, c->name, sizeof name);
    app_commit();
    audit_log(r->ip, "client_reset", "%s", name);
    sb_t b;
    sb_init(&b);
    sb_append(&b, "{\"ok\":true}");
    if (reenable)
        apply_and_report(r, false, &b);
    else
        http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void h_client_rekey(http_req_t *r, const char *id)
{
    app_begin();
    client_t *c = db_client_by_id(&g_db, id);
    if (!c) {
        app_abort();
        http_send_error(r, 404, "Không tìm thấy người dùng");
        return;
    }
    if (wg_genkey(c->private_key, c->public_key) != 0) {
        app_abort();
        http_send_error(r, 500, "Không tạo được khóa");
        return;
    }
    if (g_db.s.use_psk)
        wg_genpsk(c->preshared_key);
    else
        c->preshared_key[0] = 0;
    c->updated_at = now_unix();
    db_client_shares_remove(&g_db, id);
    char name[256];
    str_copy(name, c->name, sizeof name);
    app_commit();
    audit_log(r->ip, "client_rekey", "%s", name);
    sb_t b;
    sb_init(&b);
    sb_append(&b, "{\"ok\":true}");
    apply_and_report(r, false, &b);
    sb_free(&b);
}

static bool build_client_conf(const char *id, sb_t *conf, char *fname, size_t fnsz, char *name,
                              size_t nsz, bool comment)
{
    app_rlock();
    client_t *c = db_client_by_id(&g_db, id);
    if (!c) {
        app_runlock();
        return false;
    }
    wg_build_client_conf(&g_db, c, conf, comment);
    if (fname)
        safe_filename(c->name, fname, fnsz, 15);
    if (name)
        str_copy(name, c->name, nsz);
    app_runlock();
    return true;
}

static void h_client_config(http_req_t *r, const char *id)
{
    sb_t conf;
    sb_init(&conf);
    char fname[64], name[256];
    if (!build_client_conf(id, &conf, fname, sizeof fname, name, sizeof name, true)) {
        sb_free(&conf);
        http_send_error(r, 404, "Không tìm thấy người dùng");
        return;
    }
    char inl[8];
    bool inline_view = http_query(r, "inline", inl, sizeof inl);
    char extra[256] = "";
    if (!inline_view) {
        snprintf(extra, sizeof extra, "Content-Disposition: attachment; filename=\"%s.conf\"\r\n", fname);
        audit_log(r->ip, "client_download", "%s", name);
    }
    http_respond(r, 200, "text/plain; charset=utf-8", conf.s, conf.len, extra);
    sb_free(&conf);
}

static void h_client_qr(http_req_t *r, const char *id)
{
    sb_t conf, svg;
    sb_init(&conf);
    sb_init(&svg);
    if (!build_client_conf(id, &conf, NULL, 0, NULL, 0, false)) {
        sb_free(&conf);
        http_send_error(r, 404, "Không tìm thấy người dùng");
        return;
    }
    if (qr_svg(conf.s, &svg) != 0) {
        sb_free(&conf);
        http_send_error(r, 500, "Không tạo được mã QR");
        return;
    }
    http_respond(r, 200, "image/svg+xml", svg.s, svg.len, NULL);
    sb_free(&conf);
    sb_free(&svg);
}

static void h_share_create(http_req_t *r, const char *id)
{
    json_t *j = body_json(r);
    if (!j)
        return;
    int hours = (int)json_int(j, "hours", 24);
    json_free(j);
    if (hours < 1 || hours > 24 * 30) {
        http_send_error(r, 400, "Thời hạn link phải từ 1 giờ đến 30 ngày");
        return;
    }
    app_begin();
    client_t *c = db_client_by_id(&g_db, id);
    if (!c) {
        app_abort();
        http_send_error(r, 404, "Không tìm thấy người dùng");
        return;
    }
    db_shares_prune(&g_db, now_unix());
    share_t *x = db_share_add(&g_db);
    uint8_t rnd[24];
    random_bytes(rnd, sizeof rnd);
    base64url_encode(rnd, sizeof rnd, x->token);
    str_copy(x->client_id, id, sizeof x->client_id);
    x->created_at = now_unix();
    x->expires_at = x->created_at + (int64_t)hours * 3600;
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    jw_obj(&w);
    jw_kstr(&w, "token", x->token);
    char pathbuf[80];
    snprintf(pathbuf, sizeof pathbuf, "/s/%s", x->token);
    jw_kstr(&w, "path", pathbuf);
    jw_kint(&w, "expires_at", x->expires_at);
    jw_obj_end(&w);
    char name[256];
    str_copy(name, c->name, sizeof name);
    app_commit();
    audit_log(r->ip, "share_create", "%s (%d giờ)", name, hours);
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void h_share_delete(http_req_t *r, const char *token)
{
    app_begin();
    int idx = -1;
    for (int i = 0; i < g_db.nshares; i++)
        if (strcmp(g_db.shares[i].token, token) == 0)
            idx = i;
    if (idx < 0) {
        app_abort();
        http_send_error(r, 404, "Link không tồn tại");
        return;
    }
    char cid[24];
    str_copy(cid, g_db.shares[idx].client_id, sizeof cid);
    client_t *c = db_client_by_id(&g_db, cid);
    char name[256];
    str_copy(name, c ? c->name : cid, sizeof name);
    db_share_remove(&g_db, idx);
    app_commit();
    audit_log(r->ip, "share_revoke", "%s", name);
    send_ok(r);
}

static void h_clients_bulk(http_req_t *r)
{
    json_t *j = body_json(r);
    if (!j)
        return;
    const char *action = json_str(j, "action", "");
    const json_t *ids = json_get(j, "ids");
    if (!ids || ids->type != J_ARR || json_len(ids) == 0) {
        json_free(j);
        http_send_error(r, 400, "Chưa chọn người dùng nào");
        return;
    }
    if (strcmp(action, "enable") && strcmp(action, "disable") && strcmp(action, "delete") &&
        strcmp(action, "reset")) {
        json_free(j);
        http_send_error(r, 400, "Thao tác không hợp lệ");
        return;
    }
    int done = 0;
    app_begin();
    for (int i = 0; i < json_len(ids); i++) {
        const json_t *v = json_at(ids, i);
        if (!v || v->type != J_STR)
            continue;
        int idx = db_client_index(&g_db, v->s);
        if (idx < 0)
            continue;
        client_t *c = &g_db.clients[idx];
        if (!strcmp(action, "enable")) {
            c->enabled = true;
            c->disabled_reason[0] = 0;
            c->updated_at = now_unix();
        } else if (!strcmp(action, "disable")) {
            if (c->enabled) {
                c->enabled = false;
                str_copy(c->disabled_reason, "manual", sizeof c->disabled_reason);
                c->updated_at = now_unix();
            }
        } else if (!strcmp(action, "reset")) {
            stats_reset_client(c->id);
            if (!c->enabled && !strcmp(c->disabled_reason, "quota")) {
                c->enabled = true;
                c->disabled_reason[0] = 0;
            }
        } else {
            char id[24];
            str_copy(id, c->id, sizeof id);
            db_client_shares_remove(&g_db, id);
            db_client_remove(&g_db, idx);
            stats_remove_client(id);
        }
        done++;
    }
    app_commit();
    audit_log(r->ip, "client_bulk", "%s: %d người dùng", action, done);
    json_free(j);
    sb_t b;
    sb_init(&b);
    sb_printf(&b, "{\"ok\":true,\"count\":%d}", done);
    apply_and_report(r, false, &b);
    sb_free(&b);
}

static void h_export_zip(http_req_t *r)
{
    zip_t z;
    zip_init(&z);
    time_t now = time(NULL);
    app_rlock();
    for (int i = 0; i < g_db.nclients; i++) {
        client_t *c = &g_db.clients[i];
        sb_t conf;
        sb_init(&conf);
        wg_build_client_conf(&g_db, c, &conf, true);
        char fname[64], full[96];
        safe_filename(c->name, fname, sizeof fname, 15);
        /* tránh trùng tên file */
        snprintf(full, sizeof full, "%s.conf", fname);
        for (int k = 0; k < i; k++) {
            char other[64];
            safe_filename(g_db.clients[k].name, other, sizeof other, 15);
            if (strcmp(other, fname) == 0) {
                snprintf(full, sizeof full, "%s-%d.conf", fname, i + 1);
                break;
            }
        }
        zip_add(&z, full, conf.s ? conf.s : "", conf.len, now);
        sb_free(&conf);
    }
    app_runlock();
    sb_t out;
    zip_finish(&z, &out);
    char extra[200];
    struct tm tm;
    localtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof ts, "%Y%m%d-%H%M", &tm);
    snprintf(extra, sizeof extra, "Content-Disposition: attachment; filename=\"tuan-wg-configs-%s.zip\"\r\n", ts);
    audit_log(r->ip, "export_zip", "tải tất cả cấu hình");
    http_respond(r, 200, "application/zip", out.s ? out.s : "", out.len, extra);
    sb_free(&out);
}

/* ================= thống kê ================= */

static void h_stats(http_req_t *r)
{
    char range[16] = "30d";
    http_query(r, "range", range, sizeof range);
    int64_t now = now_unix();
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    app_rlock();
    int tz = g_db.s.tz_offset;
    int32_t today = key_day(now, tz), hnow = key_hour(now, tz);
    int mode; /* 0 = giờ, 1 = ngày, 2 = tháng */
    int32_t from, to = today;
    if (!strcmp(range, "24h")) {
        mode = 0;
        from = hnow - 23;
        to = hnow;
    } else if (!strcmp(range, "7d")) {
        mode = 1;
        from = today - 6;
    } else if (!strcmp(range, "90d")) {
        mode = 1;
        from = today - 89;
    } else if (!strcmp(range, "12m")) {
        mode = 2;
        int32_t mk = key_month(now, tz);
        from = mk - 11;
        to = mk;
    } else {
        str_copy(range, "30d", sizeof range);
        mode = 1;
        from = today - 29;
    }
    /* khoảng ngày tương ứng dùng để cộng dồn theo người dùng */
    int32_t dfrom = from, dto = to;
    if (mode == 2) {
        int y = from / 12, m = from % 12 + 1;
        dfrom = (int32_t)days_from_civil(y, m, 1);
        dto = today;
    }
    jw_obj(&w);
    jw_kstr(&w, "range", range);
    jw_kstr(&w, "unit", mode == 0 ? "hour" : mode == 1 ? "day" : "month");
    jw_key(&w, "series");
    if (mode == 0)
        window_json(&w, &g_stats.hours, from, to, true);
    else if (mode == 1)
        window_json(&w, &g_stats.days, from, to, false);
    else
        month_window_json(&w, &g_stats.days, from, to);
    jw_key(&w, "clients");
    jw_arr(&w);
    for (int i = 0; i < g_db.nclients; i++) {
        client_t *c = &g_db.clients[i];
        cstat_t *cs = stats_client(c->id, false);
        uint64_t rx = 0, tx = 0;
        if (cs) {
            if (mode == 0)
                series_sum_range(&cs->hours, from, to, &rx, &tx);
            else
                series_sum_range(&cs->days, dfrom, dto, &rx, &tx);
        }
        jw_obj(&w);
        jw_kstr(&w, "id", c->id);
        jw_kstr(&w, "name", c->name);
        jw_kstr(&w, "address", c->address);
        jw_kbool(&w, "enabled", c->enabled);
        jw_kbool(&w, "online", stats_online(c, cs, now));
        jw_kuint(&w, "rx", rx);
        jw_kuint(&w, "tx", tx);
        jw_kuint(&w, "total_rx", cs ? cs->rx : 0);
        jw_kuint(&w, "total_tx", cs ? cs->tx : 0);
        jw_obj_end(&w);
    }
    jw_arr_end(&w);
    jw_obj_end(&w);
    app_runlock();
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

/* ================= cài đặt ================= */

static void h_settings_get(http_req_t *r)
{
    char wan[32] = "", lip[64] = "";
    net_default_iface(wan, sizeof wan);
    net_local_ip(lip, sizeof lip);
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    app_rlock();
    const settings_t *s = &g_db.s;
    char up[4096], down[4096];
    wg_auto_postup(s, up, sizeof up);
    wg_auto_postdown(s, down, sizeof down);
    jw_obj(&w);
    jw_kstr(&w, "interface", s->iface);
    jw_kstr(&w, "public_key", s->public_key);
    jw_kstr(&w, "endpoint", s->endpoint);
    jw_kint(&w, "listen_port", s->listen_port);
    jw_kstr(&w, "address", s->address);
    jw_kbool(&w, "ipv6", s->ipv6);
    jw_kstr(&w, "address6", s->address6);
    jw_kstr(&w, "dns", s->dns);
    jw_kint(&w, "mtu", s->mtu);
    jw_kint(&w, "keepalive", s->keepalive);
    jw_kstr(&w, "allowed_ips", s->allowed_ips);
    jw_kstr(&w, "wan_interface", s->wan_iface);
    jw_kstr(&w, "post_up", s->post_up);
    jw_kstr(&w, "post_down", s->post_down);
    jw_kstr(&w, "auto_post_up", up);
    jw_kstr(&w, "auto_post_down", down);
    jw_kbool(&w, "client_isolation", s->client_isolation);
    jw_kbool(&w, "use_psk", s->use_psk);
    jw_kint(&w, "tz_offset", s->tz_offset);
    jw_kstr(&w, "web_listen", s->web_listen);
    jw_kint(&w, "web_port", s->web_port);
    jw_kint(&w, "session_hours", s->session_hours);
    jw_kstr(&w, "detected_wan", wan);
    jw_kstr(&w, "local_ip", lip);
    jw_kstr(&w, "data_dir", g_app.data_dir);
    jw_kstr(&w, "wg_dir", g_app.wg_dir);
    jw_obj_end(&w);
    app_runlock();
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void h_settings_put(http_req_t *r)
{
    json_t *j = body_json(r);
    if (!j)
        return;
    char err[256];
    int flags = 0;
    app_begin();
    if (settings_apply_json(&g_db, j, &flags, err, sizeof err) != 0) {
        app_abort();
        json_free(j);
        http_send_error(r, 400, err);
        return;
    }
    int web_port = g_db.s.web_port;
    int rc = app_commit();
    json_free(j);
    if (rc != 0) {
        http_send_error(r, 500, "Không lưu được cài đặt");
        return;
    }
    audit_log(r->ip, "settings_update", "%s%s", (flags & APPLY_RESTART_WG) ? "khởi động lại WireGuard" : "",
              (flags & APPLY_RESTART_WEB) ? " + khởi động lại web" : "");
    sb_t b;
    sb_init(&b);
    sb_printf(&b, "{\"ok\":true,\"restart_web\":%s,\"web_port\":%d}",
              (flags & APPLY_RESTART_WEB) ? "true" : "false", web_port);
    apply_and_report(r, (flags & APPLY_RESTART_WG) != 0, &b);
    sb_free(&b);
    if ((flags & APPLY_RESTART_WEB) && g_restart_cb)
        g_restart_cb();
}

static void h_detect_ip(http_req_t *r)
{
    char pub[64] = "", lip[64] = "";
    if (!g_app.demo)
        net_public_ip(pub, sizeof pub, 3000);
    else
        str_copy(pub, "203.0.113.10", sizeof pub);
    net_local_ip(lip, sizeof lip);
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    jw_obj(&w);
    jw_kstr(&w, "public_ip", pub);
    jw_kstr(&w, "local_ip", lip);
    jw_obj_end(&w);
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void h_wg_restart(http_req_t *r)
{
    audit_log(r->ip, "wg_restart", "%s", "");
    char err[512];
    if (wg_apply(true, err, sizeof err) != 0) {
        char msg[640];
        snprintf(msg, sizeof msg, "Khởi động lại WireGuard lỗi: %s", err);
        http_send_error(r, 500, msg);
        return;
    }
    collector_poke();
    send_ok(r);
}

/* ================= tài khoản ================= */

static bool check_password(const char *pw)
{
    char hash[192];
    app_rlock();
    str_copy(hash, g_db.s.admin_hash, sizeof hash);
    app_runlock();
    return auth_verify_password(pw, hash);
}

static void h_password(http_req_t *r, const char *token)
{
    json_t *j = body_json(r);
    if (!j)
        return;
    const char *cur = json_str(j, "current", "");
    const char *nw = json_str(j, "new", "");
    if (!check_password(cur)) {
        json_free(j);
        auth_rate_fail(r->ip);
        http_send_error(r, 400, "Mật khẩu hiện tại không đúng");
        return;
    }
    if (strlen(nw) < 8 || strlen(nw) > 128) {
        json_free(j);
        http_send_error(r, 400, "Mật khẩu mới phải có từ 8 đến 128 ký tự");
        return;
    }
    char hash[192];
    auth_hash_password(nw, hash, sizeof hash);
    json_free(j);
    app_begin();
    str_copy(g_db.s.admin_hash, hash, sizeof g_db.s.admin_hash);
    app_commit();
    int n = auth_sessions_revoke_others(token);
    audit_log(r->ip, "password_change", "đăng xuất %d phiên khác", n);
    send_ok(r);
}

static void h_username(http_req_t *r)
{
    json_t *j = body_json(r);
    if (!j)
        return;
    char user[64];
    str_copy(user, json_str(j, "username", ""), sizeof user);
    str_trim(user);
    const char *pw = json_str(j, "password", "");
    bool okpw = check_password(pw);
    json_free(j);
    if (!okpw) {
        auth_rate_fail(r->ip);
        http_send_error(r, 400, "Mật khẩu không đúng");
        return;
    }
    if (strlen(user) < 3) {
        http_send_error(r, 400, "Tên đăng nhập phải có ít nhất 3 ký tự");
        return;
    }
    for (char *p = user; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
              *p == '_' || *p == '.' || *p == '-')) {
            http_send_error(r, 400, "Tên đăng nhập chỉ gồm chữ không dấu, số và . _ -");
            return;
        }
    }
    app_begin();
    str_copy(g_db.s.admin_user, user, sizeof g_db.s.admin_user);
    app_commit();
    audit_log(r->ip, "username_change", "%s", user);
    send_ok(r);
}

static void h_2fa_setup(http_req_t *r)
{
    char secret[40], uri[512], user[64];
    auth_totp_new_secret(secret);
    app_rlock();
    str_copy(user, g_db.s.admin_user, sizeof user);
    str_copy(g_totp_pending, secret, sizeof g_totp_pending);
    app_runlock();
    auth_totp_uri(secret, user, uri, sizeof uri);
    sb_t svg;
    sb_init(&svg);
    qr_svg(uri, &svg);
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    jw_obj(&w);
    jw_kstr(&w, "secret", secret);
    jw_kstr(&w, "uri", uri);
    jw_kstr(&w, "qr_svg", svg.s ? svg.s : "");
    jw_obj_end(&w);
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
    sb_free(&svg);
}

static void h_2fa_enable(http_req_t *r)
{
    json_t *j = body_json(r);
    if (!j)
        return;
    char secret[40];
    app_rlock();
    str_copy(secret, g_totp_pending, sizeof secret);
    app_runlock();
    if (!secret[0]) {
        json_free(j);
        http_send_error(r, 400, "Hãy bấm thiết lập 2FA trước");
        return;
    }
    if (!auth_totp_check(secret, json_str(j, "code", ""))) {
        json_free(j);
        http_send_error(r, 400, "Mã xác thực không đúng, hãy thử lại");
        return;
    }
    json_free(j);
    app_begin();
    str_copy(g_db.s.totp_secret, secret, sizeof g_db.s.totp_secret);
    g_db.s.totp_enabled = true;
    g_totp_pending[0] = 0;
    app_commit();
    audit_log(r->ip, "2fa_enable", "%s", "");
    send_ok(r);
}

static void h_2fa_disable(http_req_t *r)
{
    json_t *j = body_json(r);
    if (!j)
        return;
    bool ok = check_password(json_str(j, "password", ""));
    json_free(j);
    if (!ok) {
        auth_rate_fail(r->ip);
        http_send_error(r, 400, "Mật khẩu không đúng");
        return;
    }
    app_begin();
    g_db.s.totp_enabled = false;
    g_db.s.totp_secret[0] = 0;
    app_commit();
    audit_log(r->ip, "2fa_disable", "%s", "");
    send_ok(r);
}

static void h_sessions(http_req_t *r, const char *token)
{
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    jw_obj(&w);
    jw_key(&w, "sessions");
    auth_sessions_json(&w, token);
    jw_obj_end(&w);
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void h_sessions_revoke(http_req_t *r, const char *token)
{
    int n = auth_sessions_revoke_others(token);
    audit_log(r->ip, "sessions_revoke", "%d phiên", n);
    sb_t b;
    sb_init(&b);
    sb_printf(&b, "{\"ok\":true,\"count\":%d}", n);
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

/* ================= nhật ký, sao lưu ================= */

static void h_logs(http_req_t *r)
{
    char lim[16] = "300", q[128] = "";
    http_query(r, "limit", lim, sizeof lim);
    http_query(r, "q", q, sizeof q);
    int limit = atoi(lim);
    if (limit <= 0 || limit > 2000)
        limit = 300;
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    jw_obj(&w);
    jw_key(&w, "logs");
    audit_json(&w, limit, q);
    jw_obj_end(&w);
    http_send_json(r, 200, &b, NULL);
    sb_free(&b);
}

static void h_backup(http_req_t *r)
{
    sb_t b;
    sb_init(&b);
    sb_printf(&b, "{\"tuan_wg_backup\":1,\"version\":\"%s\",\"created_at\":%lld,\"db\":", TWG_VERSION,
              (long long)now_unix());
    app_rlock();
    db_to_json(&g_db, &b);
    sb_append(&b, ",\"stats\":");
    stats_to_json(&b);
    app_runlock();
    sb_append(&b, "}\n");
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char ts[32], extra[200];
    strftime(ts, sizeof ts, "%Y%m%d-%H%M", &tm);
    snprintf(extra, sizeof extra, "Content-Disposition: attachment; filename=\"tuan-wg-backup-%s.json\"\r\n", ts);
    audit_log(r->ip, "backup", "tải bản sao lưu");
    http_respond(r, 200, "application/json", b.s, b.len, extra);
    sb_free(&b);
}

static void h_restore(http_req_t *r)
{
    char err[256];
    if (!r->body_len) {
        http_send_error(r, 400, "Chưa có dữ liệu sao lưu");
        return;
    }
    json_t *j = json_parse(r->body, r->body_len, err, sizeof err);
    if (!j || j->type != J_OBJ) {
        json_free(j);
        http_send_error(r, 400, "File sao lưu không hợp lệ");
        return;
    }
    const json_t *dbj = json_get(j, "db");
    if (!dbj && json_get(j, "server") && json_get(j, "clients"))
        dbj = j;
    if (!dbj || !json_get(dbj, "server")) {
        json_free(j);
        http_send_error(r, 400, "File không phải bản sao lưu Tuấn WireGuard");
        return;
    }
    db_t nd;
    db_defaults(&nd);
    if (db_from_json(&nd, dbj, err, sizeof err) != 0 || !wg_key_valid(nd.s.private_key) ||
        !nd.s.admin_hash[0]) {
        db_free(&nd);
        json_free(j);
        http_send_error(r, 400, "Bản sao lưu thiếu khóa máy chủ hoặc tài khoản quản trị");
        return;
    }
    int n = nd.nclients;
    app_begin();
    nd.file_sig = g_db.file_sig;
    db_free(&g_db);
    g_db = nd;
    const json_t *st = json_get(j, "stats");
    if (st)
        stats_from_json(st);
    app_commit();
    json_free(j);
    stats_save(g_app.stats_path);
    audit_log(r->ip, "restore", "khôi phục %d người dùng", n);
    sb_t b;
    sb_init(&b);
    sb_printf(&b, "{\"ok\":true,\"clients\":%d}", n);
    apply_and_report(r, true, &b);
    sb_free(&b);
}

/* ================= link chia sẻ công khai ================= */

static bool share_lookup(const char *token, bool count_view, char *cid, size_t n, int64_t *exp,
                         int *views)
{
    bool ok = false;
    int64_t now = now_unix();
    if (count_view)
        app_begin();
    else
        app_rlock();
    share_t *x = db_share_by_token(&g_db, token);
    if (x && (!x->expires_at || x->expires_at > now)) {
        client_t *c = db_client_by_id(&g_db, x->client_id);
        if (c && c->enabled) {
            ok = true;
            str_copy(cid, x->client_id, n);
            if (count_view)
                x->downloads++;
            if (exp)
                *exp = x->expires_at;
            if (views)
                *views = x->downloads;
        }
    }
    if (count_view) {
        if (ok)
            app_commit();
        else
            app_abort();
    } else {
        app_runlock();
    }
    return ok;
}

static void h_share_public(http_req_t *r, const char *token, const char *what)
{
    char cid[24];
    int64_t exp = 0;
    int views = 0;
    bool info = what == NULL;
    if (strlen(token) > 64 || !share_lookup(token, info, cid, sizeof cid, &exp, &views)) {
        sleep_ms(200);
        http_send_error(r, 404, "Link không tồn tại hoặc đã hết hạn");
        return;
    }
    sb_t conf;
    sb_init(&conf);
    char fname[64], name[256];
    if (!build_client_conf(cid, &conf, fname, sizeof fname, name, sizeof name, !what || !strcmp(what, "config"))) {
        sb_free(&conf);
        http_send_error(r, 404, "Link không tồn tại hoặc đã hết hạn");
        return;
    }
    if (info) {
        audit_log(r->ip, "share_view", "%s", name);
        sb_t b;
        sb_init(&b);
        jw_t w;
        jw_init(&w, &b);
        jw_obj(&w);
        jw_kstr(&w, "name", name);
        jw_kstr(&w, "filename", fname);
        jw_kint(&w, "expires_at", exp);
        jw_kint(&w, "views", views);
        jw_kstr(&w, "config", conf.s);
        jw_kstr(&w, "app", TWG_NAME);
        jw_kstr(&w, "version", TWG_VERSION);
        jw_obj_end(&w);
        http_send_json(r, 200, &b, NULL);
        sb_free(&b);
    } else if (!strcmp(what, "config")) {
        char extra[256];
        snprintf(extra, sizeof extra, "Content-Disposition: attachment; filename=\"%s.conf\"\r\n", fname);
        audit_log(r->ip, "share_download", "%s", name);
        http_respond(r, 200, "text/plain; charset=utf-8", conf.s, conf.len, extra);
    } else {
        sb_t svg;
        sb_init(&svg);
        qr_svg(conf.s, &svg);
        http_respond(r, 200, "image/svg+xml", svg.s, svg.len, NULL);
        sb_free(&svg);
    }
    sb_free(&conf);
}

/* ================= định tuyến ================= */

void api_handle(http_req_t *r)
{
    const char *p = r->path;
    char c[4][128];
    bool get = m_is(r, "GET") || m_is(r, "HEAD");

    if (!str_starts(p, "/api/")) {
        if (!get) {
            http_send_error(r, 405, "Phương thức không được hỗ trợ");
            return;
        }
        serve_static(r);
        return;
    }

    /* chống CSRF: yêu cầu header riêng cho mọi thao tác thay đổi dữ liệu */
    if (!get) {
        const char *x = http_header(r, "X-TWG");
        if (!x || strcmp(x, "1") != 0) {
            http_send_error(r, 403, "Yêu cầu bị từ chối (thiếu header bảo vệ CSRF)");
            return;
        }
    }

    /* ---- công khai ---- */
    if (get && !strcmp(p, "/api/public/info"))
        { h_public_info(r); return; }
    if (m_is(r, "POST") && !strcmp(p, "/api/login"))
        { h_login(r); return; }
    if (get && route(p, "/api/share/*", c, 4))
        { h_share_public(r, c[0], NULL); return; }
    if (get && route(p, "/api/share/*/config", c, 4))
        { h_share_public(r, c[0], "config"); return; }
    if (get && route(p, "/api/share/*/qr.svg", c, 4))
        { h_share_public(r, c[0], "qr"); return; }

    /* ---- cần đăng nhập ---- */
    char token[80];
    if (!session_token(r, token, sizeof token)) {
        http_send_error(r, 401, "Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại");
        return;
    }
    if (g_app.demo && !get && strcmp(p, "/api/logout") != 0 && (str_starts(p, "/api/account") || !strcmp(p, "/api/restore"))) {
        http_send_error(r, 403, "Chế độ demo không cho phép thao tác này");
        return;
    }

    if (m_is(r, "POST") && !strcmp(p, "/api/logout"))
        { h_logout(r, token); return; }
    if (get && !strcmp(p, "/api/session"))
        { h_session(r); return; }
    if (get && !strcmp(p, "/api/dashboard"))
        { h_dashboard(r); return; }
    if (get && !strcmp(p, "/api/live"))
        { h_live(r); return; }

    if (!strcmp(p, "/api/clients")) {
        if (get)
            { h_clients_list(r); return; }
        if (m_is(r, "POST"))
            { h_client_create(r); return; }
    }
    if (m_is(r, "POST") && !strcmp(p, "/api/clients/bulk"))
        { h_clients_bulk(r); return; }
    if (get && !strcmp(p, "/api/export.zip"))
        { h_export_zip(r); return; }
    if (route(p, "/api/clients/*", c, 4)) {
        if (get)
            { h_client_get(r, c[0]); return; }
        if (m_is(r, "PUT"))
            { h_client_update(r, c[0]); return; }
        if (m_is(r, "DELETE"))
            { h_client_delete(r, c[0]); return; }
    }
    if (m_is(r, "POST") && route(p, "/api/clients/*/reset", c, 4))
        { h_client_reset(r, c[0]); return; }
    if (m_is(r, "POST") && route(p, "/api/clients/*/rekey", c, 4))
        { h_client_rekey(r, c[0]); return; }
    if (get && route(p, "/api/clients/*/config", c, 4))
        { h_client_config(r, c[0]); return; }
    if (get && route(p, "/api/clients/*/qr.svg", c, 4))
        { h_client_qr(r, c[0]); return; }
    if (m_is(r, "POST") && route(p, "/api/clients/*/share", c, 4))
        { h_share_create(r, c[0]); return; }
    if (m_is(r, "DELETE") && route(p, "/api/shares/*", c, 4))
        { h_share_delete(r, c[0]); return; }

    if (get && !strcmp(p, "/api/stats"))
        { h_stats(r); return; }
    if (!strcmp(p, "/api/settings")) {
        if (get)
            { h_settings_get(r); return; }
        if (m_is(r, "PUT"))
            { h_settings_put(r); return; }
    }
    if (get && !strcmp(p, "/api/detect-ip"))
        { h_detect_ip(r); return; }
    if (m_is(r, "POST") && !strcmp(p, "/api/wireguard/restart"))
        { h_wg_restart(r); return; }

    if (m_is(r, "POST") && !strcmp(p, "/api/account/password"))
        { h_password(r, token); return; }
    if (m_is(r, "POST") && !strcmp(p, "/api/account/username"))
        { h_username(r); return; }
    if (m_is(r, "POST") && !strcmp(p, "/api/account/2fa/setup"))
        { h_2fa_setup(r); return; }
    if (m_is(r, "POST") && !strcmp(p, "/api/account/2fa/enable"))
        { h_2fa_enable(r); return; }
    if (m_is(r, "POST") && !strcmp(p, "/api/account/2fa/disable"))
        { h_2fa_disable(r); return; }
    if (get && !strcmp(p, "/api/sessions"))
        { h_sessions(r, token); return; }
    if (m_is(r, "POST") && !strcmp(p, "/api/sessions/revoke-others"))
        { h_sessions_revoke(r, token); return; }

    if (get && !strcmp(p, "/api/logs"))
        { h_logs(r); return; }
    if (get && !strcmp(p, "/api/backup"))
        { h_backup(r); return; }
    if (m_is(r, "POST") && !strcmp(p, "/api/restore"))
        { h_restore(r); return; }

    http_send_error(r, 404, "Không tìm thấy API");
}
