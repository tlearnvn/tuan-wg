/*
 * Tuấn WireGuard - xác thực
 * Tác giả: Tuandethuong
 */
#include "auth.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "util.h"

/* ================= mật khẩu ================= */

int auth_hash_password(const char *pw, char *out, size_t n)
{
    uint8_t salt[16], dk[32];
    if (random_bytes(salt, sizeof salt) != 0)
        return -1;
    pbkdf2_sha256((const uint8_t *)pw, strlen(pw), salt, sizeof salt, TWG_PBKDF2_ITER, dk,
                  sizeof dk);
    char s64[32], h64[48];
    base64_encode(salt, sizeof salt, s64);
    base64_encode(dk, sizeof dk, h64);
    snprintf(out, n, "pbkdf2-sha256$%d$%s$%s", TWG_PBKDF2_ITER, s64, h64);
    secure_zero(dk, sizeof dk);
    return 0;
}

bool auth_verify_password(const char *pw, const char *hash)
{
    if (!pw || !hash || !str_starts(hash, "pbkdf2-sha256$"))
        return false;
    char buf[256];
    str_copy(buf, hash + strlen("pbkdf2-sha256$"), sizeof buf);
    char *save = NULL;
    char *it = strtok_r(buf, "$", &save);
    char *s64 = strtok_r(NULL, "$", &save);
    char *h64 = strtok_r(NULL, "$", &save);
    if (!it || !s64 || !h64)
        return false;
    long iter = strtol(it, NULL, 10);
    if (iter < 1000 || iter > 10000000)
        return false;
    uint8_t salt[64], want[64], got[64];
    int sl = base64_decode(s64, salt, sizeof salt);
    int hl = base64_decode(h64, want, sizeof want);
    if (sl <= 0 || hl != 32)
        return false;
    pbkdf2_sha256((const uint8_t *)pw, strlen(pw), salt, (size_t)sl, (uint32_t)iter, got, 32);
    bool ok = ct_equal(got, want, 32);
    secure_zero(got, sizeof got);
    return ok;
}

void auth_random_password(char *out, size_t len)
{
    static const char alpha[] = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const size_t na = sizeof alpha - 1;
    size_t w = 0;
    int in_group = 0;
    while (w + 1 < len) {
        if (in_group == 4) {
            out[w++] = '-';
            in_group = 0;
            continue;
        }
        uint8_t b;
        random_bytes(&b, 1);
        if (b >= 256 - (256 % na))
            continue; /* loại bỏ để phân bố đều */
        out[w++] = alpha[b % na];
        in_group++;
    }
    /* không để dấu '-' ở cuối */
    if (w && out[w - 1] == '-')
        w--;
    out[w] = 0;
}

/* ================= phiên đăng nhập ================= */

#define MAX_SESS 64

typedef struct {
    char hash[65];
    int64_t created, last_seen, expires;
    int ttl_hours;
    char ip[48];
    char ua[160];
} sess_t;

static sess_t g_sess[MAX_SESS];
static int g_nsess = 0;
static pthread_mutex_t g_sess_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_sess_path[320];
static int64_t g_sess_saved_at = 0;

static void token_hash(const char *token, char out[65])
{
    uint8_t d[32];
    sha256(token, strlen(token), d);
    hex_encode(d, 32, out);
}

static void sess_prune(int64_t now)
{
    for (int i = g_nsess - 1; i >= 0; i--) {
        if (g_sess[i].expires <= now) {
            memmove(&g_sess[i], &g_sess[i + 1], (size_t)(g_nsess - i - 1) * sizeof(sess_t));
            g_nsess--;
        }
    }
}

static void sess_save_locked(void)
{
    if (!g_sess_path[0])
        return;
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    jw_arr(&w);
    for (int i = 0; i < g_nsess; i++) {
        sess_t *s = &g_sess[i];
        jw_obj(&w);
        jw_kstr(&w, "hash", s->hash);
        jw_kint(&w, "created", s->created);
        jw_kint(&w, "last_seen", s->last_seen);
        jw_kint(&w, "expires", s->expires);
        jw_kint(&w, "ttl", s->ttl_hours);
        jw_kstr(&w, "ip", s->ip);
        jw_kstr(&w, "ua", s->ua);
        jw_obj_end(&w);
    }
    jw_arr_end(&w);
    file_write_atomic(g_sess_path, b.s, b.len, 0600);
    sb_free(&b);
    g_sess_saved_at = now_unix();
}

void auth_sessions_load(const char *path)
{
    pthread_mutex_lock(&g_sess_lock);
    str_copy(g_sess_path, path, sizeof g_sess_path);
    g_nsess = 0;
    size_t len;
    char *data = file_read(path, &len);
    if (data) {
        json_t *j = json_parse(data, len, NULL, 0);
        for (int i = 0; j && i < json_len(j) && g_nsess < MAX_SESS; i++) {
            json_t *o = json_at(j, i);
            sess_t *s = &g_sess[g_nsess];
            memset(s, 0, sizeof *s);
            str_copy(s->hash, json_str(o, "hash", ""), sizeof s->hash);
            s->created = json_int(o, "created", 0);
            s->last_seen = json_int(o, "last_seen", 0);
            s->expires = json_int(o, "expires", 0);
            s->ttl_hours = (int)json_int(o, "ttl", 168);
            str_copy(s->ip, json_str(o, "ip", ""), sizeof s->ip);
            str_copy(s->ua, json_str(o, "ua", ""), sizeof s->ua);
            if (strlen(s->hash) == 64)
                g_nsess++;
        }
        json_free(j);
        free(data);
    }
    sess_prune(now_unix());
    pthread_mutex_unlock(&g_sess_lock);
}

void auth_sessions_save(void)
{
    pthread_mutex_lock(&g_sess_lock);
    sess_save_locked();
    pthread_mutex_unlock(&g_sess_lock);
}

int auth_session_create(const char *ip, const char *ua, int hours, char token_out[65])
{
    random_hex(token_out, 32);
    int64_t now = now_unix();
    pthread_mutex_lock(&g_sess_lock);
    sess_prune(now);
    if (g_nsess >= MAX_SESS) {
        /* bỏ phiên cũ nhất */
        int oldest = 0;
        for (int i = 1; i < g_nsess; i++)
            if (g_sess[i].last_seen < g_sess[oldest].last_seen)
                oldest = i;
        memmove(&g_sess[oldest], &g_sess[oldest + 1],
                (size_t)(g_nsess - oldest - 1) * sizeof(sess_t));
        g_nsess--;
    }
    sess_t *s = &g_sess[g_nsess++];
    memset(s, 0, sizeof *s);
    token_hash(token_out, s->hash);
    s->created = s->last_seen = now;
    s->ttl_hours = hours > 0 ? hours : 168;
    s->expires = now + (int64_t)s->ttl_hours * 3600;
    str_copy(s->ip, ip ? ip : "", sizeof s->ip);
    str_copy(s->ua, ua ? ua : "", sizeof s->ua);
    str_strip_ctrl(s->ua);
    utf8_truncate(s->ua, sizeof s->ua - 1);
    sess_save_locked();
    pthread_mutex_unlock(&g_sess_lock);
    return 0;
}

static int sess_find(const char *token)
{
    if (!token || strlen(token) != 64)
        return -1;
    char h[65];
    token_hash(token, h);
    int found = -1;
    for (int i = 0; i < g_nsess; i++)
        if (ct_equal(g_sess[i].hash, h, 64))
            found = i;
    return found;
}

bool auth_session_valid(const char *token)
{
    int64_t now = now_unix();
    pthread_mutex_lock(&g_sess_lock);
    int i = sess_find(token);
    bool ok = false;
    if (i >= 0 && g_sess[i].expires > now) {
        ok = true;
        g_sess[i].last_seen = now;
        g_sess[i].expires = now + (int64_t)g_sess[i].ttl_hours * 3600; /* gia hạn trượt */
        if (now - g_sess_saved_at > 600)
            sess_save_locked();
    }
    pthread_mutex_unlock(&g_sess_lock);
    return ok;
}

void auth_session_destroy(const char *token)
{
    pthread_mutex_lock(&g_sess_lock);
    int i = sess_find(token);
    if (i >= 0) {
        memmove(&g_sess[i], &g_sess[i + 1], (size_t)(g_nsess - i - 1) * sizeof(sess_t));
        g_nsess--;
        sess_save_locked();
    }
    pthread_mutex_unlock(&g_sess_lock);
}

int auth_sessions_revoke_others(const char *keep_token)
{
    pthread_mutex_lock(&g_sess_lock);
    int keep = sess_find(keep_token);
    int removed = 0;
    if (keep >= 0) {
        sess_t k = g_sess[keep];
        removed = g_nsess - 1;
        g_sess[0] = k;
        g_nsess = 1;
    } else {
        removed = g_nsess;
        g_nsess = 0;
    }
    sess_save_locked();
    pthread_mutex_unlock(&g_sess_lock);
    return removed;
}

void auth_sessions_revoke_all(void)
{
    pthread_mutex_lock(&g_sess_lock);
    g_nsess = 0;
    sess_save_locked();
    pthread_mutex_unlock(&g_sess_lock);
}

void auth_sessions_json(jw_t *w, const char *current_token)
{
    pthread_mutex_lock(&g_sess_lock);
    sess_prune(now_unix());
    int cur = sess_find(current_token);
    jw_arr(w);
    for (int i = g_nsess - 1; i >= 0; i--) {
        sess_t *s = &g_sess[i];
        jw_obj(w);
        jw_kstr(w, "id", s->hash + 56); /* 8 ký tự cuối, chỉ để hiển thị */
        jw_kint(w, "created", s->created);
        jw_kint(w, "last_seen", s->last_seen);
        jw_kint(w, "expires", s->expires);
        jw_kstr(w, "ip", s->ip);
        jw_kstr(w, "ua", s->ua);
        jw_kbool(w, "current", i == cur);
        jw_obj_end(w);
    }
    jw_arr_end(w);
    pthread_mutex_unlock(&g_sess_lock);
}

/* ================= giới hạn đăng nhập sai ================= */

#define RL_SLOTS 256
#define RL_MAX_FAILS 5
#define RL_WINDOW 900
#define RL_BLOCK 900

typedef struct {
    char ip[48];
    int fails;
    int64_t first_fail;
    int64_t blocked_until;
    int64_t touched;
} rl_t;

static rl_t g_rl[RL_SLOTS];
static pthread_mutex_t g_rl_lock = PTHREAD_MUTEX_INITIALIZER;

static rl_t *rl_find(const char *ip, bool create)
{
    rl_t *free_slot = NULL, *oldest = &g_rl[0];
    for (int i = 0; i < RL_SLOTS; i++) {
        if (g_rl[i].ip[0] && strcmp(g_rl[i].ip, ip) == 0)
            return &g_rl[i];
        if (!g_rl[i].ip[0] && !free_slot)
            free_slot = &g_rl[i];
        if (g_rl[i].touched < oldest->touched)
            oldest = &g_rl[i];
    }
    if (!create)
        return NULL;
    rl_t *r = free_slot ? free_slot : oldest;
    memset(r, 0, sizeof *r);
    str_copy(r->ip, ip, sizeof r->ip);
    return r;
}

int auth_rate_check(const char *ip)
{
    int64_t now = now_unix();
    pthread_mutex_lock(&g_rl_lock);
    rl_t *r = rl_find(ip, false);
    int wait = 0;
    if (r && r->blocked_until > now)
        wait = (int)(r->blocked_until - now);
    pthread_mutex_unlock(&g_rl_lock);
    return wait;
}

void auth_rate_fail(const char *ip)
{
    int64_t now = now_unix();
    pthread_mutex_lock(&g_rl_lock);
    rl_t *r = rl_find(ip, true);
    if (now - r->first_fail > RL_WINDOW) {
        r->fails = 0;
        r->first_fail = now;
    }
    r->fails++;
    r->touched = now;
    if (r->fails >= RL_MAX_FAILS) {
        r->blocked_until = now + RL_BLOCK;
        r->fails = 0;
        r->first_fail = now;
    }
    pthread_mutex_unlock(&g_rl_lock);
}

void auth_rate_success(const char *ip)
{
    pthread_mutex_lock(&g_rl_lock);
    rl_t *r = rl_find(ip, false);
    if (r)
        memset(r, 0, sizeof *r);
    pthread_mutex_unlock(&g_rl_lock);
}

/* ================= TOTP ================= */

static uint64_t g_totp_last_step = 0;
static pthread_mutex_t g_totp_lock = PTHREAD_MUTEX_INITIALIZER;

void auth_totp_new_secret(char out[40])
{
    uint8_t k[20];
    random_bytes(k, sizeof k);
    base32_encode(k, sizeof k, out);
    secure_zero(k, sizeof k);
}

static void url_encode(const char *in, sb_t *out)
{
    static const char hx[] = "0123456789ABCDEF";
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
            *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            sb_appendc(out, (char)*p);
        } else {
            sb_appendc(out, '%');
            sb_appendc(out, hx[*p >> 4]);
            sb_appendc(out, hx[*p & 15]);
        }
    }
}

void auth_totp_uri(const char *secret, const char *user, char *out, size_t n)
{
    sb_t b;
    sb_init(&b);
    sb_append(&b, "otpauth://totp/");
    url_encode("Tuấn WireGuard", &b);
    sb_append(&b, ":");
    url_encode(user, &b);
    sb_printf(&b, "?secret=%s&issuer=", secret);
    url_encode("Tuấn WireGuard", &b);
    sb_append(&b, "&algorithm=SHA1&digits=6&period=30");
    str_copy(out, b.s, n);
    sb_free(&b);
}

bool auth_totp_check(const char *secret, const char *code)
{
    uint64_t now = (uint64_t)now_unix();
    uint8_t key[64];
    int kl = base32_decode(secret, key, sizeof key);
    if (kl <= 0 || !code)
        return false;
    char digits[8];
    size_t nd = 0;
    for (const char *p = code; *p; p++) {
        if (*p >= '0' && *p <= '9') {
            if (nd >= 6)
                return false;
            digits[nd++] = *p;
        } else if (*p != ' ' && *p != '-') {
            return false;
        }
    }
    if (nd != 6)
        return false;
    digits[6] = 0;
    uint32_t want = (uint32_t)strtoul(digits, NULL, 10);
    bool ok = false;
    pthread_mutex_lock(&g_totp_lock);
    for (int w = -1; w <= 1; w++) {
        uint64_t step = now / 30 + (uint64_t)(int64_t)w;
        if (step <= g_totp_last_step)
            continue;
        if (totp_code(key, (size_t)kl, step * 30, 30, 6) == want) {
            g_totp_last_step = step;
            ok = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_totp_lock);
    secure_zero(key, sizeof key);
    return ok;
}
