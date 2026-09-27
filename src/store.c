/*
 * Tuấn WireGuard - mô hình dữ liệu & lưu trữ (db.json)
 * Tác giả: Tuandethuong
 */
#include "store.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "net.h"

#define S_COPY(dst, src) str_copy((dst), (src), sizeof(dst))

void db_defaults(db_t *db)
{
    memset(db, 0, sizeof *db);
    settings_t *s = &db->s;
    S_COPY(s->iface, "wg0");
    s->listen_port = 51820;
    S_COPY(s->address, "10.8.0.1/24");
    s->ipv6 = false;
    S_COPY(s->address6, "fd42:42:42::1/64");
    S_COPY(s->dns, "1.1.1.1, 8.8.8.8");
    s->mtu = 0;
    s->keepalive = 25;
    S_COPY(s->allowed_ips, "0.0.0.0/0, ::/0");
    s->use_psk = true;
    s->client_isolation = false;
    s->tz_offset = 420;
    S_COPY(s->web_listen, "0.0.0.0");
    s->web_port = 51821;
    s->session_hours = 168;
    S_COPY(s->admin_user, "admin");
}

void db_free(db_t *db)
{
    free(db->clients);
    free(db->shares);
    db->clients = NULL;
    db->shares = NULL;
    db->nclients = db->capclients = db->nshares = db->capshares = 0;
}

/* ---------- JSON ---------- */

static void rd_str(const json_t *o, const char *k, char *dst, size_t n)
{
    const char *v = json_str(o, k, NULL);
    if (v)
        str_copy(dst, v, n);
}

#define RD_STR(o, k, dst) rd_str((o), (k), (dst), sizeof(dst))

int db_from_json(db_t *db, const json_t *j, char *err, size_t errsz)
{
    if (!j || j->type != J_OBJ) {
        str_copy(err, "dữ liệu không phải đối tượng JSON", errsz);
        return -1;
    }
    db_t n;
    db_defaults(&n);
    settings_t *s = &n.s;
    const json_t *sv = json_get(j, "server");
    if (sv) {
        RD_STR(sv, "interface", s->iface);
        s->listen_port = (int)json_int(sv, "listen_port", s->listen_port);
        RD_STR(sv, "private_key", s->private_key);
        RD_STR(sv, "public_key", s->public_key);
        RD_STR(sv, "address", s->address);
        s->ipv6 = json_bool(sv, "ipv6", s->ipv6);
        RD_STR(sv, "address6", s->address6);
        RD_STR(sv, "endpoint", s->endpoint);
        RD_STR(sv, "dns", s->dns);
        s->mtu = (int)json_int(sv, "mtu", s->mtu);
        s->keepalive = (int)json_int(sv, "keepalive", s->keepalive);
        RD_STR(sv, "allowed_ips", s->allowed_ips);
        RD_STR(sv, "wan_interface", s->wan_iface);
        RD_STR(sv, "post_up", s->post_up);
        RD_STR(sv, "post_down", s->post_down);
        s->client_isolation = json_bool(sv, "client_isolation", s->client_isolation);
        s->use_psk = json_bool(sv, "use_psk", s->use_psk);
        s->tz_offset = (int)json_int(sv, "tz_offset", s->tz_offset);
        s->installed_at = json_int(sv, "installed_at", 0);
    }
    const json_t *wv = json_get(j, "web");
    if (wv) {
        RD_STR(wv, "listen", s->web_listen);
        s->web_port = (int)json_int(wv, "port", s->web_port);
        s->session_hours = (int)json_int(wv, "session_hours", s->session_hours);
    }
    const json_t *av = json_get(j, "admin");
    if (av) {
        RD_STR(av, "username", s->admin_user);
        RD_STR(av, "password_hash", s->admin_hash);
        RD_STR(av, "totp_secret", s->totp_secret);
        s->totp_enabled = json_bool(av, "totp_enabled", 0);
    }
    const json_t *cl = json_get(j, "clients");
    for (int i = 0; i < json_len(cl); i++) {
        const json_t *o = json_at(cl, i);
        if (!o || o->type != J_OBJ)
            continue;
        client_t *c = db_client_add(&n);
        if (!c)
            break;
        RD_STR(o, "id", c->id);
        RD_STR(o, "name", c->name);
        RD_STR(o, "note", c->note);
        c->enabled = json_bool(o, "enabled", 1);
        RD_STR(o, "disabled_reason", c->disabled_reason);
        RD_STR(o, "private_key", c->private_key);
        RD_STR(o, "public_key", c->public_key);
        RD_STR(o, "preshared_key", c->preshared_key);
        RD_STR(o, "address", c->address);
        RD_STR(o, "address6", c->address6);
        RD_STR(o, "dns", c->dns);
        RD_STR(o, "allowed_ips", c->allowed_ips);
        c->keepalive = (int)json_int(o, "keepalive", -1);
        c->mtu = (int)json_int(o, "mtu", 0);
        c->created_at = json_int(o, "created_at", 0);
        c->updated_at = json_int(o, "updated_at", c->created_at);
        c->expires_at = json_int(o, "expires_at", 0);
        c->data_limit = json_int(o, "data_limit", 0);
        c->limit_monthly = json_bool(o, "limit_monthly", 0);
        if (!c->id[0] || !wg_key_valid(c->public_key)) {
            n.nclients--; /* bỏ bản ghi hỏng */
            continue;
        }
        if (c->private_key[0] && !wg_key_valid(c->private_key))
            c->private_key[0] = 0;
        if (c->preshared_key[0] && !wg_key_valid(c->preshared_key))
            c->preshared_key[0] = 0;
    }
    const json_t *sh = json_get(j, "shares");
    for (int i = 0; i < json_len(sh); i++) {
        const json_t *o = json_at(sh, i);
        share_t *x = db_share_add(&n);
        RD_STR(o, "token", x->token);
        RD_STR(o, "client_id", x->client_id);
        x->created_at = json_int(o, "created_at", 0);
        x->expires_at = json_int(o, "expires_at", 0);
        x->max_downloads = (int)json_int(o, "max_downloads", 0);
        x->downloads = (int)json_int(o, "downloads", 0);
        if (!x->token[0])
            n.nshares--;
    }
    n.file_sig = db->file_sig;
    db_free(db);
    *db = n;
    return 0;
}

void db_to_json(const db_t *db, sb_t *out)
{
    const settings_t *s = &db->s;
    jw_t w;
    jw_init(&w, out);
    jw_obj(&w);
    jw_kint(&w, "format", 1);
    jw_kstr(&w, "app", "tuan-wg");
    jw_key(&w, "server");
    jw_obj(&w);
    jw_kstr(&w, "interface", s->iface);
    jw_kint(&w, "listen_port", s->listen_port);
    jw_kstr(&w, "private_key", s->private_key);
    jw_kstr(&w, "public_key", s->public_key);
    jw_kstr(&w, "address", s->address);
    jw_kbool(&w, "ipv6", s->ipv6);
    jw_kstr(&w, "address6", s->address6);
    jw_kstr(&w, "endpoint", s->endpoint);
    jw_kstr(&w, "dns", s->dns);
    jw_kint(&w, "mtu", s->mtu);
    jw_kint(&w, "keepalive", s->keepalive);
    jw_kstr(&w, "allowed_ips", s->allowed_ips);
    jw_kstr(&w, "wan_interface", s->wan_iface);
    jw_kstr(&w, "post_up", s->post_up);
    jw_kstr(&w, "post_down", s->post_down);
    jw_kbool(&w, "client_isolation", s->client_isolation);
    jw_kbool(&w, "use_psk", s->use_psk);
    jw_kint(&w, "tz_offset", s->tz_offset);
    jw_kint(&w, "installed_at", s->installed_at);
    jw_obj_end(&w);
    jw_key(&w, "web");
    jw_obj(&w);
    jw_kstr(&w, "listen", s->web_listen);
    jw_kint(&w, "port", s->web_port);
    jw_kint(&w, "session_hours", s->session_hours);
    jw_obj_end(&w);
    jw_key(&w, "admin");
    jw_obj(&w);
    jw_kstr(&w, "username", s->admin_user);
    jw_kstr(&w, "password_hash", s->admin_hash);
    jw_kstr(&w, "totp_secret", s->totp_secret);
    jw_kbool(&w, "totp_enabled", s->totp_enabled);
    jw_obj_end(&w);
    jw_key(&w, "clients");
    jw_arr(&w);
    for (int i = 0; i < db->nclients; i++) {
        const client_t *c = &db->clients[i];
        sb_append(out, i ? ",\n  " : "\n  ");
        jw_obj(&w);
        jw_kstr(&w, "id", c->id);
        jw_kstr(&w, "name", c->name);
        jw_kstr(&w, "note", c->note);
        jw_kbool(&w, "enabled", c->enabled);
        jw_kstr(&w, "disabled_reason", c->disabled_reason);
        jw_kstr(&w, "private_key", c->private_key);
        jw_kstr(&w, "public_key", c->public_key);
        jw_kstr(&w, "preshared_key", c->preshared_key);
        jw_kstr(&w, "address", c->address);
        jw_kstr(&w, "address6", c->address6);
        jw_kstr(&w, "dns", c->dns);
        jw_kstr(&w, "allowed_ips", c->allowed_ips);
        jw_kint(&w, "keepalive", c->keepalive);
        jw_kint(&w, "mtu", c->mtu);
        jw_kint(&w, "created_at", c->created_at);
        jw_kint(&w, "updated_at", c->updated_at);
        jw_kint(&w, "expires_at", c->expires_at);
        jw_kint(&w, "data_limit", c->data_limit);
        jw_kbool(&w, "limit_monthly", c->limit_monthly);
        jw_obj_end(&w);
        w.comma[w.depth] = 0; /* dấu phẩy đã thêm thủ công */
    }
    jw_arr_end(&w);
    w.comma[w.depth] = 1;
    jw_key(&w, "shares");
    jw_arr(&w);
    for (int i = 0; i < db->nshares; i++) {
        const share_t *x = &db->shares[i];
        jw_obj(&w);
        jw_kstr(&w, "token", x->token);
        jw_kstr(&w, "client_id", x->client_id);
        jw_kint(&w, "created_at", x->created_at);
        jw_kint(&w, "expires_at", x->expires_at);
        jw_kint(&w, "max_downloads", x->max_downloads);
        jw_kint(&w, "downloads", x->downloads);
        jw_obj_end(&w);
    }
    jw_arr_end(&w);
    jw_obj_end(&w);
    sb_appendc(out, '\n');
}

int db_load_file(db_t *db, const char *path, char *err, size_t errsz)
{
    size_t len;
    char *data = file_read(path, &len);
    if (!data) {
        str_copy(err, "chưa có file dữ liệu", errsz);
        return 1;
    }
    char perr[128];
    json_t *j = json_parse(data, len, perr, sizeof perr);
    free(data);
    if (!j) {
        snprintf(err, errsz, "file dữ liệu hỏng: %s", perr);
        return -1;
    }
    int r = db_from_json(db, j, err, errsz);
    json_free(j);
    if (r == 0)
        db->file_sig = file_mtime_ns(path);
    return r;
}

int db_save_file(db_t *db, const char *path)
{
    sb_t b;
    sb_init(&b);
    db_to_json(db, &b);
    int r = file_write_atomic(path, b.s, b.len, 0600);
    sb_free(&b);
    if (r == 0)
        db->file_sig = file_mtime_ns(path);
    return r;
}

/* ---------- clients ---------- */

int db_client_index(const db_t *db, const char *id)
{
    for (int i = 0; i < db->nclients; i++)
        if (strcmp(db->clients[i].id, id) == 0)
            return i;
    return -1;
}

client_t *db_client_by_id(db_t *db, const char *id)
{
    int i = db_client_index(db, id);
    return i >= 0 ? &db->clients[i] : NULL;
}

client_t *db_client_by_name(db_t *db, const char *name)
{
    for (int i = 0; i < db->nclients; i++)
        if (strcasecmp(db->clients[i].name, name) == 0)
            return &db->clients[i];
    return NULL;
}

client_t *db_client_by_pubkey(db_t *db, const char *pk)
{
    for (int i = 0; i < db->nclients; i++)
        if (strcmp(db->clients[i].public_key, pk) == 0)
            return &db->clients[i];
    return NULL;
}

client_t *db_client_find(db_t *db, const char *q)
{
    client_t *c = db_client_by_id(db, q);
    if (!c)
        c = db_client_by_name(db, q);
    if (!c) {
        for (int i = 0; i < db->nclients; i++)
            if (strcmp(db->clients[i].address, q) == 0)
                return &db->clients[i];
    }
    return c;
}

client_t *db_client_add(db_t *db)
{
    if (db->nclients >= TWG_MAX_CLIENTS)
        return NULL;
    if (db->nclients == db->capclients) {
        db->capclients = db->capclients ? db->capclients * 2 : 16;
        db->clients = xrealloc(db->clients, (size_t)db->capclients * sizeof(client_t));
    }
    client_t *c = &db->clients[db->nclients++];
    memset(c, 0, sizeof *c);
    c->keepalive = -1;
    return c;
}

void db_client_remove(db_t *db, int idx)
{
    if (idx < 0 || idx >= db->nclients)
        return;
    memmove(&db->clients[idx], &db->clients[idx + 1],
            (size_t)(db->nclients - idx - 1) * sizeof(client_t));
    db->nclients--;
}

/* ---------- địa chỉ IP ---------- */

int db_subnet(const db_t *db, uint32_t *network, int *prefix, uint32_t *server_ip)
{
    uint32_t a;
    int p;
    if (cidr4_parse(db->s.address, &a, &p) != 0 || p < 8 || p > 30)
        return -1;
    uint32_t mask = p == 0 ? 0 : 0xFFFFFFFFu << (32 - p);
    if (network)
        *network = a & mask;
    if (prefix)
        *prefix = p;
    if (server_ip)
        *server_ip = a;
    return 0;
}

static bool ipv4_used(const db_t *db, uint32_t ip, int skip_idx)
{
    for (int i = 0; i < db->nclients; i++) {
        if (i == skip_idx)
            continue;
        uint32_t a;
        if (ip4_parse(db->clients[i].address, &a) == 0 && a == ip)
            return true;
    }
    return false;
}

int db_alloc_ipv4(const db_t *db, char *out, size_t n)
{
    uint32_t net, srv;
    int p;
    if (db_subnet(db, &net, &p, &srv) != 0)
        return -1;
    uint32_t hosts = (p >= 31) ? 0 : ((1u << (32 - p)) - 2);
    for (uint32_t k = 1; k <= hosts; k++) {
        uint32_t ip = net + k;
        if (ip == srv || ipv4_used(db, ip, -1))
            continue;
        char buf[16];
        ip4_format(ip, buf);
        str_copy(out, buf, n);
        return 0;
    }
    return -1;
}

int db_ipv6_for(const db_t *db, const char *ipv4, char *out, size_t n)
{
    uint32_t net, ip;
    int p4, p6;
    uint8_t a6[16];
    if (!db->s.ipv6 || db_subnet(db, &net, &p4, NULL) != 0 || ip4_parse(ipv4, &ip) != 0 ||
        cidr6_parse(db->s.address6, a6, &p6) != 0)
        return -1;
    uint32_t offset = ip - net;
    int hostbits = 128 - p6;
    if (hostbits < 32 && offset >= (1u << hostbits))
        return -1;
    /* xóa phần host của prefix */
    for (int bit = p6; bit < 128; bit++)
        a6[bit / 8] &= (uint8_t) ~(0x80 >> (bit % 8));
    uint32_t low = ((uint32_t)a6[12] << 24) | ((uint32_t)a6[13] << 16) | ((uint32_t)a6[14] << 8) | a6[15];
    low += offset;
    a6[12] = (uint8_t)(low >> 24);
    a6[13] = (uint8_t)(low >> 16);
    a6[14] = (uint8_t)(low >> 8);
    a6[15] = (uint8_t)low;
    char buf[46];
    ip6_format(a6, buf);
    str_copy(out, buf, n);
    return 0;
}

void db_refresh_ipv6(db_t *db)
{
    for (int i = 0; i < db->nclients; i++) {
        client_t *c = &db->clients[i];
        if (!db->s.ipv6 || db_ipv6_for(db, c->address, c->address6, sizeof c->address6) != 0)
            c->address6[0] = 0;
    }
}

void db_renumber(db_t *db, const char *old_address)
{
    uint32_t oa, nnet, nsrv;
    int op, np;
    if (cidr4_parse(old_address, &oa, &op) != 0 || db_subnet(db, &nnet, &np, &nsrv) != 0)
        return;
    uint32_t omask = op == 0 ? 0 : 0xFFFFFFFFu << (32 - op);
    uint32_t onet = oa & omask;
    uint32_t nhosts = (1u << (32 - np)) - 2;
    uint32_t *want = xcalloc((size_t)db->nclients + 1, sizeof(uint32_t));
    for (int i = 0; i < db->nclients; i++) {
        uint32_t ip;
        if (ip4_parse(db->clients[i].address, &ip) != 0)
            continue;
        uint32_t off = ip - onet;
        if (off >= 1 && off <= nhosts && nnet + off != nsrv)
            want[i] = nnet + off;
    }
    /* loại trùng */
    for (int i = 0; i < db->nclients; i++)
        for (int k = 0; k < i; k++)
            if (want[i] && want[i] == want[k])
                want[i] = 0;
    for (int i = 0; i < db->nclients; i++) {
        if (want[i])
            ip4_format(want[i], db->clients[i].address);
        else
            db->clients[i].address[0] = 0;
    }
    for (int i = 0; i < db->nclients; i++)
        if (!db->clients[i].address[0])
            db_alloc_ipv4(db, db->clients[i].address, sizeof db->clients[i].address);
    free(want);
    db_refresh_ipv6(db);
}

/* ---------- shares ---------- */

share_t *db_share_by_token(db_t *db, const char *token)
{
    size_t tl = strlen(token);
    for (int i = 0; i < db->nshares; i++) {
        share_t *x = &db->shares[i];
        if (strlen(x->token) == tl && ct_equal(x->token, token, tl))
            return x;
    }
    return NULL;
}

share_t *db_share_add(db_t *db)
{
    if (db->nshares == db->capshares) {
        db->capshares = db->capshares ? db->capshares * 2 : 8;
        db->shares = xrealloc(db->shares, (size_t)db->capshares * sizeof(share_t));
    }
    share_t *x = &db->shares[db->nshares++];
    memset(x, 0, sizeof *x);
    return x;
}

void db_share_remove(db_t *db, int idx)
{
    if (idx < 0 || idx >= db->nshares)
        return;
    memmove(&db->shares[idx], &db->shares[idx + 1],
            (size_t)(db->nshares - idx - 1) * sizeof(share_t));
    db->nshares--;
}

void db_shares_prune(db_t *db, int64_t now)
{
    for (int i = db->nshares - 1; i >= 0; i--) {
        share_t *x = &db->shares[i];
        bool dead = (x->expires_at && now >= x->expires_at) ||
                    (x->max_downloads && x->downloads >= x->max_downloads) ||
                    !db_client_by_id(db, x->client_id);
        if (dead)
            db_share_remove(db, i);
    }
}

void db_client_shares_remove(db_t *db, const char *client_id)
{
    for (int i = db->nshares - 1; i >= 0; i--)
        if (strcmp(db->shares[i].client_id, client_id) == 0)
            db_share_remove(db, i);
}

/* ---------- kiểm tra dữ liệu ---------- */

bool client_expired(const client_t *c, int64_t now)
{
    return c->expires_at > 0 && now >= c->expires_at;
}

static int clean_text(const char *in, char *out, size_t outsz, size_t max_chars, bool required,
                      const char *field, char *err, size_t errsz)
{
    char buf[2048];
    str_copy(buf, in, sizeof buf);
    for (char *p = buf; *p; p++)
        if (*p == '\n' || *p == '\r' || *p == '\t')
            *p = ' ';
    str_strip_ctrl(buf);
    str_trim(buf);
    if (!utf8_valid(buf)) {
        snprintf(err, errsz, "%s chứa ký tự không hợp lệ", field);
        return -1;
    }
    if (required && !buf[0]) {
        snprintf(err, errsz, "%s không được để trống", field);
        return -1;
    }
    if (utf8_len(buf) > max_chars) {
        snprintf(err, errsz, "%s tối đa %zu ký tự", field, max_chars);
        return -1;
    }
    utf8_truncate(buf, outsz - 1);
    str_copy(out, buf, outsz);
    return 0;
}

int client_init_new(db_t *db, client_t *c, char *err, size_t errsz)
{
    char id[24];
    do {
        char hx[17];
        random_hex(hx, 8);
        snprintf(id, sizeof id, "c%s", hx);
    } while (db_client_by_id(db, id));
    S_COPY(c->id, id);
    if (wg_genkey(c->private_key, c->public_key) != 0) {
        str_copy(err, "không tạo được khóa", errsz);
        return -1;
    }
    if (db->s.use_psk)
        wg_genpsk(c->preshared_key);
    if (db_alloc_ipv4(db, c->address, sizeof c->address) != 0) {
        str_copy(err, "hết địa chỉ IP trong dải mạng VPN", errsz);
        return -1;
    }
    if (db->s.ipv6)
        db_ipv6_for(db, c->address, c->address6, sizeof c->address6);
    c->enabled = true;
    c->keepalive = -1;
    c->created_at = c->updated_at = now_unix();
    return 0;
}

int client_apply_json(db_t *db, client_t *c, int self, const json_t *in, bool creating, char *err,
                      size_t errsz)
{
    const char *v;
    if ((v = json_str(in, "name", NULL)) || creating) {
        char name[256];
        if (clean_text(v ? v : "", name, sizeof name, TWG_NAME_MAX, true, "Tên", err, errsz) != 0)
            return -1;
        client_t *dup = db_client_by_name(db, name);
        if (dup && strcmp(dup->id, c->id) != 0) {
            snprintf(err, errsz, "Tên \"%s\" đã tồn tại", name);
            return -1;
        }
        S_COPY(c->name, name);
    }
    if ((v = json_str(in, "note", NULL))) {
        if (clean_text(v, c->note, sizeof c->note, TWG_NOTE_MAX, false, "Ghi chú", err, errsz) != 0)
            return -1;
    }
    if ((v = json_str(in, "dns", NULL))) {
        char norm[256];
        if (dns_list_normalize(v, norm, sizeof norm) != 0) {
            str_copy(err, "DNS không hợp lệ", errsz);
            return -1;
        }
        S_COPY(c->dns, norm);
    }
    if ((v = json_str(in, "allowed_ips", NULL))) {
        char norm[512];
        if (cidr_list_normalize(v, norm, sizeof norm) != 0) {
            str_copy(err, "AllowedIPs không hợp lệ (ví dụ: 0.0.0.0/0, ::/0)", errsz);
            return -1;
        }
        S_COPY(c->allowed_ips, norm);
    }
    if (json_has(in, "keepalive")) {
        int k = (int)json_int(in, "keepalive", -1);
        if (k < -1 || k > 3600) {
            str_copy(err, "Keepalive phải trong khoảng 0-3600 giây", errsz);
            return -1;
        }
        c->keepalive = k;
    }
    if (json_has(in, "mtu")) {
        int m = (int)json_int(in, "mtu", 0);
        if (m != 0 && (m < 576 || m > 9000)) {
            str_copy(err, "MTU phải trong khoảng 576-9000 (0 = mặc định)", errsz);
            return -1;
        }
        c->mtu = m;
    }
    if (json_has(in, "expires_at")) {
        int64_t e = json_int(in, "expires_at", 0);
        if (e < 0) {
            str_copy(err, "Ngày hết hạn không hợp lệ", errsz);
            return -1;
        }
        c->expires_at = e;
    }
    if (json_has(in, "data_limit")) {
        int64_t d = json_int(in, "data_limit", 0);
        if (d < 0) {
            str_copy(err, "Hạn mức dung lượng không hợp lệ", errsz);
            return -1;
        }
        c->data_limit = d;
    }
    if (json_has(in, "limit_monthly"))
        c->limit_monthly = json_bool(in, "limit_monthly", 0);
    if ((v = json_str(in, "address", NULL)) && *v && strcmp(v, c->address) != 0) {
        uint32_t ip, net, srv;
        int p;
        if (ip4_parse(v, &ip) != 0 || db_subnet(db, &net, &p, &srv) != 0) {
            str_copy(err, "Địa chỉ IP không hợp lệ", errsz);
            return -1;
        }
        uint32_t mask = 0xFFFFFFFFu << (32 - p);
        uint32_t bcast = net | ~mask;
        if ((ip & mask) != net || ip == net || ip == bcast || ip == srv) {
            str_copy(err, "Địa chỉ IP phải thuộc dải mạng VPN và không trùng máy chủ", errsz);
            return -1;
        }
        if (ipv4_used(db, ip, self)) {
            str_copy(err, "Địa chỉ IP đã được dùng", errsz);
            return -1;
        }
        ip4_format(ip, c->address);
        if (db->s.ipv6)
            db_ipv6_for(db, c->address, c->address6, sizeof c->address6);
    }
    if (json_has(in, "enabled")) {
        bool en = json_bool(in, "enabled", 1);
        if (en && !c->enabled) {
            c->enabled = true;
            c->disabled_reason[0] = 0;
        } else if (!en && c->enabled) {
            c->enabled = false;
            S_COPY(c->disabled_reason, "manual");
        }
    }
    /* gia hạn -> tự bật lại */
    if (!c->enabled && strcmp(c->disabled_reason, "expired") == 0 && !client_expired(c, now_unix())) {
        c->enabled = true;
        c->disabled_reason[0] = 0;
    }
    c->updated_at = now_unix();
    return 0;
}

static int check_int(const json_t *in, const char *k, int lo, int hi, int *dst, const char *label,
                     char *err, size_t errsz)
{
    if (!json_has(in, k))
        return 0;
    int64_t v = json_int(in, k, INT64_MIN);
    if (v < lo || v > hi) {
        snprintf(err, errsz, "%s phải trong khoảng %d-%d", label, lo, hi);
        return -1;
    }
    *dst = (int)v;
    return 0;
}

int settings_apply_json(db_t *db, const json_t *in, int *flags, char *err, size_t errsz)
{
    settings_t ns = db->s;
    const char *v;
    int f = 0;
    char old_address[48];
    S_COPY(old_address, db->s.address);

    if ((v = json_str(in, "endpoint", NULL))) {
        char e[256];
        S_COPY(e, v);
        str_trim(e);
        if (*e && !host_valid(e)) {
            str_copy(err, "Endpoint (tên miền/IP máy chủ) không hợp lệ", errsz);
            return -1;
        }
        S_COPY(ns.endpoint, e);
    }
    if (check_int(in, "listen_port", 1, 65535, &ns.listen_port, "Cổng WireGuard", err, errsz) ||
        check_int(in, "mtu", 0, 9000, &ns.mtu, "MTU", err, errsz) ||
        check_int(in, "keepalive", 0, 3600, &ns.keepalive, "Keepalive", err, errsz) ||
        check_int(in, "tz_offset", -720, 840, &ns.tz_offset, "Múi giờ", err, errsz) ||
        check_int(in, "web_port", 1, 65535, &ns.web_port, "Cổng web", err, errsz) ||
        check_int(in, "session_hours", 1, 8760, &ns.session_hours, "Thời gian phiên", err, errsz))
        return -1;
    if (ns.mtu != 0 && ns.mtu < 576) {
        str_copy(err, "MTU phải từ 576 trở lên (0 = tự động)", errsz);
        return -1;
    }
    if ((v = json_str(in, "address", NULL))) {
        uint32_t a;
        int p;
        char t[64];
        S_COPY(t, v);
        str_trim(t);
        if (cidr4_parse(t, &a, &p) != 0 || !strchr(t, '/') || p < 16 || p > 29) {
            str_copy(err, "Dải địa chỉ VPN phải dạng 10.8.0.1/24 (prefix 16-29)", errsz);
            return -1;
        }
        uint32_t mask = 0xFFFFFFFFu << (32 - p);
        if ((a & mask) == a || (a | ~mask) == a) {
            str_copy(err, "Địa chỉ máy chủ không được là địa chỉ mạng/broadcast", errsz);
            return -1;
        }
        char norm[48], ip[16];
        ip4_format(a, ip);
        snprintf(norm, sizeof norm, "%s/%d", ip, p);
        uint32_t hosts = (1u << (32 - p)) - 3;
        if ((uint32_t)db->nclients > hosts) {
            str_copy(err, "Dải mạng mới quá nhỏ so với số người dùng hiện có", errsz);
            return -1;
        }
        S_COPY(ns.address, norm);
    }
    if (json_has(in, "ipv6"))
        ns.ipv6 = json_bool(in, "ipv6", 0);
    if ((v = json_str(in, "address6", NULL))) {
        uint8_t a6[16];
        int p;
        char t[80];
        S_COPY(t, v);
        str_trim(t);
        if (*t || ns.ipv6) {
            if (cidr6_parse(t, a6, &p) != 0 || !strchr(t, '/') || p < 48 || p > 120) {
                str_copy(err, "Dải IPv6 phải dạng fd42:42:42::1/64 (prefix 48-120)", errsz);
                return -1;
            }
        }
        S_COPY(ns.address6, t);
    }
    if (ns.ipv6 && !ns.address6[0]) {
        str_copy(err, "Cần nhập dải IPv6 khi bật IPv6", errsz);
        return -1;
    }
    if ((v = json_str(in, "dns", NULL))) {
        char norm[256];
        if (dns_list_normalize(v, norm, sizeof norm) != 0) {
            str_copy(err, "DNS không hợp lệ", errsz);
            return -1;
        }
        S_COPY(ns.dns, norm);
    }
    if ((v = json_str(in, "allowed_ips", NULL))) {
        char norm[512];
        if (cidr_list_normalize(v, norm, sizeof norm) != 0 || !norm[0]) {
            str_copy(err, "AllowedIPs mặc định không hợp lệ", errsz);
            return -1;
        }
        S_COPY(ns.allowed_ips, norm);
    }
    if ((v = json_str(in, "wan_interface", NULL))) {
        char t[32];
        S_COPY(t, v);
        str_trim(t);
        if (*t && !iface_name_valid(t)) {
            str_copy(err, "Tên card mạng WAN không hợp lệ", errsz);
            return -1;
        }
        S_COPY(ns.wan_iface, t);
    }
    if ((v = json_str(in, "post_up", NULL))) {
        char t[2048];
        S_COPY(t, v);
        str_strip_ctrl(t);
        str_trim(t);
        S_COPY(ns.post_up, t);
    }
    if ((v = json_str(in, "post_down", NULL))) {
        char t[2048];
        S_COPY(t, v);
        str_strip_ctrl(t);
        str_trim(t);
        S_COPY(ns.post_down, t);
    }
    if (json_has(in, "client_isolation"))
        ns.client_isolation = json_bool(in, "client_isolation", 0);
    if (json_has(in, "use_psk"))
        ns.use_psk = json_bool(in, "use_psk", 1);
    if ((v = json_str(in, "web_listen", NULL))) {
        char t[64];
        uint32_t a4;
        uint8_t a6[16];
        S_COPY(t, v);
        str_trim(t);
        if (ip4_parse(t, &a4) != 0 && ip6_parse(t, a6) != 0) {
            str_copy(err, "Địa chỉ lắng nghe web phải là IP (vd: 0.0.0.0)", errsz);
            return -1;
        }
        S_COPY(ns.web_listen, t);
    }

    const settings_t *o = &db->s;
    if (ns.listen_port != o->listen_port || strcmp(ns.address, o->address) != 0 ||
        ns.ipv6 != o->ipv6 || strcmp(ns.address6, o->address6) != 0 || ns.mtu != o->mtu ||
        strcmp(ns.wan_iface, o->wan_iface) != 0 || strcmp(ns.post_up, o->post_up) != 0 ||
        strcmp(ns.post_down, o->post_down) != 0 || ns.client_isolation != o->client_isolation)
        f |= APPLY_RESTART_WG;
    if (ns.web_port != o->web_port || strcmp(ns.web_listen, o->web_listen) != 0)
        f |= APPLY_RESTART_WEB;

    bool subnet_changed = strcmp(ns.address, o->address) != 0;
    bool v6_changed = ns.ipv6 != o->ipv6 || strcmp(ns.address6, o->address6) != 0;
    db->s = ns;
    if (subnet_changed)
        db_renumber(db, old_address);
    else if (v6_changed)
        db_refresh_ipv6(db);
    if (flags)
        *flags = f;
    return 0;
}
