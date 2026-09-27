/*
 * Tuấn WireGuard - điều khiển WireGuard (wg, wg-quick)
 * Tác giả: Tuandethuong
 */
#include "wg.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app.h"
#include "net.h"

bool wg_iface_up(const char *iface)
{
    return net_iface_exists(iface);
}

bool wg_tools_installed(void)
{
    return have_cmd("wg") && have_cmd("wg-quick");
}

static char g_wg_version[64];
static pthread_once_t g_wg_version_once = PTHREAD_ONCE_INIT;

static void wg_version_init(void)
{
    const char *argv[] = {"wg", "--version", NULL};
    cmd_result_t r;
    if (run_cmd(argv, NULL, NULL, 3000, &r) == 0 && r.out) {
        /* "wireguard-tools v1.0.20210914 - https://git.zx2c4.com/wireguard-tools/" */
        char *v = strstr(r.out, " v");
        if (v) {
            v += 2;
            size_t n = strcspn(v, " \n");
            if (n >= sizeof g_wg_version)
                n = sizeof g_wg_version - 1;
            memcpy(g_wg_version, v, n);
            g_wg_version[n] = 0;
        }
    }
    cmd_result_free(&r);
}

const char *wg_version(void)
{
    pthread_once(&g_wg_version_once, wg_version_init);
    return g_wg_version;
}

void wg_status_free(wg_status_t *st)
{
    free(st->peers);
    st->peers = NULL;
    st->npeers = 0;
}

int wg_dump(const char *iface, wg_status_t *st, char *err, size_t errsz)
{
    memset(st, 0, sizeof *st);
    if (!wg_iface_up(iface))
        return 0;
    const char *argv[] = {"wg", "show", iface, "dump", NULL};
    cmd_result_t r;
    if (run_cmd(argv, NULL, NULL, 5000, &r) != 0) {
        str_copy(err, r.out ? r.out : "wg show lỗi", errsz);
        str_trim(err);
        cmd_result_free(&r);
        return -1;
    }
    st->up = true;
    int cap = 0;
    char *save = NULL;
    int lineno = 0;
    for (char *line = strtok_r(r.out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *f[9];
        int nf = 0;
        char *fs = NULL;
        for (char *t = strtok_r(line, "\t", &fs); t && nf < 9; t = strtok_r(NULL, "\t", &fs))
            f[nf++] = t;
        if (lineno++ == 0) {
            if (nf >= 3) {
                str_copy(st->public_key, f[1], sizeof st->public_key);
                st->listen_port = atoi(f[2]);
            }
            continue;
        }
        if (nf < 8)
            continue;
        if (st->npeers == cap) {
            cap = cap ? cap * 2 : 32;
            st->peers = xrealloc(st->peers, (size_t)cap * sizeof(wg_peer_t));
        }
        wg_peer_t *p = &st->peers[st->npeers++];
        memset(p, 0, sizeof *p);
        str_copy(p->public_key, f[0], sizeof p->public_key);
        if (strcmp(f[2], "(none)") != 0)
            str_copy(p->endpoint, f[2], sizeof p->endpoint);
        p->handshake = strtoll(f[4], NULL, 10);
        p->rx = strtoull(f[5], NULL, 10);
        p->tx = strtoull(f[6], NULL, 10);
    }
    cmd_result_free(&r);
    return 0;
}

/* ---------- quy tắc tường lửa tự động ---------- */

static void wan_iface(const settings_t *s, char *out, size_t n)
{
    if (s->wan_iface[0])
        str_copy(out, s->wan_iface, n);
    else if (net_default_iface(out, n) != 0)
        str_copy(out, "eth0", n);
}

static void subnet4(const settings_t *s, char *out, size_t n)
{
    uint32_t a;
    int p;
    if (cidr4_parse(s->address, &a, &p) != 0) {
        str_copy(out, "10.8.0.0/24", n);
        return;
    }
    uint32_t mask = p ? 0xFFFFFFFFu << (32 - p) : 0;
    char ip[16];
    ip4_format(a & mask, ip);
    snprintf(out, n, "%s/%d", ip, p);
}

static int subnet6(const settings_t *s, char *out, size_t n)
{
    uint8_t a[16];
    int p;
    if (!s->ipv6 || cidr6_parse(s->address6, a, &p) != 0)
        return -1;
    for (int bit = p; bit < 128; bit++)
        a[bit / 8] &= (uint8_t) ~(0x80 >> (bit % 8));
    char ip[46];
    ip6_format(a, ip);
    snprintf(out, n, "%s/%d", ip, p);
    return 0;
}

static void rules(const settings_t *s, bool up, char *out, size_t n)
{
    char wan[32], net4[64], net6[80];
    wan_iface(s, wan, sizeof wan);
    subnet4(s, net4, sizeof net4);
    bool v6 = subnet6(s, net6, sizeof net6) == 0;
    sb_t b;
    sb_init(&b);
    const char *tools[2] = {"iptables", "ip6tables"};
    const char *nets[2] = {net4, net6};
    if (up) {
        sb_append(&b, "sysctl -q -w net.ipv4.ip_forward=1 || true");
        if (v6)
            sb_append(&b, "; sysctl -q -w net.ipv6.conf.all.forwarding=1 || true");
    }
    for (int k = 0; k < (v6 ? 2 : 1); k++) {
        const char *t = tools[k];
        char r[5][256];
        int nr = 0;
        snprintf(r[nr++], sizeof r[0], "-t nat %%s POSTROUTING -s %s -o %s -j MASQUERADE", nets[k], wan);
        snprintf(r[nr++], sizeof r[0], "%%s INPUT -p udp --dport %d -j ACCEPT", s->listen_port);
        snprintf(r[nr++], sizeof r[0], "%%s FORWARD -i %%%%i -j ACCEPT");
        snprintf(r[nr++], sizeof r[0], "%%s FORWARD -o %%%%i -j ACCEPT");
        if (s->client_isolation)
            snprintf(r[nr++], sizeof r[0], "%%s FORWARD -i %%%%i -o %%%%i -j DROP");
        for (int i = 0; i < nr; i++) {
            char chk[300], act[300];
            bool nat = i == 0;
            snprintf(chk, sizeof chk, r[i], "-C");
            snprintf(act, sizeof act, r[i], up ? (nat ? "-A" : "-I") : "-D");
            if (b.len)
                sb_append(&b, "; ");
            if (up)
                sb_printf(&b, "%s %s 2>/dev/null || %s %s", t, chk, t, act);
            else
                sb_printf(&b, "%s %s 2>/dev/null || true", t, act);
        }
    }
    str_copy(out, b.s ? b.s : "", n);
    sb_free(&b);
}

void wg_auto_postup(const settings_t *s, char *out, size_t n)
{
    rules(s, true, out, n);
}

void wg_auto_postdown(const settings_t *s, char *out, size_t n)
{
    rules(s, false, out, n);
}

/* ---------- sinh cấu hình ---------- */

void wg_build_server_conf(const db_t *db, sb_t *out, bool strip)
{
    const settings_t *s = &db->s;
    if (!strip) {
        sb_append(out, "# Tuấn WireGuard - tệp này được tạo tự động, vui lòng không sửa trực tiếp.\n"
                       "# Hãy thay đổi cấu hình qua giao diện web hoặc lệnh `tuan-wg`.\n");
    }
    sb_append(out, "[Interface]\n");
    sb_printf(out, "PrivateKey = %s\n", s->private_key);
    if (!strip) {
        sb_printf(out, "Address = %s", s->address);
        if (s->ipv6 && s->address6[0])
            sb_printf(out, ", %s", s->address6);
        sb_append(out, "\n");
    }
    sb_printf(out, "ListenPort = %d\n", s->listen_port);
    if (!strip) {
        if (s->mtu > 0)
            sb_printf(out, "MTU = %d\n", s->mtu);
        char rule[4096];
        if (s->post_up[0])
            sb_printf(out, "PostUp = %s\n", s->post_up);
        else {
            wg_auto_postup(s, rule, sizeof rule);
            sb_printf(out, "PostUp = %s\n", rule);
        }
        if (s->post_down[0])
            sb_printf(out, "PostDown = %s\n", s->post_down);
        else {
            wg_auto_postdown(s, rule, sizeof rule);
            sb_printf(out, "PostDown = %s\n", rule);
        }
    }
    for (int i = 0; i < db->nclients; i++) {
        const client_t *c = &db->clients[i];
        if (!c->enabled || !c->address[0])
            continue;
        sb_append(out, "\n");
        if (!strip)
            sb_printf(out, "### %s (%s)\n", c->name, c->id);
        sb_append(out, "[Peer]\n");
        sb_printf(out, "PublicKey = %s\n", c->public_key);
        if (c->preshared_key[0])
            sb_printf(out, "PresharedKey = %s\n", c->preshared_key);
        sb_printf(out, "AllowedIPs = %s/32", c->address);
        if (s->ipv6 && c->address6[0])
            sb_printf(out, ", %s/128", c->address6);
        sb_append(out, "\n");
    }
}

void wg_endpoint_string(const settings_t *s, char *out, size_t n)
{
    char host[300];
    str_copy(host, s->endpoint, sizeof host);
    str_trim(host);
    if (!host[0] && net_local_ip(host, sizeof host) != 0)
        str_copy(host, "YOUR_SERVER_IP", sizeof host);
    uint8_t a6[16];
    if (host[0] == '[') {
        if (strstr(host, "]:"))
            str_copy(out, host, n);
        else
            snprintf(out, n, "%s:%d", host, s->listen_port);
    } else if (ip6_parse(host, a6) == 0) {
        snprintf(out, n, "[%s]:%d", host, s->listen_port);
    } else if (strchr(host, ':')) {
        str_copy(out, host, n); /* đã có cổng */
    } else {
        snprintf(out, n, "%s:%d", host, s->listen_port);
    }
}

void wg_build_client_conf(const db_t *db, const client_t *c, sb_t *out, bool with_comment)
{
    const settings_t *s = &db->s;
    if (with_comment)
        sb_printf(out, "# Tuấn WireGuard - %s\n", c->name);
    sb_append(out, "[Interface]\n");
    sb_printf(out, "PrivateKey = %s\n", c->private_key[0] ? c->private_key : "<không có khóa riêng>");
    sb_printf(out, "Address = %s/32", c->address);
    if (s->ipv6 && c->address6[0])
        sb_printf(out, ", %s/128", c->address6);
    sb_append(out, "\n");
    const char *dns = c->dns[0] ? c->dns : s->dns;
    if (dns[0])
        sb_printf(out, "DNS = %s\n", dns);
    int mtu = c->mtu > 0 ? c->mtu : s->mtu;
    if (mtu > 0)
        sb_printf(out, "MTU = %d\n", mtu);
    sb_append(out, "\n[Peer]\n");
    sb_printf(out, "PublicKey = %s\n", s->public_key);
    if (c->preshared_key[0])
        sb_printf(out, "PresharedKey = %s\n", c->preshared_key);
    sb_printf(out, "AllowedIPs = %s\n", c->allowed_ips[0] ? c->allowed_ips : s->allowed_ips);
    char ep[320];
    wg_endpoint_string(s, ep, sizeof ep);
    sb_printf(out, "Endpoint = %s\n", ep);
    int ka = c->keepalive >= 0 ? c->keepalive : s->keepalive;
    if (ka > 0)
        sb_printf(out, "PersistentKeepalive = %d\n", ka);
}

/* ---------- áp dụng ---------- */

static pthread_mutex_t g_apply_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *const WG_ENV[] = {"WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1", NULL};

static int run_logged(const char *const argv[], char *err, size_t errsz)
{
    cmd_result_t r;
    int rc = run_cmd(argv, WG_ENV, NULL, 60000, &r);
    if (rc != 0) {
        sb_t cmd;
        sb_init(&cmd);
        for (int i = 0; argv[i]; i++)
            sb_printf(&cmd, "%s%s", i ? " " : "", argv[i]);
        LOGW("Lệnh '%s' lỗi (mã %d): %s", cmd.s, r.status, r.out ? r.out : "");
        if (err && errsz) {
            char *o = r.out ? r.out : (char *)"";
            /* lấy dòng lỗi cuối cùng cho gọn */
            str_trim(o);
            char *last = strrchr(o, '\n');
            snprintf(err, errsz, "%s: %s", cmd.s, last ? last + 1 : o);
        }
        sb_free(&cmd);
    }
    cmd_result_free(&r);
    return rc;
}

static bool unit_active(const char *unit)
{
    const char *argv[] = {"systemctl", "is-active", "--quiet", unit, NULL};
    cmd_result_t r;
    int rc = run_cmd(argv, NULL, NULL, 10000, &r);
    cmd_result_free(&r);
    return rc == 0;
}

/* wg-quick@ của systemd chỉ đọc /etc/wireguard; thư mục khác thì dùng đường dẫn đầy đủ */
static bool use_systemd_unit(void)
{
    return app_systemd_running() && strcmp(g_app.wg_dir, "/etc/wireguard") == 0;
}

static void quick_target(const char *iface, char *out, size_t n)
{
    if (strcmp(g_app.wg_dir, "/etc/wireguard") == 0)
        str_copy(out, iface, n);
    else
        snprintf(out, n, "%s/%s.conf", g_app.wg_dir, iface);
}

static int iface_start(const char *iface, char *err, size_t errsz)
{
    char unit[64], target[600];
    snprintf(unit, sizeof unit, "wg-quick@%s", iface);
    quick_target(iface, target, sizeof target);
    if (use_systemd_unit()) {
        const char *a1[] = {"systemctl", "start", unit, NULL};
        if (run_logged(a1, err, errsz) == 0 && wg_iface_up(iface))
            return 0;
        if (wg_iface_up(iface))
            return 0;
    }
    const char *a2[] = {"wg-quick", "up", target, NULL};
    return run_logged(a2, err, errsz);
}

static int iface_stop(const char *iface, char *err, size_t errsz)
{
    char unit[64], target[600];
    snprintf(unit, sizeof unit, "wg-quick@%s", iface);
    quick_target(iface, target, sizeof target);
    if (use_systemd_unit() && unit_active(unit)) {
        const char *a1[] = {"systemctl", "stop", unit, NULL};
        run_logged(a1, err, errsz);
    }
    if (wg_iface_up(iface)) {
        const char *a2[] = {"wg-quick", "down", target, NULL};
        return run_logged(a2, err, errsz);
    }
    return 0;
}

static int iface_restart(const char *iface, char *err, size_t errsz)
{
    char unit[64];
    snprintf(unit, sizeof unit, "wg-quick@%s", iface);
    if (use_systemd_unit() && unit_active(unit)) {
        const char *a[] = {"systemctl", "restart", unit, NULL};
        if (run_logged(a, err, errsz) == 0 && wg_iface_up(iface))
            return 0;
    }
    iface_stop(iface, NULL, 0);
    return iface_start(iface, err, errsz);
}

int wg_down(char *err, size_t errsz)
{
    char iface[16];
    app_rlock();
    str_copy(iface, g_db.s.iface, sizeof iface);
    app_runlock();
    if (g_app.demo || g_app.no_wg)
        return 0;
    pthread_mutex_lock(&g_apply_lock);
    int r = iface_stop(iface, err, errsz);
    pthread_mutex_unlock(&g_apply_lock);
    return r;
}

int wg_apply(bool restart, char *err, size_t errsz)
{
    if (err && errsz)
        err[0] = 0;
    if (g_app.demo)
        return 0;
    pthread_mutex_lock(&g_apply_lock);
    sb_t full, strip;
    sb_init(&full);
    sb_init(&strip);
    char iface[16];
    app_rlock();
    wg_build_server_conf(&g_db, &full, false);
    wg_build_server_conf(&g_db, &strip, true);
    str_copy(iface, g_db.s.iface, sizeof iface);
    app_runlock();

    int rc = 0;
    char path[512];
    snprintf(path, sizeof path, "%s/%s.conf", g_app.wg_dir, iface);
    mkdir_p(g_app.wg_dir, 0700);
    size_t oldlen = 0;
    char *old = file_read(path, &oldlen);
    bool changed = !old || oldlen != full.len || memcmp(old, full.s, full.len) != 0;
    free(old);
    if (changed && file_write_atomic(path, full.s, full.len, 0600) != 0) {
        snprintf(err, errsz, "không ghi được %s", path);
        rc = -1;
        goto out;
    }
    if (g_app.no_wg)
        goto out;
    if (!wg_tools_installed()) {
        str_copy(err, "Chưa cài đặt wireguard-tools (chạy: apt install wireguard-tools)", errsz);
        rc = -1;
        goto out;
    }
    if (!wg_iface_up(iface)) {
        LOGI("Khởi động interface %s", iface);
        rc = iface_start(iface, err, errsz);
    } else if (restart) {
        LOGI("Khởi động lại interface %s", iface);
        rc = iface_restart(iface, err, errsz);
    } else {
        char tmp[512];
        snprintf(tmp, sizeof tmp, "%s/.%s.sync.conf", g_app.data_dir, iface);
        if (file_write_atomic(tmp, strip.s, strip.len, 0600) != 0) {
            snprintf(err, errsz, "không ghi được %s", tmp);
            rc = -1;
            goto out;
        }
        const char *argv[] = {"wg", "syncconf", iface, tmp, NULL};
        rc = run_logged(argv, err, errsz);
        unlink(tmp);
    }
    if (rc == 0 && !wg_iface_up(iface)) {
        snprintf(err, errsz, "interface %s không hoạt động sau khi khởi động", iface);
        rc = -1;
    }
out:
    sb_free(&full);
    sb_free(&strip);
    pthread_mutex_unlock(&g_apply_lock);
    return rc;
}
