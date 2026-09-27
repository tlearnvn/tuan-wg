/*
 * Tuấn WireGuard - trình cài đặt, gỡ cài đặt và quản lý dịch vụ systemd
 * Tác giả: Tuandethuong
 */
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "app.h"
#include "auth.h"
#include "cli.h"
#include "crypto.h"
#include "net.h"
#include "wg.h"

#define UNIT_NAME "tuan-wg.service"
#define UNIT_ETC "/etc/systemd/system/tuan-wg.service"
#define SYSCTL_FILE "/etc/sysctl.d/99-tuan-wg.conf"
#define BIN_LOCAL "/usr/local/bin/tuan-wg"
#define BIN_PKG "/usr/bin/tuan-wg"

static int g_step = 0, g_steps = 7;

static void step(const char *msg)
{
    g_step++;
    printf("%s[%d/%d]%s %s\n", C_CYAN, g_step, g_steps, C_RESET, msg);
}

static void ok(const char *fmt, const char *arg)
{
    printf("      %s✔%s ", C_GREEN, C_RESET);
    printf(fmt, arg ? arg : "");
    printf("\n");
}

static void warn(const char *fmt, const char *arg)
{
    printf("      %s!%s ", C_YELLOW, C_RESET);
    printf(fmt, arg ? arg : "");
    printf("\n");
}

static int sh(const char *const argv[], int timeout_ms, bool show_err)
{
    cmd_result_t r;
    int rc = run_cmd(argv, NULL, NULL, timeout_ms, &r);
    if (rc != 0 && show_err && r.out && r.out[0]) {
        char *o = r.out;
        str_trim(o);
        char *last = strrchr(o, '\n');
        printf("        %s%s%s\n", C_DIM, last ? last + 1 : o, C_RESET);
    }
    cmd_result_free(&r);
    return rc;
}

static bool pkg_unit_exists(void)
{
    return file_exists("/lib/systemd/system/" UNIT_NAME) || file_exists("/usr/lib/systemd/system/" UNIT_NAME);
}

static void unit_text(const char *exe, sb_t *out)
{
    sb_printf(out,
              "[Unit]\n"
              "Description=Tuấn WireGuard - giao diện web quản lý WireGuard\n"
              "Documentation=%s\n"
              "After=network-online.target\n"
              "Wants=network-online.target\n"
              "\n"
              "[Service]\n"
              "Type=simple\n"
              "ExecStart=%s serve\n"
              "Restart=always\n"
              "RestartSec=3\n"
              "LimitNOFILE=65536\n"
              "ProtectHome=true\n"
              "PrivateTmp=true\n"
              "\n"
              "[Install]\n"
              "WantedBy=multi-user.target\n",
              TWG_REPO, exe);
}

static int service_install(const char *exe, bool start)
{
    if (!app_systemd_running()) {
        warn("Không phát hiện systemd - bỏ qua tạo dịch vụ. Hãy tự chạy: %s serve", exe);
        return -1;
    }
    if (!pkg_unit_exists()) {
        sb_t u;
        sb_init(&u);
        unit_text(exe, &u);
        if (file_write_atomic(UNIT_ETC, u.s, u.len, 0644) != 0) {
            sb_free(&u);
            warn("Không ghi được %s", UNIT_ETC);
            return -1;
        }
        sb_free(&u);
    }
    const char *reload[] = {"systemctl", "daemon-reload", NULL};
    const char *enable[] = {"systemctl", "enable", UNIT_NAME, NULL};
    const char *restart[] = {"systemctl", "restart", UNIT_NAME, NULL};
    sh(reload, 30000, true);
    if (sh(enable, 30000, true) != 0) {
        warn("Không bật được dịch vụ %s", UNIT_NAME);
        return -1;
    }
    if (start && sh(restart, 30000, true) != 0) {
        warn("Không khởi động được dịch vụ - xem: journalctl -u tuan-wg -n 50%s", "");
        return -1;
    }
    return 0;
}

static void enable_forwarding(void)
{
    const char *conf = "# Tuấn WireGuard - bật chuyển tiếp gói tin cho VPN\n"
                       "net.ipv4.ip_forward = 1\n"
                       "net.ipv6.conf.all.forwarding = 1\n";
    mkdir_p("/etc/sysctl.d", 0755);
    file_write_atomic(SYSCTL_FILE, conf, strlen(conf), 0644);
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "we");
    if (f) {
        fputs("1\n", f);
        fclose(f);
    }
    f = fopen("/proc/sys/net/ipv6/conf/all/forwarding", "we");
    if (f) {
        fputs("1\n", f);
        fclose(f);
    }
}

static bool kernel_has_wireguard(void)
{
    if (is_dir("/sys/module/wireguard"))
        return true;
    const char *add[] = {"ip", "link", "add", "dev", "twgprobe0", "type", "wireguard", NULL};
    const char *del[] = {"ip", "link", "del", "dev", "twgprobe0", NULL};
    if (sh(add, 10000, false) == 0) {
        sh(del, 10000, false);
        return true;
    }
    const char *mp[] = {"modprobe", "wireguard", NULL};
    return sh(mp, 10000, false) == 0 && is_dir("/sys/module/wireguard");
}

static bool apt_install(const char *const pkgs[])
{
    if (!have_cmd("apt-get"))
        return false;
    static bool updated = false;
    const char *env[] = {"DEBIAN_FRONTEND=noninteractive", NULL};
    cmd_result_t r;
    if (!updated) {
        const char *up[] = {"apt-get", "update", NULL};
        run_cmd(up, env, NULL, 600000, &r);
        cmd_result_free(&r);
        updated = true;
    }
    const char *argv[32] = {"apt-get", "install", "-y", "--no-install-recommends"};
    int n = 4;
    for (int i = 0; pkgs[i] && n < 30; i++)
        argv[n++] = pkgs[i];
    argv[n] = NULL;
    int rc = run_cmd(argv, env, NULL, 900000, &r);
    if (rc != 0 && r.out) {
        str_trim(r.out);
        char *last = strrchr(r.out, '\n');
        printf("        %s%s%s\n", C_DIM, last ? last + 1 : r.out, C_RESET);
    }
    cmd_result_free(&r);
    return rc == 0;
}

static bool is_our_conf(const char *path)
{
    char *d = file_read(path, NULL);
    bool ours = d && strstr(d, "Tuấn WireGuard") != NULL;
    free(d);
    return ours;
}

/* Nhập cấu hình WireGuard có sẵn (khóa máy chủ + các peer) */
static int import_wg_conf(const char *path)
{
    char *d = file_read(path, NULL);
    if (!d)
        return -1;
    int imported = 0;
    char section[16] = "";
    char pending_name[128] = "";
    client_t cur;
    bool in_peer = false;
    memset(&cur, 0, sizeof cur);
    char *save = NULL;
    for (char *line = strtok_r(d, "\n", &save);; line = strtok_r(NULL, "\n", &save)) {
        bool end = line == NULL;
        if (!end)
            str_trim(line);
        if (end || str_starts(line, "[")) {
            if (in_peer && wg_key_valid(cur.public_key) && !db_client_by_pubkey(&g_db, cur.public_key)) {
                char err[128];
                client_t tmp;
                memset(&tmp, 0, sizeof tmp);
                if (client_init_new(&g_db, &tmp, err, sizeof err) == 0) {
                    str_copy(tmp.public_key, cur.public_key, sizeof tmp.public_key);
                    tmp.private_key[0] = 0; /* không có khóa riêng của client */
                    str_copy(tmp.preshared_key, cur.preshared_key, sizeof tmp.preshared_key);
                    if (cur.address[0])
                        str_copy(tmp.address, cur.address, sizeof tmp.address);
                    char nm[160];
                    if (pending_name[0])
                        snprintf(nm, sizeof nm, "%s", pending_name);
                    else
                        snprintf(nm, sizeof nm, "Nhập %d", imported + 1);
                    str_strip_ctrl(nm);
                    utf8_truncate(nm, 120);
                    if (db_client_by_name(&g_db, nm))
                        snprintf(tmp.name, sizeof tmp.name, "%s (%d)", nm, imported + 1);
                    else
                        str_copy(tmp.name, nm, sizeof tmp.name);
                    str_copy(tmp.note, "Nhập từ cấu hình WireGuard cũ (không có khóa riêng)", sizeof tmp.note);
                    client_t *c = db_client_add(&g_db);
                    if (c) {
                        *c = tmp;
                        imported++;
                    }
                }
            }
            if (end)
                break;
            in_peer = strcasecmp(line, "[Peer]") == 0;
            str_copy(section, in_peer ? "peer" : "iface", sizeof section);
            memset(&cur, 0, sizeof cur);
            if (!in_peer)
                pending_name[0] = 0;
            continue;
        }
        if (line[0] == '#') {
            /* "### Client ten" (wireguard-install) hoặc "# ten" */
            const char *n = line;
            while (*n == '#' || *n == ' ')
                n++;
            if (str_starts(n, "Client "))
                n += 7;
            if (*n && !strstr(n, "Tuấn WireGuard"))
                str_copy(pending_name, n, sizeof pending_name);
            continue;
        }
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = 0;
        char *k = line, *v = eq + 1;
        str_trim(k);
        str_trim(v);
        char full[512];
        str_copy(full, v, sizeof full);
        if (!strcmp(section, "iface")) {
            if (!strcasecmp(k, "PrivateKey") && wg_key_valid(full)) {
                str_copy(g_db.s.private_key, full, sizeof g_db.s.private_key);
                wg_pubkey(g_db.s.private_key, g_db.s.public_key);
            } else if (!strcasecmp(k, "ListenPort")) {
                int p = atoi(full);
                if (p > 0 && p < 65536)
                    g_db.s.listen_port = p;
            } else if (!strcasecmp(k, "Address")) {
                char *comma = strchr(full, ',');
                if (comma)
                    *comma = 0;
                str_trim(full);
                uint32_t a;
                int pfx;
                if (cidr4_parse(full, &a, &pfx) == 0 && pfx >= 16 && pfx <= 29)
                    str_copy(g_db.s.address, full, sizeof g_db.s.address);
            }
        } else if (in_peer) {
            if (!strcasecmp(k, "PublicKey"))
                str_copy(cur.public_key, full, sizeof cur.public_key);
            else if (!strcasecmp(k, "PresharedKey") && wg_key_valid(full))
                str_copy(cur.preshared_key, full, sizeof cur.preshared_key);
            else if (!strcasecmp(k, "AllowedIPs")) {
                char *slash = strchr(full, '/');
                if (slash)
                    *slash = 0;
                char *comma = strchr(full, ',');
                if (comma)
                    *comma = 0;
                uint32_t a;
                if (ip4_parse(full, &a) == 0)
                    str_copy(cur.address, full, sizeof cur.address);
            }
        }
    }
    free(d);
    return imported;
}

static bool copy_self(const char *dst)
{
    if (!strcmp(g_app.exe, dst))
        return true;
    size_t len;
    char *data = file_read(g_app.exe, &len);
    if (!data)
        return false;
    mkdir_p("/usr/local/bin", 0755);
    int r = file_write_atomic(dst, data, len, 0755);
    free(data);
    return r == 0;
}

static void box_line(const char *label, const char *value, const char *color)
{
    /* căn lề theo số ký tự hiển thị (UTF-8), không theo số byte */
    printf("  %s│%s  %s", C_MAGENTA, C_RESET, label);
    for (size_t i = utf8_len(label); i < 17; i++)
        putchar(' ');
    printf("%s%s%s\n", color, value, C_RESET);
}

static void usage_install(void)
{
    printf("Cách dùng: sudo tuan-wg install [tùy chọn]\n\n"
           "  -y, --yes              Không hỏi, dùng giá trị mặc định/tự phát hiện\n"
           "  --endpoint HOST        Tên miền hoặc IP công khai của máy chủ\n"
           "  --port N               Cổng WireGuard UDP (mặc định 51820)\n"
           "  --web-port N           Cổng giao diện web TCP (mặc định 51821)\n"
           "  --web-listen IP        Địa chỉ lắng nghe web (mặc định 0.0.0.0)\n"
           "  --subnet CIDR          Dải IP VPN, ví dụ 10.8.0.1/24\n"
           "  --dns LIST             DNS cho người dùng (mặc định 1.1.1.1, 8.8.8.8)\n"
           "  --user NAME            Tên đăng nhập quản trị (mặc định admin)\n"
           "  --password PASS        Mật khẩu quản trị (mặc định: tạo ngẫu nhiên)\n"
           "  --no-deps              Không tự cài gói phụ thuộc bằng apt\n"
           "  --no-service           Không tạo dịch vụ systemd\n"
           "  --no-import            Không nhập cấu hình WireGuard có sẵn\n");
}

int cmd_install(int argc, char **argv)
{
    bool yes = false, no_deps = false, no_service = false, from_pkg = false, no_import = false;
    const char *o_endpoint = NULL, *o_port = NULL, *o_webport = NULL, *o_weblisten = NULL,
               *o_subnet = NULL, *o_dns = NULL, *o_user = NULL, *o_pass = NULL;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
#define OPT(name, var)                                                                             \
    if (!strcmp(a, name) && v) {                                                                   \
        var = v;                                                                                   \
        i++;                                                                                       \
        continue;                                                                                  \
    }
        if (!strcmp(a, "-y") || !strcmp(a, "--yes")) {
            yes = true;
            continue;
        }
        if (!strcmp(a, "--no-deps")) {
            no_deps = true;
            continue;
        }
        if (!strcmp(a, "--no-service")) {
            no_service = true;
            continue;
        }
        if (!strcmp(a, "--no-import")) {
            no_import = true;
            continue;
        }
        if (!strcmp(a, "--from-package")) {
            from_pkg = yes = no_deps = true;
            continue;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage_install();
            return 0;
        }
        OPT("--endpoint", o_endpoint)
        OPT("--port", o_port)
        OPT("--web-port", o_webport)
        OPT("--web-listen", o_weblisten)
        OPT("--subnet", o_subnet)
        OPT("--dns", o_dns)
        OPT("--user", o_user)
        OPT("--password", o_pass)
#undef OPT
        fprintf(stderr, "Tùy chọn không hợp lệ: %s\n", a);
        usage_install();
        return 2;
    }
    if (!cli_is_root()) {
        fprintf(stderr, "%sCần chạy với quyền root:%s sudo tuan-wg install\n", C_RED, C_RESET);
        return 1;
    }
    bool interactive = !yes && isatty(0);

    printf("\n%s  ╭──────────────────────────────────────────────%s\n", C_MAGENTA, C_RESET);
    printf("%s  │%s  %sTuấn WireGuard v%s%s - Trình cài đặt\n", C_MAGENTA, C_RESET, C_BOLD, TWG_VERSION, C_RESET);
    printf("%s  │%s  Tác giả: %s  •  %s\n", C_MAGENTA, C_RESET, TWG_AUTHOR, TWG_REPO);
    printf("%s  ╰──────────────────────────────────────────────%s\n\n", C_MAGENTA, C_RESET);

    /* 1. hệ thống */
    step("Kiểm tra hệ thống");
    char os[160] = "Linux";
    {
        char *rel = file_read("/etc/os-release", NULL);
        if (rel) {
            char *p = strstr(rel, "PRETTY_NAME=");
            if (p) {
                p += 12;
                if (*p == '"')
                    p++;
                size_t n = strcspn(p, "\"\n");
                if (n >= sizeof os)
                    n = sizeof os - 1;
                memcpy(os, p, n);
                os[n] = 0;
            }
            bool debian_like = strstr(rel, "debian") || strstr(rel, "ubuntu") || strstr(rel, "Debian");
            free(rel);
            ok("%s", os);
            if (!debian_like)
                warn("Hệ điều hành chưa được kiểm thử chính thức (hỗ trợ tốt nhất: Debian/Ubuntu)%s", "");
        } else {
            ok("%s", os);
        }
    }

    /* 2. gói phụ thuộc */
    step("Cài đặt gói phụ thuộc (wireguard-tools, iptables, iproute2)");
    if (!no_deps) {
        const char *need[8];
        int nn = 0;
        if (!have_cmd("wg") || !have_cmd("wg-quick"))
            need[nn++] = "wireguard-tools";
        if (!have_cmd("iptables"))
            need[nn++] = "iptables";
        if (!have_cmd("ip"))
            need[nn++] = "iproute2";
        need[nn] = NULL;
        if (nn == 0) {
            ok("Đã có đủ gói cần thiết%s", "");
        } else if (apt_install(need)) {
            ok("Đã cài đặt các gói còn thiếu%s", "");
        } else {
            warn("Không cài được gói tự động. Hãy cài thủ công: apt install wireguard-tools iptables iproute2%s", "");
        }
    } else {
        ok("Bỏ qua (gói đã được quản lý bởi trình quản lý gói)%s", "");
    }
    if (!kernel_has_wireguard()) {
        if (have_cmd("wireguard-go")) {
            warn("Kernel không có module WireGuard - sẽ dùng wireguard-go (userspace)%s", "");
        } else {
            const char *wgo[] = {"wireguard-go", NULL};
            if (!no_deps && apt_install(wgo))
                warn("Kernel không có module WireGuard - đã cài wireguard-go (userspace)%s", "");
            else
                warn("Kernel không hỗ trợ WireGuard và chưa có wireguard-go. Cân nhắc nâng cấp kernel.%s", "");
        }
    } else {
        ok("Kernel hỗ trợ WireGuard%s", "");
    }

    /* 3. forwarding */
    step("Bật chuyển tiếp IP (IP forwarding)");
    enable_forwarding();
    ok("Đã ghi %s", SYSCTL_FILE);

    /* 4. cấu hình */
    step("Cấu hình máy chủ");
    if (cli_open_db(false) != 0)
        return 1;
    bool fresh = !file_exists(g_app.db_path);
    char gen_pw[64] = "";
    char wgconf[512];
    snprintf(wgconf, sizeof wgconf, "%s/%s.conf", g_app.wg_dir, g_db.s.iface);
    if (fresh && file_exists(wgconf) && !is_our_conf(wgconf)) {
        char bak[600];
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);
        char ts[32];
        strftime(ts, sizeof ts, "%Y%m%d-%H%M%S", &tm);
        snprintf(bak, sizeof bak, "%s.bak-%s", wgconf, ts);
        size_t l;
        char *old = file_read(wgconf, &l);
        if (old) {
            file_write_atomic(bak, old, l, 0600);
            free(old);
            ok("Đã sao lưu cấu hình cũ sang %s", bak);
        }
        bool do_import = !no_import && (!interactive || cli_yesno("      Phát hiện cấu hình WireGuard có sẵn. Nhập các peer vào Tuấn WireGuard?", true));
        if (do_import) {
            int n = import_wg_conf(wgconf);
            char nb[32];
            snprintf(nb, sizeof nb, "%d", n < 0 ? 0 : n);
            ok("Đã nhập %s peer từ cấu hình cũ", nb);
        }
    }
    char wan[32] = "";
    net_default_iface(wan, sizeof wan);
    if (!g_db.s.wan_iface[0] && wan[0])
        str_copy(g_db.s.wan_iface, wan, sizeof g_db.s.wan_iface);
    char detected[64] = "";
    if (!g_db.s.endpoint[0] && !o_endpoint) {
        printf("      Đang phát hiện IP công khai...\n");
        if (net_public_ip(detected, sizeof detected, 2500) != 0)
            net_local_ip(detected, sizeof detected);
    }
    char buf[512];
    char endpoint[256], port[16], webport[16], dns[256], user[64], subnet[64];
    str_copy(endpoint, o_endpoint ? o_endpoint : (g_db.s.endpoint[0] ? g_db.s.endpoint : detected), sizeof endpoint);
    snprintf(port, sizeof port, "%s", o_port ? o_port : "");
    if (!port[0])
        snprintf(port, sizeof port, "%d", g_db.s.listen_port);
    snprintf(webport, sizeof webport, "%s", o_webport ? o_webport : "");
    if (!webport[0])
        snprintf(webport, sizeof webport, "%d", g_db.s.web_port);
    str_copy(dns, o_dns ? o_dns : g_db.s.dns, sizeof dns);
    str_copy(user, o_user ? o_user : g_db.s.admin_user, sizeof user);
    str_copy(subnet, o_subnet ? o_subnet : g_db.s.address, sizeof subnet);
    char password[256] = "";
    if (o_pass)
        str_copy(password, o_pass, sizeof password);

    if (interactive) {
        cli_prompt("      Tên miền hoặc IP công khai của máy chủ", endpoint, buf, sizeof buf);
        str_copy(endpoint, buf, sizeof endpoint);
        cli_prompt("      Cổng WireGuard (UDP)", port, buf, sizeof buf);
        str_copy(port, buf, sizeof port);
        cli_prompt("      Cổng giao diện web (TCP)", webport, buf, sizeof buf);
        str_copy(webport, buf, sizeof webport);
        cli_prompt("      Dải IP mạng VPN", subnet, buf, sizeof buf);
        str_copy(subnet, buf, sizeof subnet);
        cli_prompt("      DNS cho người dùng", dns, buf, sizeof buf);
        str_copy(dns, buf, sizeof dns);
        cli_prompt("      Tên đăng nhập quản trị", user, buf, sizeof buf);
        str_copy(user, buf, sizeof user);
        if (!o_pass) {
            for (;;) {
                if (cli_read_password("      Mật khẩu quản trị (Enter = tạo ngẫu nhiên)", password,
                                      sizeof password) != 0)
                    password[0] = 0;
                if (!password[0] && !fresh && g_db.s.admin_hash[0])
                    break; /* giữ mật khẩu cũ */
                if (!password[0] || strlen(password) >= 8)
                    break;
                printf("      %sMật khẩu cần ít nhất 8 ký tự%s\n", C_RED, C_RESET);
            }
        }
    }
    /* áp dụng qua bộ kiểm tra dữ liệu chung */
    sb_t in;
    sb_init(&in);
    jw_t w;
    jw_init(&w, &in);
    jw_obj(&w);
    jw_kstr(&w, "endpoint", endpoint);
    jw_kint(&w, "listen_port", atoi(port));
    jw_kint(&w, "web_port", atoi(webport));
    if (o_weblisten)
        jw_kstr(&w, "web_listen", o_weblisten);
    jw_kstr(&w, "address", subnet);
    jw_kstr(&w, "dns", dns);
    jw_obj_end(&w);
    json_t *j = json_parse(in.s, in.len, NULL, 0);
    sb_free(&in);
    char err[256];
    int flags = 0;
    app_begin();
    if (settings_apply_json(&g_db, j, &flags, err, sizeof err) != 0) {
        app_abort();
        json_free(j);
        fprintf(stderr, "      %sLỗi cấu hình:%s %s\n", C_RED, C_RESET, err);
        return 1;
    }
    json_free(j);
    if (user[0])
        str_copy(g_db.s.admin_user, user, sizeof g_db.s.admin_user);
    if (password[0]) {
        if (strlen(password) < 8) {
            app_abort();
            fprintf(stderr, "      %sMật khẩu cần ít nhất 8 ký tự%s\n", C_RED, C_RESET);
            return 1;
        }
        auth_hash_password(password, g_db.s.admin_hash, sizeof g_db.s.admin_hash);
    }
    bool generated = cli_first_run_init(gen_pw, sizeof gen_pw);
    app_commit();
    ok("Đã lưu cấu hình vào %s", g_app.db_path);

    /* 5. WireGuard */
    step("Khởi động WireGuard");
    if (app_systemd_running()) {
        char unit[64];
        snprintf(unit, sizeof unit, "wg-quick@%s", g_db.s.iface);
        const char *en[] = {"systemctl", "enable", unit, NULL};
        sh(en, 30000, false);
    }
    if (wg_apply(true, err, sizeof err) == 0) {
        char info[64];
        snprintf(info, sizeof info, "%s (cổng %d/udp)", g_db.s.iface, g_db.s.listen_port);
        ok("WireGuard đang chạy: %s", info);
    } else {
        warn("Chưa khởi động được WireGuard: %s", err);
    }

    /* 6. tường lửa */
    step("Mở cổng tường lửa");
    char p1[32], p2[32];
    snprintf(p1, sizeof p1, "%d/udp", g_db.s.listen_port);
    snprintf(p2, sizeof p2, "%d/tcp", g_db.s.web_port);
    bool fw = false;
    if (have_cmd("ufw")) {
        const char *st[] = {"ufw", "status", NULL};
        cmd_result_t r;
        run_cmd(st, NULL, NULL, 10000, &r);
        bool active = r.out && strstr(r.out, "Status: active");
        cmd_result_free(&r);
        if (active) {
            const char *a1[] = {"ufw", "allow", p1, NULL};
            const char *a2[] = {"ufw", "allow", p2, NULL};
            sh(a1, 20000, true);
            sh(a2, 20000, true);
            char info[80];
            snprintf(info, sizeof info, "%s, %s", p1, p2);
            ok("ufw: đã mở %s", info);
            fw = true;
        }
    }
    if (have_cmd("firewall-cmd")) {
        const char *st[] = {"firewall-cmd", "--state", NULL};
        if (sh(st, 10000, false) == 0) {
            char a[64], b[64];
            snprintf(a, sizeof a, "--add-port=%s", p1);
            snprintf(b, sizeof b, "--add-port=%s", p2);
            const char *c1[] = {"firewall-cmd", "--permanent", a, b, "--add-masquerade", NULL};
            const char *c2[] = {"firewall-cmd", "--reload", NULL};
            sh(c1, 20000, true);
            sh(c2, 20000, true);
            ok("firewalld: đã mở cổng%s", "");
            fw = true;
        }
    }
    if (!fw)
        ok("Không phát hiện ufw/firewalld đang bật - quy tắc iptables được thêm tự động khi WireGuard chạy%s", "");

    /* 7. dịch vụ */
    step("Cài dịch vụ tự khởi động cùng hệ thống (systemd)");
    const char *exe = g_app.exe;
    if (!from_pkg && strcmp(g_app.exe, BIN_PKG) != 0) {
        if (copy_self(BIN_LOCAL)) {
            exe = BIN_LOCAL;
            ok("Đã cài chương trình vào %s", BIN_LOCAL);
        } else {
            warn("Không sao chép được chương trình vào %s", BIN_LOCAL);
        }
    }
    if (!no_service) {
        if (service_install(exe, true) == 0)
            ok("Dịch vụ %s đã bật và đang chạy", UNIT_NAME);
    } else {
        ok("Bỏ qua theo yêu cầu (--no-service)%s", "");
    }

    /* tổng kết */
    char host[300];
    str_copy(host, g_db.s.endpoint, sizeof host);
    char *colon = strrchr(host, ':');
    if (colon && host[0] != '[' && strchr(host, ':') == colon)
        *colon = 0;
    if (!host[0])
        net_local_ip(host, sizeof host);
    char url[400];
    const char *lst = g_db.s.web_listen;
    snprintf(url, sizeof url, "http://%s:%d", (strcmp(lst, "0.0.0.0") && strcmp(lst, "::")) ? lst : host,
             g_db.s.web_port);
    printf("\n  %s╭─%s %sCài đặt hoàn tất!%s %s──────────────────────────────%s\n", C_MAGENTA, C_RESET, C_BOLD,
           C_RESET, C_MAGENTA, C_RESET);
    box_line("Giao diện web:", url, C_CYAN);
    box_line("Tài khoản:", g_db.s.admin_user, C_BOLD);
    if (generated)
        box_line("Mật khẩu:", gen_pw, C_YELLOW);
    else if (password[0])
        box_line("Mật khẩu:", "(như bạn vừa nhập)", "");
    else
        box_line("Mật khẩu:", "(giữ nguyên mật khẩu cũ)", "");
    printf("  %s│%s\n", C_MAGENTA, C_RESET);
    box_line("Đổi mật khẩu:", "sudo tuan-wg passwd", C_DIM);
    box_line("Xem trạng thái:", "sudo tuan-wg status", C_DIM);
    printf("  %s╰───────────────────────────────────────────────────%s\n\n", C_MAGENTA, C_RESET);
    if (generated)
        printf("  %sHãy lưu lại mật khẩu trên - nó chỉ hiển thị một lần.%s\n\n", C_YELLOW, C_RESET);
    secure_zero(password, sizeof password);
    return 0;
}

static int rm_dir_files(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char p[1024];
        snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        unlink(p);
    }
    closedir(d);
    return rmdir(dir);
}

int cmd_uninstall(int argc, char **argv)
{
    bool purge = false, yes = false;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--purge")) {
            purge = true;
        } else if (!strcmp(argv[i], "-y") || !strcmp(argv[i], "--yes")) {
            yes = true;
        } else {
            fprintf(stderr, "Tùy chọn không hợp lệ: %s (xem: tuan-wg uninstall --help)\n", argv[i]);
            return 2;
        }
    }
    if (!cli_is_root()) {
        fprintf(stderr, "Cần quyền root: sudo tuan-wg uninstall\n");
        return 1;
    }
    if (!yes && isatty(0)) {
        const char *q = purge ? "Gỡ Tuấn WireGuard và XÓA TOÀN BỘ dữ liệu (người dùng, thống kê)?"
                              : "Gỡ dịch vụ Tuấn WireGuard (giữ lại dữ liệu và WireGuard)?";
        if (!cli_yesno(q, false)) {
            printf("Đã hủy.\n");
            return 0;
        }
    }
    if (app_systemd_running()) {
        const char *dis[] = {"systemctl", "disable", "--now", UNIT_NAME, NULL};
        sh(dis, 30000, false);
        if (file_exists(UNIT_ETC))
            unlink(UNIT_ETC);
        const char *reload[] = {"systemctl", "daemon-reload", NULL};
        sh(reload, 30000, false);
        printf("%s✔%s Đã gỡ dịch vụ %s\n", C_GREEN, C_RESET, UNIT_NAME);
    }
    if (purge) {
        char iface[16] = "wg0", err[256];
        if (app_db_open(err, sizeof err) == 0)
            str_copy(iface, g_db.s.iface, sizeof iface);
        wg_down(err, sizeof err);
        if (app_systemd_running()) {
            char unit[64];
            snprintf(unit, sizeof unit, "wg-quick@%s", iface);
            const char *dis[] = {"systemctl", "disable", unit, NULL};
            sh(dis, 30000, false);
        }
        char conf[512];
        snprintf(conf, sizeof conf, "%s/%s.conf", g_app.wg_dir, iface);
        if (is_our_conf(conf))
            unlink(conf);
        unlink(SYSCTL_FILE);
        rm_dir_files(g_app.data_dir);
        printf("%s✔%s Đã dừng WireGuard (%s) và xóa dữ liệu tại %s\n", C_GREEN, C_RESET, iface, g_app.data_dir);
    } else {
        printf("  Dữ liệu vẫn được giữ tại %s (xóa hẳn: tuan-wg uninstall --purge)\n", g_app.data_dir);
    }
    if (file_exists(BIN_LOCAL) && strcmp(g_app.exe, BIN_PKG) != 0) {
        unlink(BIN_LOCAL);
        printf("%s✔%s Đã xóa %s\n", C_GREEN, C_RESET, BIN_LOCAL);
    }
    if (file_exists(BIN_PKG))
        printf("  Cài bằng gói .deb? Gỡ gói bằng: %ssudo apt remove tuan-wg%s\n", C_CYAN, C_RESET);
    return 0;
}

int cmd_service(int argc, char **argv)
{
    const char *sub = argc > 0 ? argv[0] : "status";
    if (!strcmp(sub, "install")) {
        if (!cli_is_root()) {
            fprintf(stderr, "Cần quyền root\n");
            return 1;
        }
        const char *exe = file_exists(BIN_PKG) ? BIN_PKG : (file_exists(BIN_LOCAL) ? BIN_LOCAL : g_app.exe);
        if (service_install(exe, true) != 0)
            return 1;
        printf("%s✔%s Đã cài và khởi động dịch vụ %s (tự chạy khi khởi động máy)\n", C_GREEN, C_RESET, UNIT_NAME);
        return 0;
    }
    if (!strcmp(sub, "remove") || !strcmp(sub, "uninstall")) {
        if (!cli_is_root()) {
            fprintf(stderr, "Cần quyền root\n");
            return 1;
        }
        const char *dis[] = {"systemctl", "disable", "--now", UNIT_NAME, NULL};
        sh(dis, 30000, true);
        if (file_exists(UNIT_ETC))
            unlink(UNIT_ETC);
        const char *reload[] = {"systemctl", "daemon-reload", NULL};
        sh(reload, 30000, false);
        printf("%s✔%s Đã gỡ dịch vụ %s\n", C_GREEN, C_RESET, UNIT_NAME);
        return 0;
    }
    if (!strcmp(sub, "logs")) {
        bool follow = argc > 1 && (!strcmp(argv[1], "-f") || !strcmp(argv[1], "--follow"));
        if (follow)
            execlp("journalctl", "journalctl", "-u", UNIT_NAME, "-n", "100", "-f", (char *)NULL);
        else
            execlp("journalctl", "journalctl", "-u", UNIT_NAME, "-n", "200", "--no-pager", (char *)NULL);
        perror("journalctl");
        return 1;
    }
    static const char *verbs[] = {"start", "stop", "restart", "status", "enable", "disable", NULL};
    for (int i = 0; verbs[i]; i++) {
        if (!strcmp(sub, verbs[i])) {
            execlp("systemctl", "systemctl", sub, UNIT_NAME, (char *)NULL);
            perror("systemctl");
            return 1;
        }
    }
    printf("Cách dùng: tuan-wg service install|remove|start|stop|restart|status|enable|disable|logs [-f]\n");
    return 2;
}
