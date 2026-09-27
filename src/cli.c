/*
 * Tuấn WireGuard - các lệnh dòng lệnh (CLI)
 * Tác giả: Tuandethuong
 */
#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "app.h"
#include "auth.h"
#include "crypto.h"
#include "json.h"
#include "net.h"
#include "qr.h"
#include "stats.h"
#include "wg.h"

const char *C_RESET = "", *C_BOLD = "", *C_DIM = "", *C_GREEN = "", *C_RED = "", *C_YELLOW = "",
           *C_CYAN = "", *C_MAGENTA = "";

void cli_colors_init(void)
{
    if (isatty(1) && !getenv("NO_COLOR")) {
        C_RESET = "\033[0m";
        C_BOLD = "\033[1m";
        C_DIM = "\033[2m";
        C_GREEN = "\033[32m";
        C_RED = "\033[31m";
        C_YELLOW = "\033[33m";
        C_CYAN = "\033[36m";
        C_MAGENTA = "\033[35m";
    }
}

/* ================= tiện ích ================= */

void fmt_bytes(uint64_t b, char *out, size_t n)
{
    static const char *u[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double v = (double)b;
    int i = 0;
    while (v >= 1024 && i < 5) {
        v /= 1024;
        i++;
    }
    if (i == 0)
        snprintf(out, n, "%llu B", (unsigned long long)b);
    else
        snprintf(out, n, "%.2f %s", v, u[i]);
}

bool cli_is_root(void)
{
    return geteuid() == 0;
}

void cli_prompt(const char *q, const char *def, char *out, size_t n)
{
    if (def && *def)
        printf("%s%s%s [%s%s%s]: ", C_BOLD, q, C_RESET, C_CYAN, def, C_RESET);
    else
        printf("%s%s%s: ", C_BOLD, q, C_RESET);
    fflush(stdout);
    char line[1024];
    if (!fgets(line, sizeof line, stdin)) {
        str_copy(out, def ? def : "", n);
        printf("\n");
        return;
    }
    str_trim(line);
    str_copy(out, line[0] ? line : (def ? def : ""), n);
}

bool cli_yesno(const char *q, bool def)
{
    char a[16];
    cli_prompt(q, def ? "C/k" : "c/K", a, sizeof a);
    if (!strcmp(a, "C/k"))
        return true;
    if (!strcmp(a, "c/K"))
        return false;
    return a[0] == 'c' || a[0] == 'C' || a[0] == 'y' || a[0] == 'Y';
}

int cli_read_password(const char *q, char *out, size_t n)
{
    printf("%s%s%s: ", C_BOLD, q, C_RESET);
    fflush(stdout);
    struct termios old, noecho;
    bool tty = isatty(0) && tcgetattr(0, &old) == 0;
    if (tty) {
        noecho = old;
        noecho.c_lflag &= (tcflag_t)~ECHO;
        tcsetattr(0, TCSAFLUSH, &noecho);
    }
    char line[512];
    char *r = fgets(line, sizeof line, stdin);
    if (tty) {
        tcsetattr(0, TCSAFLUSH, &old);
        printf("\n");
    }
    if (!r)
        return -1;
    size_t l = strlen(line);
    while (l && (line[l - 1] == '\n' || line[l - 1] == '\r'))
        line[--l] = 0;
    str_copy(out, line, n);
    secure_zero(line, sizeof line);
    return 0;
}

int cli_open_db(bool must_exist)
{
    char err[256];
    if (!is_dir(g_app.data_dir)) {
        if (must_exist) {
            fprintf(stderr, "%sChưa cài đặt Tuấn WireGuard.%s Hãy chạy: %ssudo tuan-wg install%s\n", C_RED,
                    C_RESET, C_BOLD, C_RESET);
            return -1;
        }
        if (mkdir_p(g_app.data_dir, 0700) != 0) {
            fprintf(stderr, "Không tạo được thư mục %s (cần quyền root?)\n", g_app.data_dir);
            return -1;
        }
    }
    int r = app_db_open(err, sizeof err);
    if (r < 0) {
        fprintf(stderr, "%sLỗi:%s %s\n", C_RED, C_RESET, err);
        return -1;
    }
    if (r == 1 && must_exist) {
        fprintf(stderr, "%sChưa có dữ liệu.%s Hãy chạy: %ssudo tuan-wg install%s\n", C_RED, C_RESET,
                C_BOLD, C_RESET);
        return -1;
    }
    return 0;
}

bool cli_first_run_init(char *generated_password, size_t n)
{
    bool gen = false;
    if (!wg_key_valid(g_db.s.private_key)) {
        wg_genkey(g_db.s.private_key, g_db.s.public_key);
        LOGI("Đã tạo cặp khóa WireGuard cho máy chủ");
    } else if (!wg_key_valid(g_db.s.public_key)) {
        wg_pubkey(g_db.s.private_key, g_db.s.public_key);
    }
    if (!g_db.s.admin_hash[0]) {
        const char *envpw = getenv("TUAN_WG_PASSWORD");
        const char *envuser = getenv("TUAN_WG_USER");
        if (envuser && *envuser)
            str_copy(g_db.s.admin_user, envuser, sizeof g_db.s.admin_user);
        if (envpw && strlen(envpw) >= 8) {
            auth_hash_password(envpw, g_db.s.admin_hash, sizeof g_db.s.admin_hash);
            goto done;
        }
        char pw[32];
        auth_random_password(pw, 15);
        auth_hash_password(pw, g_db.s.admin_hash, sizeof g_db.s.admin_hash);
        if (generated_password)
            str_copy(generated_password, pw, n);
        gen = true;
    }
done:
    if (!g_db.s.installed_at)
        g_db.s.installed_at = now_unix();
    return gen;
}

static void pad_print(const char *s, size_t width)
{
    size_t w = utf8_len(s);
    fputs(s, stdout);
    for (size_t i = w; i < width; i++)
        putchar(' ');
}

static void rel_time(int64_t t, int64_t now, char *out, size_t n)
{
    if (!t) {
        str_copy(out, "chưa kết nối", n);
        return;
    }
    int64_t d = now - t;
    if (d < 60)
        snprintf(out, n, "%lld giây trước", (long long)(d < 0 ? 0 : d));
    else if (d < 3600)
        snprintf(out, n, "%lld phút trước", (long long)(d / 60));
    else if (d < 86400)
        snprintf(out, n, "%lld giờ trước", (long long)(d / 3600));
    else
        snprintf(out, n, "%lld ngày trước", (long long)(d / 86400));
}

static void fmt_date(int64_t t, int tz, char *out, size_t n)
{
    if (!t) {
        str_copy(out, "—", n);
        return;
    }
    int y, m, d;
    civil_from_days(key_day(t, tz), &y, &m, &d);
    snprintf(out, n, "%02d/%02d/%04d", d, m, y);
}

/* ================= client ================= */

static void usage_client(void)
{
    printf("Quản lý người dùng VPN:\n"
           "  tuan-wg client list\n"
           "  tuan-wg client add <tên> [--note TEXT] [--expire SỐ_NGÀY] [--limit GB] [--monthly]\n"
           "                          [--dns LIST] [--allowed-ips LIST] [--qr]\n"
           "  tuan-wg client show <tên|id|ip> [--qr]\n"
           "  tuan-wg client config <tên|id|ip>     (in cấu hình thô, dùng: > file.conf)\n"
           "  tuan-wg client qr <tên|id|ip>\n"
           "  tuan-wg client enable|disable <tên|id|ip>\n"
           "  tuan-wg client del <tên|id|ip>\n");
}

static void apply_after_cli(void)
{
    if (g_app.demo)
        return;
    char err[512];
    if (!wg_tools_installed()) {
        printf("%s!%s Chưa cài wireguard-tools nên chưa áp dụng được vào WireGuard.\n", C_YELLOW, C_RESET);
        return;
    }
    if (wg_apply(false, err, sizeof err) != 0)
        printf("%s!%s Áp dụng vào WireGuard lỗi: %s\n", C_YELLOW, C_RESET, err);
    else
        printf("%s✔%s Đã áp dụng vào WireGuard (%s)\n", C_GREEN, C_RESET, g_db.s.iface);
}

static void print_client_config(client_t *c, bool qr)
{
    sb_t conf;
    sb_init(&conf);
    app_rlock();
    wg_build_client_conf(&g_db, c, &conf, !qr);
    app_runlock();
    if (qr) {
        printf("\n%sQuét mã QR bằng ứng dụng WireGuard trên điện thoại:%s\n\n", C_BOLD, C_RESET);
        if (qr_print_terminal(conf.s, stdout) != 0)
            printf("(không tạo được mã QR)\n");
    } else {
        printf("%s", conf.s);
    }
    sb_free(&conf);
}

static int client_list(void)
{
    stats_load(g_app.stats_path);
    wg_status_t st;
    char err[256];
    bool live = !g_app.demo && wg_dump(g_db.s.iface, &st, err, sizeof err) == 0;
    int64_t now = now_unix();
    int tz = g_db.s.tz_offset;
    printf("%s", C_BOLD);
    pad_print(" #", 4);
    pad_print("TÊN", 24);
    pad_print("IP", 14);
    pad_print("TRẠNG THÁI", 14);
    pad_print("KẾT NỐI GẦN NHẤT", 18);
    pad_print("THÁNG NÀY", 12);
    printf("HẾT HẠN%s\n", C_RESET);
    for (int i = 0; i < g_db.nclients; i++) {
        client_t *c = &g_db.clients[i];
        cstat_t *cs = stats_client(c->id, false);
        int64_t hs = cs ? cs->handshake : 0;
        if (live) {
            for (int k = 0; k < st.npeers; k++)
                if (!strcmp(st.peers[k].public_key, c->public_key) && st.peers[k].handshake)
                    hs = st.peers[k].handshake;
        }
        bool online = c->enabled && hs && now - hs < ONLINE_WINDOW;
        char idx[16], name[64], state[64], hsbuf[48], used[32], exp[32];
        snprintf(idx, sizeof idx, "%2d", i + 1);
        str_copy(name, c->name, sizeof name);
        utf8_truncate(name, 60);
        if (utf8_len(name) > 22) {
            char *p = name;
            size_t cnt = 0;
            while (*p && cnt < 21) {
                if (((unsigned char)*p & 0xC0) != 0x80)
                    cnt++;
                p++;
            }
            while (*p && ((unsigned char)*p & 0xC0) == 0x80)
                p++;
            strcpy(p, "…");
        }
        if (c->enabled)
            snprintf(state, sizeof state, "%s", online ? "● online" : "○ offline");
        else if (!strcmp(c->disabled_reason, "expired"))
            str_copy(state, "✖ hết hạn", sizeof state);
        else if (!strcmp(c->disabled_reason, "quota"))
            str_copy(state, "✖ hết dung lượng", sizeof state);
        else
            str_copy(state, "✖ đã tắt", sizeof state);
        rel_time(hs, now, hsbuf, sizeof hsbuf);
        uint64_t m = 0;
        if (cs && cs->pkey == key_month(now, tz))
            m = cs->prx + cs->ptx;
        fmt_bytes(m, used, sizeof used);
        fmt_date(c->expires_at, tz, exp, sizeof exp);
        pad_print(idx, 4);
        pad_print(name, 24);
        pad_print(c->address, 14);
        printf("%s", c->enabled ? (online ? C_GREEN : C_DIM) : C_RED);
        pad_print(state, 14);
        printf("%s", C_RESET);
        pad_print(hsbuf, 18);
        pad_print(used, 12);
        printf("%s\n", exp);
    }
    if (!g_db.nclients)
        printf("  (chưa có người dùng nào - thêm bằng: tuan-wg client add \"Tên\")\n");
    printf("\nTổng: %d người dùng\n", g_db.nclients);
    if (live)
        wg_status_free(&st);
    return 0;
}

static int client_add(int argc, char **argv)
{
    if (argc < 1) {
        usage_client();
        return 2;
    }
    const char *name = argv[0];
    sb_t in;
    sb_init(&in);
    jw_t w;
    jw_init(&w, &in);
    jw_obj(&w);
    jw_kstr(&w, "name", name);
    bool qr = false;
    int tz = g_db.s.tz_offset;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--qr")) {
            qr = true;
        } else if (!strcmp(a, "--monthly")) {
            jw_kbool(&w, "limit_monthly", 1);
        } else if (v && !strcmp(a, "--note")) {
            jw_kstr(&w, "note", v);
            i++;
        } else if (v && !strcmp(a, "--dns")) {
            jw_kstr(&w, "dns", v);
            i++;
        } else if (v && !strcmp(a, "--allowed-ips")) {
            jw_kstr(&w, "allowed_ips", v);
            i++;
        } else if (v && !strcmp(a, "--expire")) {
            int days = atoi(v);
            if (days > 0) {
                /* hết hạn vào cuối ngày thứ N (theo múi giờ cài đặt) */
                int32_t dk = key_day(now_unix(), tz) + days;
                int64_t end = (int64_t)(dk + 1) * 86400 - (int64_t)tz * 60 - 1;
                jw_kint(&w, "expires_at", end);
            }
            i++;
        } else if (v && !strcmp(a, "--limit")) {
            double gb = atof(v);
            jw_kint(&w, "data_limit", (int64_t)(gb * 1073741824.0));
            i++;
        } else {
            fprintf(stderr, "Tùy chọn không hợp lệ: %s\n", a);
            sb_free(&in);
            return 2;
        }
    }
    jw_obj_end(&w);
    json_t *j = json_parse(in.s, in.len, NULL, 0);
    sb_free(&in);
    char err[256];
    client_t tmp;
    memset(&tmp, 0, sizeof tmp);
    app_begin();
    if (client_init_new(&g_db, &tmp, err, sizeof err) != 0 ||
        client_apply_json(&g_db, &tmp, -1, j, true, err, sizeof err) != 0) {
        app_abort();
        json_free(j);
        fprintf(stderr, "%sLỗi:%s %s\n", C_RED, C_RESET, err);
        return 1;
    }
    json_free(j);
    client_t *c = db_client_add(&g_db);
    *c = tmp;
    char id[24];
    str_copy(id, c->id, sizeof id);
    if (app_commit() != 0) {
        fprintf(stderr, "Không lưu được dữ liệu\n");
        return 1;
    }
    printf("%s✔%s Đã thêm người dùng %s%s%s - IP %s\n", C_GREEN, C_RESET, C_BOLD, tmp.name, C_RESET,
           tmp.address);
    apply_after_cli();
    c = db_client_by_id(&g_db, id);
    if (c) {
        if (qr)
            print_client_config(c, true);
        else
            printf("Xem cấu hình: %stuan-wg client show \"%s\" --qr%s\n", C_CYAN, tmp.name, C_RESET);
    }
    return 0;
}

static client_t *find_or_die(const char *q)
{
    client_t *c = db_client_find(&g_db, q);
    if (!c)
        fprintf(stderr, "%sKhông tìm thấy người dùng '%s'%s\n", C_RED, q, C_RESET);
    return c;
}

static int client_show(const char *q, bool qr)
{
    client_t *c = find_or_die(q);
    if (!c)
        return 1;
    stats_load(g_app.stats_path);
    cstat_t *cs = stats_client(c->id, false);
    int tz = g_db.s.tz_offset;
    char a[32], b[32], e[32], cr[32];
    fmt_bytes(cs ? cs->tx : 0, a, sizeof a);
    fmt_bytes(cs ? cs->rx : 0, b, sizeof b);
    fmt_date(c->expires_at, tz, e, sizeof e);
    fmt_date(c->created_at, tz, cr, sizeof cr);
    printf("%s%s%s  (%s)\n", C_BOLD, c->name, C_RESET, c->id);
    if (c->note[0])
        printf("  Ghi chú:     %s\n", c->note);
    printf("  Trạng thái:  %s\n", c->enabled ? "đang bật" : "đã tắt");
    printf("  Địa chỉ IP:  %s%s%s\n", c->address, c->address6[0] ? ", " : "", c->address6);
    printf("  Tạo lúc:     %s\n", cr);
    printf("  Hết hạn:     %s\n", e);
    if (c->data_limit) {
        char l[32];
        fmt_bytes((uint64_t)c->data_limit, l, sizeof l);
        printf("  Hạn mức:     %s%s\n", l, c->limit_monthly ? " / tháng" : "");
    }
    printf("  Đã dùng:     ↓ %s  ↑ %s\n", a, b);
    printf("  Khóa công khai: %s\n\n", c->public_key);
    print_client_config(c, qr);
    return 0;
}

static int client_set_enabled(const char *q, bool en)
{
    app_begin();
    client_t *c = find_or_die(q);
    if (!c) {
        app_abort();
        return 1;
    }
    c->enabled = en;
    str_copy(c->disabled_reason, en ? "" : "manual", sizeof c->disabled_reason);
    c->updated_at = now_unix();
    char name[256];
    str_copy(name, c->name, sizeof name);
    app_commit();
    printf("%s✔%s Đã %s %s\n", C_GREEN, C_RESET, en ? "bật" : "tắt", name);
    apply_after_cli();
    return 0;
}

static int client_del(const char *q)
{
    app_begin();
    client_t *c = find_or_die(q);
    if (!c) {
        app_abort();
        return 1;
    }
    char name[256], id[24];
    str_copy(name, c->name, sizeof name);
    str_copy(id, c->id, sizeof id);
    db_client_shares_remove(&g_db, id);
    db_client_remove(&g_db, db_client_index(&g_db, id));
    app_commit();
    printf("%s✔%s Đã xóa %s\n", C_GREEN, C_RESET, name);
    apply_after_cli();
    return 0;
}

int cmd_client(int argc, char **argv)
{
    if (argc < 1 || !strcmp(argv[0], "help") || !strcmp(argv[0], "--help")) {
        usage_client();
        return argc < 1 ? 2 : 0;
    }
    const char *sub = argv[0];
    bool readonly = !strcmp(sub, "list") || !strcmp(sub, "ls") || !strcmp(sub, "show") ||
                    !strcmp(sub, "config") || !strcmp(sub, "qr");
    if (!readonly && !cli_is_root() && !g_app.demo && !strcmp(g_app.data_dir, TWG_DEFAULT_DIR)) {
        fprintf(stderr, "Cần quyền root: hãy chạy với sudo\n");
        return 1;
    }
    if (cli_open_db(true) != 0)
        return 1;
    if (!strcmp(sub, "list") || !strcmp(sub, "ls"))
        return client_list();
    if (!strcmp(sub, "add") || !strcmp(sub, "create"))
        return client_add(argc - 1, argv + 1);
    if (argc < 2) {
        usage_client();
        return 2;
    }
    const char *q = argv[1];
    bool qr = argc > 2 && !strcmp(argv[2], "--qr");
    if (!strcmp(sub, "show"))
        return client_show(q, qr);
    if (!strcmp(sub, "config") || !strcmp(sub, "qr")) {
        client_t *c = find_or_die(q);
        if (!c)
            return 1;
        print_client_config(c, !strcmp(sub, "qr"));
        return 0;
    }
    if (!strcmp(sub, "enable"))
        return client_set_enabled(q, true);
    if (!strcmp(sub, "disable"))
        return client_set_enabled(q, false);
    if (!strcmp(sub, "del") || !strcmp(sub, "delete") || !strcmp(sub, "rm"))
        return client_del(q);
    usage_client();
    return 2;
}

/* ================= passwd / 2fa ================= */

int cmd_passwd(int argc, char **argv)
{
    if (!cli_is_root() && !strcmp(g_app.data_dir, TWG_DEFAULT_DIR)) {
        fprintf(stderr, "Cần quyền root: hãy chạy với sudo\n");
        return 1;
    }
    if (cli_open_db(true) != 0)
        return 1;
    char pw[256] = "", pw2[256];
    bool random = false;
    if (argc >= 1 && !strcmp(argv[0], "--random")) {
        auth_random_password(pw, 15);
        random = true;
    } else if (argc >= 1) {
        str_copy(pw, argv[0], sizeof pw);
    } else {
        if (cli_read_password("Mật khẩu mới", pw, sizeof pw) != 0 ||
            cli_read_password("Nhập lại mật khẩu", pw2, sizeof pw2) != 0)
            return 1;
        if (strcmp(pw, pw2) != 0) {
            fprintf(stderr, "%sHai lần nhập không khớp%s\n", C_RED, C_RESET);
            return 1;
        }
    }
    if (strlen(pw) < 8) {
        fprintf(stderr, "%sMật khẩu phải có ít nhất 8 ký tự%s\n", C_RED, C_RESET);
        return 1;
    }
    char hash[192];
    auth_hash_password(pw, hash, sizeof hash);
    app_begin();
    str_copy(g_db.s.admin_hash, hash, sizeof g_db.s.admin_hash);
    char user[64];
    str_copy(user, g_db.s.admin_user, sizeof user);
    app_commit();
    printf("%s✔%s Đã đặt lại mật khẩu cho tài khoản %s%s%s\n", C_GREEN, C_RESET, C_BOLD, user, C_RESET);
    if (random)
        printf("  Mật khẩu mới: %s%s%s\n", C_YELLOW, pw, C_RESET);
    secure_zero(pw, sizeof pw);
    return 0;
}

int cmd_reset_2fa(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (!cli_is_root() && !strcmp(g_app.data_dir, TWG_DEFAULT_DIR)) {
        fprintf(stderr, "Cần quyền root: hãy chạy với sudo\n");
        return 1;
    }
    if (cli_open_db(true) != 0)
        return 1;
    app_begin();
    g_db.s.totp_enabled = false;
    g_db.s.totp_secret[0] = 0;
    app_commit();
    printf("%s✔%s Đã tắt xác thực 2 lớp (2FA)\n", C_GREEN, C_RESET);
    return 0;
}

/* ================= status ================= */

static const char *svc_state(const char *unit)
{
    static char buf[64];
    if (!app_systemd_running())
        return "không có systemd";
    const char *argv[] = {"systemctl", "is-active", unit, NULL};
    cmd_result_t r;
    run_cmd(argv, NULL, NULL, 5000, &r);
    str_copy(buf, r.out ? r.out : "?", sizeof buf);
    str_trim(buf);
    cmd_result_free(&r);
    return buf;
}

int cmd_status(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (cli_open_db(true) != 0)
        return 1;
    const settings_t *s = &g_db.s;
    printf("%s%s%s v%s  -  tác giả %s\n\n", C_BOLD, TWG_NAME, C_RESET, TWG_VERSION, TWG_AUTHOR);
    const char *web = svc_state("tuan-wg");
    printf("  Dịch vụ web (tuan-wg):   %s%s%s\n", !strcmp(web, "active") ? C_GREEN : C_YELLOW,
           !strcmp(web, "active") ? "● đang chạy" : web, C_RESET);
    wg_status_t st;
    char err[256];
    int64_t now = now_unix();
    if (wg_dump(s->iface, &st, err, sizeof err) == 0 && st.up) {
        int online = 0;
        for (int i = 0; i < st.npeers; i++)
            if (st.peers[i].handshake && now - st.peers[i].handshake < ONLINE_WINDOW)
                online++;
        printf("  WireGuard (%s):         %s● hoạt động%s, cổng %d/udp, %d peer (%d online)\n", s->iface,
               C_GREEN, C_RESET, st.listen_port, st.npeers, online);
        wg_status_free(&st);
    } else {
        printf("  WireGuard (%s):         %s○ không hoạt động%s %s\n", s->iface, C_RED, C_RESET, err);
    }
    int en = 0;
    for (int i = 0; i < g_db.nclients; i++)
        if (g_db.clients[i].enabled)
            en++;
    printf("  Người dùng:              %d (%d đang bật)\n", g_db.nclients, en);
    char host[256];
    str_copy(host, s->endpoint, sizeof host);
    char *colon = strrchr(host, ':');
    if (colon && !strchr(host, ']') && strchr(host, ':') == colon)
        *colon = 0;
    if (!host[0])
        net_local_ip(host, sizeof host);
    printf("  Giao diện web:           %shttp://%s:%d%s\n", C_CYAN,
           strcmp(s->web_listen, "0.0.0.0") && strcmp(s->web_listen, "::") ? s->web_listen : host,
           s->web_port, C_RESET);
    printf("  Endpoint cho client:     %s:%d\n", s->endpoint[0] ? s->endpoint : "(chưa đặt)", s->listen_port);
    printf("  Dải mạng VPN:            %s%s%s\n", s->address, s->ipv6 ? ", " : "", s->ipv6 ? s->address6 : "");
    printf("  Thư mục dữ liệu:         %s\n", g_app.data_dir);
    return 0;
}

/* ================= backup / restore ================= */

int cmd_backup(int argc, char **argv)
{
    if (cli_open_db(true) != 0)
        return 1;
    stats_load(g_app.stats_path);
    sb_t b;
    sb_init(&b);
    sb_printf(&b, "{\"tuan_wg_backup\":1,\"version\":\"%s\",\"created_at\":%lld,\"db\":", TWG_VERSION,
              (long long)now_unix());
    db_to_json(&g_db, &b);
    sb_append(&b, ",\"stats\":");
    stats_to_json(&b);
    sb_append(&b, "}\n");
    int rc = 0;
    if (argc >= 1 && strcmp(argv[0], "-") != 0) {
        if (file_write_atomic(argv[0], b.s, b.len, 0600) != 0) {
            fprintf(stderr, "Không ghi được %s\n", argv[0]);
            rc = 1;
        } else {
            printf("%s✔%s Đã sao lưu %d người dùng vào %s\n", C_GREEN, C_RESET, g_db.nclients, argv[0]);
        }
    } else {
        fwrite(b.s, 1, b.len, stdout);
    }
    sb_free(&b);
    return rc;
}

int cmd_restore(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Cách dùng: tuan-wg restore <file-sao-luu.json>\n");
        return 2;
    }
    if (!cli_is_root() && !strcmp(g_app.data_dir, TWG_DEFAULT_DIR)) {
        fprintf(stderr, "Cần quyền root: hãy chạy với sudo\n");
        return 1;
    }
    size_t len;
    char *data = file_read(argv[0], &len);
    if (!data) {
        fprintf(stderr, "Không đọc được %s\n", argv[0]);
        return 1;
    }
    char err[256];
    json_t *j = json_parse(data, len, err, sizeof err);
    free(data);
    const json_t *dbj = j ? json_get(j, "db") : NULL;
    if (j && !dbj && json_get(j, "server"))
        dbj = j;
    if (!dbj) {
        fprintf(stderr, "File sao lưu không hợp lệ\n");
        json_free(j);
        return 1;
    }
    if (cli_open_db(false) != 0) {
        json_free(j);
        return 1;
    }
    app_begin();
    if (db_from_json(&g_db, dbj, err, sizeof err) != 0) {
        app_abort();
        fprintf(stderr, "Lỗi: %s\n", err);
        json_free(j);
        return 1;
    }
    app_commit();
    const json_t *st = json_get(j, "stats");
    if (st) {
        pthread_mutex_lock(&g_lock);
        stats_from_json(st);
        pthread_mutex_unlock(&g_lock);
        stats_save(g_app.stats_path);
    }
    json_free(j);
    printf("%s✔%s Đã khôi phục %d người dùng.\n", C_GREEN, C_RESET, g_db.nclients);
    apply_after_cli();
    if (app_systemd_running())
        printf("Khởi động lại dịch vụ để nạp thống kê: %ssudo systemctl restart tuan-wg%s\n", C_CYAN, C_RESET);
    return 0;
}
