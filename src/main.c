/*
 * Tuấn WireGuard - giao diện web quản lý máy chủ WireGuard
 * Tác giả: Tuandethuong
 * Mã nguồn: https://github.com/tlearnvn/tuan-wg
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "app.h"
#include "audit.h"
#include "auth.h"
#include "cli.h"
#include "demo.h"
#include "http.h"
#include "stats.h"
#include "wg.h"

static volatile int g_stop = 0;
static volatile int g_restart = 0;
static int g_wake[2] = {-1, -1};

static void wake_main(void)
{
    if (g_wake[1] >= 0) {
        char c = 1;
        ssize_t r = write(g_wake[1], &c, 1);
        (void)r;
    }
}

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
    wake_main();
}

static void request_restart(void)
{
    g_restart = 1;
    g_stop = 1;
    wake_main();
}

static void usage(void)
{
    printf("%s%s%s v%s - giao diện web quản lý máy chủ WireGuard\n", C_BOLD, TWG_NAME, C_RESET, TWG_VERSION);
    printf("Tác giả: %s  •  %s\n\n", TWG_AUTHOR, TWG_REPO);
    printf("%sCách dùng:%s tuan-wg <lệnh> [tùy chọn]\n\n", C_BOLD, C_RESET);
    printf("%sCài đặt & dịch vụ%s\n", C_CYAN, C_RESET);
    printf("  install [-y]             Cài WireGuard + giao diện web + dịch vụ tự khởi động\n"
           "  uninstall [--purge]      Gỡ cài đặt (--purge: xóa luôn dữ liệu và WireGuard)\n"
           "  service <lệnh>           install|remove|start|stop|restart|status|logs\n"
           "  serve                    Chạy máy chủ web (dịch vụ systemd gọi lệnh này)\n"
           "  status                   Xem trạng thái máy chủ\n\n");
    printf("%sNgười dùng VPN%s\n", C_CYAN, C_RESET);
    printf("  client list              Danh sách người dùng\n"
           "  client add <tên>         Thêm người dùng (xem: tuan-wg client help)\n"
           "  client show <tên> [--qr] Xem cấu hình / in mã QR ra terminal\n"
           "  client enable|disable|del <tên>\n\n");
    printf("%sQuản trị%s\n", C_CYAN, C_RESET);
    printf("  passwd [MẬT_KHẨU]        Đặt lại mật khẩu quản trị (--random: tạo ngẫu nhiên)\n"
           "  reset-2fa                Tắt xác thực 2 lớp khi mất điện thoại\n"
           "  backup [FILE]            Sao lưu dữ liệu ra file JSON\n"
           "  restore FILE             Khôi phục từ file sao lưu\n"
           "  version                  Xem phiên bản\n\n");
    printf("%sTùy chọn chung%s\n", C_CYAN, C_RESET);
    printf("  --data-dir DIR           Thư mục dữ liệu (mặc định %s, hoặc biến TUAN_WG_DIR)\n"
           "  --wg-dir DIR             Thư mục cấu hình WireGuard (mặc định /etc/wireguard)\n"
           "  --demo                   Chế độ trình diễn: dữ liệu mẫu, không đụng tới WireGuard\n"
           "  --verbose                In thêm thông tin gỡ lỗi\n\n",
           TWG_DEFAULT_DIR);
    printf("Ví dụ: %ssudo tuan-wg install%s  rồi mở trình duyệt tới http://IP-máy-chủ:51821\n", C_BOLD, C_RESET);
}

static int cmd_serve(int argc, char **argv, char **orig_argv)
{
    const char *o_listen = NULL;
    int o_port = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--listen") && i + 1 < argc)
            o_listen = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc)
            o_port = atoi(argv[++i]);
    }
    if (mkdir_p(g_app.data_dir, 0700) != 0) {
        LOGE("Không tạo được thư mục dữ liệu %s: %s", g_app.data_dir, strerror(errno));
        return 1;
    }
    char err[256];
    int r = app_db_open(err, sizeof err);
    if (r < 0) {
        LOGE("Không đọc được dữ liệu: %s", err);
        return 1;
    }
    audit_init(g_app.audit_path);
    auth_sessions_load(g_app.sessions_path);
    pthread_mutex_lock(&g_lock);
    stats_load(g_app.stats_path);
    pthread_mutex_unlock(&g_lock);
    if (g_app.demo)
        demo_seed(); /* đặt sẵn khóa + tài khoản admin/admin + dữ liệu mẫu */
    char genpw[64] = "";
    app_begin();
    bool gen = cli_first_run_init(genpw, sizeof genpw);
    app_commit();
    if (gen && !g_app.demo) {
        LOGW("============================================================");
        LOGW("Đã tạo tài khoản quản trị: %s / %s", g_db.s.admin_user, genpw);
        LOGW("Hãy đổi mật khẩu sau khi đăng nhập (hoặc: tuan-wg passwd)");
        LOGW("============================================================");
    }
    if (g_app.demo) {
        LOGW("CHẾ ĐỘ DEMO: dữ liệu mẫu, không thay đổi WireGuard thật. Đăng nhập: admin / admin");
    } else {
        if (wg_apply(false, err, sizeof err) != 0)
            LOGW("WireGuard chưa sẵn sàng: %s", err);
        else
            LOGI("WireGuard %s đã sẵn sàng", g_db.s.iface);
    }

    if (pipe2(g_wake, O_CLOEXEC | O_NONBLOCK) != 0)
        g_wake[0] = g_wake[1] = -1;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGHUP, &sa, NULL);

    collector_start();
    api_set_restart_cb(request_restart);

    char listen[64];
    int port;
    app_rlock();
    str_copy(listen, o_listen ? o_listen : g_db.s.web_listen, sizeof listen);
    port = o_port ? o_port : g_db.s.web_port;
    app_runlock();
    LOGI("%s v%s (build %s) đang khởi động - dữ liệu: %s", TWG_NAME, TWG_VERSION, TWG_BUILD, g_app.data_dir);
    int rc = http_serve(listen, port, api_handle, &g_stop, g_wake[0]);
    if (rc != 0 && !g_stop && strcmp(listen, "0.0.0.0") != 0 && strcmp(listen, "::") != 0) {
        /* địa chỉ lắng nghe có thể chưa tồn tại (ví dụ IP của wg0) - thử lại với mọi địa chỉ */
        LOGW("Thử lắng nghe trên 0.0.0.0:%d", port);
        rc = http_serve("0.0.0.0", port, api_handle, &g_stop, g_wake[0]);
    }
    collector_stop();
    stats_save(g_app.stats_path);
    auth_sessions_save();
    if (rc != 0) {
        LOGE("Không khởi động được giao diện web");
        return 1;
    }
    if (g_restart) {
        LOGI("Khởi động lại tiến trình để áp dụng cấu hình web mới...");
        /* bỏ --listen/--port trên dòng lệnh để cổng/địa chỉ mới trong cài đặt có hiệu lực */
        int n = 0;
        while (orig_argv[n])
            n++;
        char **nargv = calloc((size_t)n + 1, sizeof(char *));
        int k = 0;
        for (int i = 0; nargv && i < n; i++) {
            if ((!strcmp(orig_argv[i], "--listen") || !strcmp(orig_argv[i], "--port")) && i + 1 < n) {
                i++;
                continue;
            }
            nargv[k++] = orig_argv[i];
        }
        execv(g_app.exe, nargv ? nargv : orig_argv);
        LOGE("execv lỗi: %s", strerror(errno));
        return 1;
    }
    LOGI("Đã dừng.");
    return 0;
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    cli_colors_init();
    ssize_t n = readlink("/proc/self/exe", g_app.exe, sizeof g_app.exe - 1);
    if (n > 0)
        g_app.exe[n] = 0;
    else
        str_copy(g_app.exe, argv[0], sizeof g_app.exe);

    const char *dir = getenv("TUAN_WG_DIR");
    bool dir_set = dir && *dir;
    char *rest[256];
    int nrest = 0;
    for (int i = 1; i < argc && nrest < 255; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--data-dir") && i + 1 < argc) {
            dir = argv[++i];
            dir_set = true;
        } else if (!strcmp(a, "--wg-dir") && i + 1 < argc) {
            str_copy(g_app.wg_dir, argv[++i], sizeof g_app.wg_dir);
        } else if (!strcmp(a, "--demo")) {
            g_app.demo = true;
        } else if (!strcmp(a, "--no-wg")) {
            g_app.no_wg = true;
        } else if (!strcmp(a, "--verbose") || !strcmp(a, "-v")) {
            g_log_level = LOG_DEBUG;
        } else {
            rest[nrest++] = argv[i];
        }
    }
    rest[nrest] = NULL;
    if (g_app.demo && !dir_set)
        dir = "/tmp/tuan-wg-demo";
    app_set_data_dir(dir_set || g_app.demo ? dir : TWG_DEFAULT_DIR);

    const char *cmd = nrest > 0 ? rest[0] : "help";
    int sub_argc = nrest > 0 ? nrest - 1 : 0;
    char **sub_argv = rest + 1;

    if (!strcmp(cmd, "serve") || !strcmp(cmd, "run"))
        return cmd_serve(sub_argc, sub_argv, argv);
    if (!strcmp(cmd, "install"))
        return cmd_install(sub_argc, sub_argv);
    if (!strcmp(cmd, "uninstall"))
        return cmd_uninstall(sub_argc, sub_argv);
    if (!strcmp(cmd, "service"))
        return cmd_service(sub_argc, sub_argv);
    if (!strcmp(cmd, "client") || !strcmp(cmd, "user") || !strcmp(cmd, "clients"))
        return cmd_client(sub_argc, sub_argv);
    if (!strcmp(cmd, "passwd") || !strcmp(cmd, "password"))
        return cmd_passwd(sub_argc, sub_argv);
    if (!strcmp(cmd, "reset-2fa"))
        return cmd_reset_2fa(sub_argc, sub_argv);
    if (!strcmp(cmd, "status"))
        return cmd_status(sub_argc, sub_argv);
    if (!strcmp(cmd, "backup"))
        return cmd_backup(sub_argc, sub_argv);
    if (!strcmp(cmd, "restore"))
        return cmd_restore(sub_argc, sub_argv);
    if (!strcmp(cmd, "version") || !strcmp(cmd, "--version") || !strcmp(cmd, "-V")) {
        printf("%s %s (build %s)\nTác giả: %s\n%s\n", TWG_NAME, TWG_VERSION, TWG_BUILD, TWG_AUTHOR, TWG_REPO);
        return 0;
    }
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        usage();
        return 0;
    }
    fprintf(stderr, "Lệnh không hợp lệ: %s\n\n", cmd);
    usage();
    return 2;
}
