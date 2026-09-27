/*
 * Tuấn WireGuard - trạng thái toàn cục của ứng dụng
 * Tác giả: Tuandethuong
 */
#include "app.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

app_t g_app = {.lock_fd = -1};
db_t g_db;
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void app_set_data_dir(const char *dir)
{
    str_copy(g_app.data_dir, dir, sizeof g_app.data_dir);
    size_t n = strlen(g_app.data_dir);
    while (n > 1 && g_app.data_dir[n - 1] == '/')
        g_app.data_dir[--n] = 0;
    snprintf(g_app.db_path, sizeof g_app.db_path, "%s/db.json", g_app.data_dir);
    snprintf(g_app.stats_path, sizeof g_app.stats_path, "%s/stats.json", g_app.data_dir);
    snprintf(g_app.audit_path, sizeof g_app.audit_path, "%s/audit.log", g_app.data_dir);
    snprintf(g_app.sessions_path, sizeof g_app.sessions_path, "%s/sessions.json", g_app.data_dir);
    snprintf(g_app.lock_path, sizeof g_app.lock_path, "%s/.lock", g_app.data_dir);
    if (!g_app.wg_dir[0])
        str_copy(g_app.wg_dir, "/etc/wireguard", sizeof g_app.wg_dir);
}

int app_db_open(char *err, size_t errsz)
{
    db_defaults(&g_db);
    int r = db_load_file(&g_db, g_app.db_path, err, errsz);
    if (r == 1) {
        db_defaults(&g_db);
        return 1;
    }
    return r;
}

static void reload_if_changed_q(bool quiet)
{
    int64_t sig = file_mtime_ns(g_app.db_path);
    if (sig && sig != g_db.file_sig) {
        char err[256];
        db_t tmp;
        db_defaults(&tmp);
        if (db_load_file(&tmp, g_app.db_path, err, sizeof err) == 0) {
            db_free(&g_db);
            g_db = tmp;
            if (!quiet)
                LOGI("Đã nạp lại dữ liệu (file db.json thay đổi từ bên ngoài)");
        } else {
            db_free(&tmp);
            LOGW("Không nạp lại được db.json: %s", err);
            g_db.file_sig = sig; /* tránh báo lỗi lặp lại */
        }
    }
}

static void reload_if_changed(void)
{
    reload_if_changed_q(false);
}

static void file_lock(void)
{
    if (g_app.lock_fd < 0) {
        g_app.lock_fd = open(g_app.lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (g_app.lock_fd < 0)
            return;
    }
    while (flock(g_app.lock_fd, LOCK_EX) != 0 && errno == EINTR) {
    }
}

static void file_unlock(void)
{
    if (g_app.lock_fd >= 0)
        flock(g_app.lock_fd, LOCK_UN);
}

void app_rlock(void)
{
    pthread_mutex_lock(&g_lock);
    reload_if_changed();
}

void app_runlock(void)
{
    pthread_mutex_unlock(&g_lock);
}

void app_begin(void)
{
    pthread_mutex_lock(&g_lock);
    file_lock();
    reload_if_changed();
}

int app_commit(void)
{
    int r = db_save_file(&g_db, g_app.db_path);
    if (r != 0)
        LOGE("Không ghi được %s: %s", g_app.db_path, strerror(errno));
    file_unlock();
    pthread_mutex_unlock(&g_lock);
    return r;
}

void app_abort(void)
{
    /* buộc nạp lại từ đĩa để bỏ các thay đổi dang dở */
    g_db.file_sig = -1;
    reload_if_changed_q(true);
    file_unlock();
    pthread_mutex_unlock(&g_lock);
}

bool app_systemd_running(void)
{
    return is_dir("/run/systemd/system");
}
