/*
 * Tuấn WireGuard - trạng thái toàn cục của ứng dụng
 * Tác giả: Tuandethuong
 */
#ifndef TWG_APP_H
#define TWG_APP_H

#include <pthread.h>
#include <stdbool.h>

#include "store.h"

#define TWG_NAME "Tuấn WireGuard"
#define TWG_AUTHOR "Tuandethuong"
#define TWG_REPO "https://github.com/tlearnvn/tuan-wg"
#ifndef TWG_VERSION
#define TWG_VERSION "0.0.0-dev"
#endif
#ifndef TWG_BUILD
#define TWG_BUILD "dev"
#endif

#define TWG_DEFAULT_DIR "/etc/tuan-wg"

typedef struct {
    char data_dir[256];
    char db_path[320];
    char stats_path[320];
    char audit_path[320];
    char sessions_path[320];
    char lock_path[320];
    char wg_dir[256];
    char exe[512];
    bool demo;    /* chế độ trình diễn: không đụng tới WireGuard thật */
    bool no_wg;   /* không gọi lệnh WireGuard (kiểm thử) */
    int lock_fd;
} app_t;

extern app_t g_app;
extern db_t g_db;
extern pthread_mutex_t g_lock;

void app_set_data_dir(const char *dir);
/* Đọc db.json (hoặc tạo mặc định trong bộ nhớ). 0 = ok, 1 = mới, -1 = lỗi */
int app_db_open(char *err, size_t errsz);

/* Đọc: khóa mutex, tự nạp lại nếu file bị CLI sửa */
void app_rlock(void);
void app_runlock(void);
/* Ghi: khóa mutex + flock file, nạp lại nếu cần */
void app_begin(void);
int app_commit(void);   /* lưu rồi mở khóa */
void app_abort(void);   /* mở khóa không lưu (nạp lại từ đĩa để hủy thay đổi) */

bool app_systemd_running(void);

#endif
