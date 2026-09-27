/*
 * Tuấn WireGuard - thông tin hệ thống (CPU, RAM, ổ đĩa, uptime...)
 * Tác giả: Tuandethuong
 */
#ifndef TWG_SYSINFO_H
#define TWG_SYSINFO_H

#include <stdint.h>

typedef struct {
    double load1, load5, load15;
    uint64_t mem_total, mem_avail;
    uint64_t disk_total, disk_free;
    int64_t uptime;
    int cpus;
    char hostname[128];
    char kernel[128];
    char os[128];
} sysinfo_t;

void sysinfo_get(sysinfo_t *si);
/* Lấy mẫu CPU; trả về % sử dụng kể từ lần gọi trước */
double sysinfo_cpu_sample(uint64_t *prev_total, uint64_t *prev_idle);

#endif
