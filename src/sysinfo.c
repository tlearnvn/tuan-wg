/*
 * Tuấn WireGuard - thông tin hệ thống
 * Tác giả: Tuandethuong
 */
#include "sysinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "util.h"

void sysinfo_get(sysinfo_t *si)
{
    memset(si, 0, sizeof *si);
    FILE *f = fopen("/proc/loadavg", "re");
    if (f) {
        if (fscanf(f, "%lf %lf %lf", &si->load1, &si->load5, &si->load15) != 3)
            si->load1 = si->load5 = si->load15 = 0;
        fclose(f);
    }
    f = fopen("/proc/meminfo", "re");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f)) {
            unsigned long long v;
            if (sscanf(line, "MemTotal: %llu kB", &v) == 1)
                si->mem_total = v * 1024;
            else if (sscanf(line, "MemAvailable: %llu kB", &v) == 1)
                si->mem_avail = v * 1024;
        }
        fclose(f);
    }
    struct statvfs vfs;
    if (statvfs("/", &vfs) == 0) {
        si->disk_total = (uint64_t)vfs.f_blocks * vfs.f_frsize;
        si->disk_free = (uint64_t)vfs.f_bavail * vfs.f_frsize;
    }
    f = fopen("/proc/uptime", "re");
    if (f) {
        double up = 0;
        if (fscanf(f, "%lf", &up) == 1)
            si->uptime = (int64_t)up;
        fclose(f);
    }
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    si->cpus = n > 0 ? (int)n : 1;
    gethostname(si->hostname, sizeof si->hostname - 1);
    struct utsname u;
    if (uname(&u) == 0)
        snprintf(si->kernel, sizeof si->kernel, "%.20s %.100s", u.sysname, u.release);
    f = fopen("/etc/os-release", "re");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f)) {
            if (str_starts(line, "PRETTY_NAME=")) {
                char *v = line + strlen("PRETTY_NAME=");
                str_trim(v);
                size_t l = strlen(v);
                if (l >= 2 && v[0] == '"' && v[l - 1] == '"') {
                    v[l - 1] = 0;
                    v++;
                }
                str_copy(si->os, v, sizeof si->os);
            }
        }
        fclose(f);
    }
}

double sysinfo_cpu_sample(uint64_t *prev_total, uint64_t *prev_idle)
{
    FILE *f = fopen("/proc/stat", "re");
    if (!f)
        return 0;
    unsigned long long u = 0, n = 0, s = 0, idle = 0, io = 0, irq = 0, sirq = 0, st = 0;
    int r = fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &u, &n, &s, &idle, &io, &irq,
                   &sirq, &st);
    fclose(f);
    if (r < 4)
        return 0;
    uint64_t total = u + n + s + idle + io + irq + sirq + st;
    uint64_t idl = idle + io;
    double pct = 0;
    if (*prev_total && total > *prev_total) {
        uint64_t dt = total - *prev_total;
        uint64_t di = idl >= *prev_idle ? idl - *prev_idle : 0;
        pct = 100.0 * (double)(dt - (di > dt ? dt : di)) / (double)dt;
    }
    *prev_total = total;
    *prev_idle = idl;
    return pct;
}
