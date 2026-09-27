/*
 * Tuấn WireGuard - tạo file ZIP (phương thức store, không nén)
 * Tác giả: Tuandethuong
 */
#include "zip.h"

#include <string.h>

#include "crypto.h"

static void put16(sb_t *b, uint16_t v)
{
    char c[2] = {(char)(v & 0xff), (char)(v >> 8)};
    sb_appendn(b, c, 2);
}

static void put32(sb_t *b, uint32_t v)
{
    char c[4] = {(char)(v & 0xff), (char)((v >> 8) & 0xff), (char)((v >> 16) & 0xff),
                 (char)(v >> 24)};
    sb_appendn(b, c, 4);
}

static void dos_time(time_t t, uint16_t *dtime, uint16_t *ddate)
{
    struct tm tm;
    localtime_r(&t, &tm);
    if (tm.tm_year < 80) {
        *dtime = 0;
        *ddate = (1 << 5) | 1;
        return;
    }
    *dtime = (uint16_t)((tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2));
    *ddate = (uint16_t)(((tm.tm_year - 80) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday);
}

void zip_init(zip_t *z)
{
    sb_init(&z->data);
    sb_init(&z->central);
    z->count = 0;
}

void zip_add(zip_t *z, const char *name, const void *data, size_t len, time_t mtime)
{
    uint32_t crc = crc32_update(0, data, len);
    uint16_t dt, dd;
    dos_time(mtime, &dt, &dd);
    uint32_t offset = (uint32_t)z->data.len;
    uint16_t nlen = (uint16_t)strlen(name);
    const uint16_t flags = 0x0800; /* tên file UTF-8 */

    put32(&z->data, 0x04034b50);
    put16(&z->data, 10);
    put16(&z->data, flags);
    put16(&z->data, 0); /* store */
    put16(&z->data, dt);
    put16(&z->data, dd);
    put32(&z->data, crc);
    put32(&z->data, (uint32_t)len);
    put32(&z->data, (uint32_t)len);
    put16(&z->data, nlen);
    put16(&z->data, 0);
    sb_appendn(&z->data, name, nlen);
    sb_appendn(&z->data, data, len);

    put32(&z->central, 0x02014b50);
    put16(&z->central, (3 << 8) | 20); /* tạo trên Unix */
    put16(&z->central, 10);
    put16(&z->central, flags);
    put16(&z->central, 0);
    put16(&z->central, dt);
    put16(&z->central, dd);
    put32(&z->central, crc);
    put32(&z->central, (uint32_t)len);
    put32(&z->central, (uint32_t)len);
    put16(&z->central, nlen);
    put16(&z->central, 0);
    put16(&z->central, 0);
    put16(&z->central, 0);
    put16(&z->central, 0);
    put32(&z->central, (uint32_t)0100600 << 16); /* quyền -rw------- */
    put32(&z->central, offset);
    sb_appendn(&z->central, name, nlen);
    z->count++;
}

void zip_finish(zip_t *z, sb_t *out)
{
    uint32_t cd_off = (uint32_t)z->data.len;
    uint32_t cd_len = (uint32_t)z->central.len;
    sb_appendn(&z->data, z->central.s ? z->central.s : "", z->central.len);
    put32(&z->data, 0x06054b50);
    put16(&z->data, 0);
    put16(&z->data, 0);
    put16(&z->data, (uint16_t)z->count);
    put16(&z->data, (uint16_t)z->count);
    put32(&z->data, cd_len);
    put32(&z->data, cd_off);
    put16(&z->data, 0);
    sb_free(&z->central);
    *out = z->data;
    sb_init(&z->data);
}
