/*
 * Tuấn WireGuard - tài nguyên web nhúng trong binary (sinh bởi tools/embed.c)
 * Tác giả: Tuandethuong
 */
#ifndef TWG_ASSETS_H
#define TWG_ASSETS_H

#include <stddef.h>

typedef struct {
    const char *path;
    const char *mime;
    const unsigned char *data;
    size_t len;
    const unsigned char *gz;
    size_t gzlen;
} asset_t;

extern const asset_t g_assets[];
extern const size_t g_nassets;
extern const char g_assets_etag[];

const asset_t *asset_find(const char *path);

#endif
