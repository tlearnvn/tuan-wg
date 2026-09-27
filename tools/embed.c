/*
 * Tuấn WireGuard - công cụ nhúng file tĩnh vào mã C
 * Cách dùng: embed <output.c> <root_dir> <file1> [<file2> ...]
 *   Với mỗi file, nếu tồn tại <file>.gz thì nhúng thêm bản nén gzip.
 * Tác giả: Tuandethuong
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc((size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        free(buf);
        return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static const char *mime_of(const char *p)
{
    const char *dot = strrchr(p, '.');
    if (!dot)
        return "application/octet-stream";
    if (!strcmp(dot, ".html"))
        return "text/html; charset=utf-8";
    if (!strcmp(dot, ".css"))
        return "text/css; charset=utf-8";
    if (!strcmp(dot, ".js"))
        return "text/javascript; charset=utf-8";
    if (!strcmp(dot, ".svg"))
        return "image/svg+xml";
    if (!strcmp(dot, ".woff2"))
        return "font/woff2";
    if (!strcmp(dot, ".png"))
        return "image/png";
    if (!strcmp(dot, ".ico"))
        return "image/x-icon";
    if (!strcmp(dot, ".json") || !strcmp(dot, ".webmanifest"))
        return "application/manifest+json";
    if (!strcmp(dot, ".md"))
        return "text/markdown; charset=utf-8";
    if (!strcmp(dot, ".txt"))
        return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

static void dump(FILE *o, const char *name, const unsigned char *d, size_t n)
{
    fprintf(o, "static const unsigned char %s[] = {", name);
    for (size_t i = 0; i < n; i++) {
        if (i % 20 == 0)
            fprintf(o, "\n ");
        fprintf(o, "%u,", d[i]);
    }
    fprintf(o, "0};\n");
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: embed out.c root files...\n");
        return 2;
    }
    FILE *o = fopen(argv[1], "w");
    if (!o)
        return 1;
    const char *root = argv[2];
    size_t rootlen = strlen(root);
    unsigned long hash = 5381;
    fprintf(o, "/* Tệp sinh tự động bởi tools/embed.c - không sửa tay */\n#include \"assets.h\"\n#include <string.h>\n\n");
    int n = argc - 3;
    for (int i = 0; i < n; i++) {
        const char *path = argv[3 + i];
        size_t len, gzlen = 0;
        unsigned char *d = read_file(path, &len);
        if (!d) {
            fprintf(stderr, "không đọc được %s\n", path);
            return 1;
        }
        for (size_t k = 0; k < len; k++)
            hash = ((hash << 5) + hash) ^ d[k];
        char name[32];
        snprintf(name, sizeof name, "a%d", i);
        dump(o, name, d, len);
        free(d);
        char gzpath[4096];
        snprintf(gzpath, sizeof gzpath, "%s.gz", path);
        unsigned char *g = read_file(gzpath, &gzlen);
        if (g && gzlen < len) {
            snprintf(name, sizeof name, "g%d", i);
            dump(o, name, g, gzlen);
        } else {
            gzlen = 0;
        }
        free(g);
    }
    fprintf(o, "\nconst asset_t g_assets[] = {\n");
    for (int i = 0; i < n; i++) {
        const char *path = argv[3 + i];
        const char *rel = path;
        if (strncmp(path, root, rootlen) == 0)
            rel = path + rootlen;
        size_t len, gzlen = 0;
        unsigned char *d = read_file(path, &len);
        char gzpath[4096];
        snprintf(gzpath, sizeof gzpath, "%s.gz", path);
        unsigned char *g = read_file(gzpath, &gzlen);
        int has_gz = g && gzlen < len;
        char gzname[32] = "0";
        if (has_gz)
            snprintf(gzname, sizeof gzname, "g%d", i);
        fprintf(o, "  {\"%s%s\", \"%s\", a%d, %zu, %s, %zu},\n", rel[0] == '/' ? "" : "/", rel,
                mime_of(path), i, len, gzname, has_gz ? gzlen : 0);
        free(d);
        free(g);
    }
    fprintf(o, "};\nconst size_t g_nassets = %d;\n", n);
    fprintf(o, "const char g_assets_etag[] = \"\\\"%08lx\\\"\";\n\n", hash & 0xffffffffUL);
    fprintf(o, "const asset_t *asset_find(const char *path)\n{\n"
               "    for (size_t i = 0; i < g_nassets; i++)\n"
               "        if (strcmp(g_assets[i].path, path) == 0)\n"
               "            return &g_assets[i];\n"
               "    return 0;\n}\n");
    fclose(o);
    return 0;
}
