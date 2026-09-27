/*
 * Tuấn WireGuard - mã QR (SVG / terminal)
 * Tác giả: Tuandethuong
 */
#include "qr.h"

#include <stdint.h>
#include <stdlib.h>

#include "qrcodegen.h"

typedef struct {
    uint8_t *buf;
    int size;
} qr_t;

static int qr_make(const char *text, qr_t *q)
{
    uint8_t *tmp = xmalloc(qrcodegen_BUFFER_LEN_MAX);
    q->buf = xmalloc(qrcodegen_BUFFER_LEN_MAX);
    bool ok = qrcodegen_encodeText(text, tmp, q->buf, qrcodegen_Ecc_LOW, qrcodegen_VERSION_MIN,
                                   qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true);
    free(tmp);
    if (!ok) {
        free(q->buf);
        q->buf = NULL;
        return -1;
    }
    q->size = qrcodegen_getSize(q->buf);
    return 0;
}

static bool qr_dark(const qr_t *q, int x, int y)
{
    if (x < 0 || y < 0 || x >= q->size || y >= q->size)
        return false;
    return qrcodegen_getModule(q->buf, x, y);
}

int qr_svg(const char *text, sb_t *out)
{
    qr_t q;
    if (qr_make(text, &q) != 0)
        return -1;
    const int border = 3;
    int dim = q.size + border * 2;
    sb_printf(out,
              "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 %d %d\" "
              "shape-rendering=\"crispEdges\"><rect width=\"%d\" height=\"%d\" fill=\"#ffffff\"/>"
              "<path fill=\"#0f172a\" d=\"",
              dim, dim, dim, dim);
    for (int y = 0; y < q.size; y++) {
        int x = 0;
        while (x < q.size) {
            if (!qr_dark(&q, x, y)) {
                x++;
                continue;
            }
            int start = x;
            while (x < q.size && qr_dark(&q, x, y))
                x++;
            sb_printf(out, "M%d %dh%dv1h-%dz", start + border, y + border, x - start, x - start);
        }
    }
    sb_append(out, "\"/></svg>");
    free(q.buf);
    return 0;
}

int qr_print_terminal(const char *text, FILE *f)
{
    qr_t q;
    if (qr_make(text, &q) != 0)
        return -1;
    const int border = 2;
    /* nền trắng, module đen - hiển thị đúng trên cả terminal nền sáng lẫn tối */
    for (int y = -border; y < q.size + border; y += 2) {
        fputs("\033[30;107m", f);
        for (int x = -border; x < q.size + border; x++) {
            bool top = qr_dark(&q, x, y), bot = qr_dark(&q, x, y + 1);
            if (top && bot)
                fputs("\xe2\x96\x88", f); /* █ */
            else if (top)
                fputs("\xe2\x96\x80", f); /* ▀ */
            else if (bot)
                fputs("\xe2\x96\x84", f); /* ▄ */
            else
                fputc(' ', f);
        }
        fputs("\033[0m\n", f);
    }
    free(q.buf);
    return 0;
}

int qr_pbm(const char *text, int scale, sb_t *out)
{
    qr_t q;
    if (qr_make(text, &q) != 0)
        return -1;
    const int border = 4;
    int dim = (q.size + border * 2) * scale;
    sb_printf(out, "P1\n%d %d\n", dim, dim);
    for (int py = 0; py < dim; py++) {
        for (int px = 0; px < dim; px++) {
            int x = px / scale - border, y = py / scale - border;
            sb_appendc(out, qr_dark(&q, x, y) ? '1' : '0');
        }
        sb_appendc(out, '\n');
    }
    free(q.buf);
    return 0;
}
