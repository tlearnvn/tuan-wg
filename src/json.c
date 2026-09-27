/*
 * Tuấn WireGuard - JSON parser/writer tối giản
 * Tác giả: Tuandethuong
 */
#include "json.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define JSON_MAX_DEPTH 48

typedef struct {
    const char *p, *end;
    int depth;
    char *err;
    size_t errsz;
    int failed;
} jp_t;

static void jp_fail(jp_t *p, const char *msg)
{
    if (!p->failed && p->err && p->errsz)
        str_copy(p->err, msg, p->errsz);
    p->failed = 1;
}

static void skip_ws(jp_t *p)
{
    while (p->p < p->end && (*p->p == ' ' || *p->p == '\t' || *p->p == '\n' || *p->p == '\r'))
        p->p++;
}

static json_t *jnew(jtype_t t)
{
    json_t *j = xcalloc(1, sizeof *j);
    j->type = t;
    return j;
}

void json_free(json_t *j)
{
    if (!j)
        return;
    free(j->s);
    for (int i = 0; i < j->count; i++) {
        if (j->keys)
            free(j->keys[i]);
        json_free(j->items[i]);
    }
    free(j->keys);
    free(j->items);
    free(j);
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int parse_hex4(jp_t *p, uint32_t *out)
{
    if (p->end - p->p < 4)
        return -1;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hexval(p->p[i]);
        if (h < 0)
            return -1;
        v = (v << 4) | (uint32_t)h;
    }
    p->p += 4;
    *out = v;
    return 0;
}

static void utf8_put(sb_t *b, uint32_t cp)
{
    if (cp < 0x80) {
        sb_appendc(b, (char)cp);
    } else if (cp < 0x800) {
        sb_appendc(b, (char)(0xC0 | (cp >> 6)));
        sb_appendc(b, (char)(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        sb_appendc(b, (char)(0xE0 | (cp >> 12)));
        sb_appendc(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
        sb_appendc(b, (char)(0x80 | (cp & 0x3F)));
    } else {
        sb_appendc(b, (char)(0xF0 | (cp >> 18)));
        sb_appendc(b, (char)(0x80 | ((cp >> 12) & 0x3F)));
        sb_appendc(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
        sb_appendc(b, (char)(0x80 | (cp & 0x3F)));
    }
}

static char *parse_string_raw(jp_t *p)
{
    p->p++; /* bỏ dấu " */
    sb_t b;
    sb_init(&b);
    sb_reserve(&b, 16);
    while (p->p < p->end) {
        char c = *p->p++;
        if (c == '"')
            return sb_steal(&b);
        if ((unsigned char)c < 0x20) {
            jp_fail(p, "ký tự điều khiển trong chuỗi");
            break;
        }
        if (c != '\\') {
            sb_appendc(&b, c);
            continue;
        }
        if (p->p >= p->end)
            break;
        char e = *p->p++;
        switch (e) {
        case '"': sb_appendc(&b, '"'); break;
        case '\\': sb_appendc(&b, '\\'); break;
        case '/': sb_appendc(&b, '/'); break;
        case 'b': sb_appendc(&b, '\b'); break;
        case 'f': sb_appendc(&b, '\f'); break;
        case 'n': sb_appendc(&b, '\n'); break;
        case 'r': sb_appendc(&b, '\r'); break;
        case 't': sb_appendc(&b, '\t'); break;
        case 'u': {
            uint32_t cp;
            if (parse_hex4(p, &cp) != 0) {
                jp_fail(p, "\\u không hợp lệ");
                goto fail;
            }
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                uint32_t lo;
                if (p->end - p->p >= 6 && p->p[0] == '\\' && p->p[1] == 'u') {
                    p->p += 2;
                    if (parse_hex4(p, &lo) != 0 || lo < 0xDC00 || lo > 0xDFFF) {
                        jp_fail(p, "surrogate không hợp lệ");
                        goto fail;
                    }
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else {
                    cp = 0xFFFD;
                }
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                cp = 0xFFFD;
            }
            if (cp == 0)
                cp = 0xFFFD; /* không cho phép NUL trong chuỗi C */
            utf8_put(&b, cp);
            break;
        }
        default:
            jp_fail(p, "escape không hợp lệ");
            goto fail;
        }
    }
    jp_fail(p, "chuỗi chưa đóng");
fail:
    sb_free(&b);
    return NULL;
}

static json_t *parse_value(jp_t *p);

static json_t *parse_array(jp_t *p)
{
    json_t *a = jnew(J_ARR);
    int cap = 0;
    p->p++;
    skip_ws(p);
    if (p->p < p->end && *p->p == ']') {
        p->p++;
        return a;
    }
    for (;;) {
        json_t *v = parse_value(p);
        if (!v) {
            json_free(a);
            return NULL;
        }
        if (a->count == cap) {
            cap = cap ? cap * 2 : 8;
            a->items = xrealloc(a->items, (size_t)cap * sizeof(json_t *));
        }
        a->items[a->count++] = v;
        skip_ws(p);
        if (p->p < p->end && *p->p == ',') {
            p->p++;
            continue;
        }
        if (p->p < p->end && *p->p == ']') {
            p->p++;
            return a;
        }
        jp_fail(p, "thiếu ',' hoặc ']'");
        json_free(a);
        return NULL;
    }
}

static json_t *parse_object(jp_t *p)
{
    json_t *o = jnew(J_OBJ);
    int cap = 0;
    p->p++;
    skip_ws(p);
    if (p->p < p->end && *p->p == '}') {
        p->p++;
        return o;
    }
    for (;;) {
        skip_ws(p);
        if (p->p >= p->end || *p->p != '"') {
            jp_fail(p, "khóa phải là chuỗi");
            json_free(o);
            return NULL;
        }
        char *key = parse_string_raw(p);
        if (!key) {
            json_free(o);
            return NULL;
        }
        skip_ws(p);
        if (p->p >= p->end || *p->p != ':') {
            free(key);
            jp_fail(p, "thiếu ':'");
            json_free(o);
            return NULL;
        }
        p->p++;
        json_t *v = parse_value(p);
        if (!v) {
            free(key);
            json_free(o);
            return NULL;
        }
        if (o->count == cap) {
            cap = cap ? cap * 2 : 8;
            o->items = xrealloc(o->items, (size_t)cap * sizeof(json_t *));
            o->keys = xrealloc(o->keys, (size_t)cap * sizeof(char *));
        }
        o->keys[o->count] = key;
        o->items[o->count] = v;
        o->count++;
        skip_ws(p);
        if (p->p < p->end && *p->p == ',') {
            p->p++;
            continue;
        }
        if (p->p < p->end && *p->p == '}') {
            p->p++;
            return o;
        }
        jp_fail(p, "thiếu ',' hoặc '}'");
        json_free(o);
        return NULL;
    }
}

static json_t *parse_value(jp_t *p)
{
    skip_ws(p);
    if (p->p >= p->end) {
        jp_fail(p, "hết dữ liệu");
        return NULL;
    }
    if (++p->depth > JSON_MAX_DEPTH) {
        jp_fail(p, "lồng quá sâu");
        return NULL;
    }
    json_t *r = NULL;
    char c = *p->p;
    if (c == '{') {
        r = parse_object(p);
    } else if (c == '[') {
        r = parse_array(p);
    } else if (c == '"') {
        char *s = parse_string_raw(p);
        if (s) {
            r = jnew(J_STR);
            r->s = s;
        }
    } else if (c == 't' && p->end - p->p >= 4 && memcmp(p->p, "true", 4) == 0) {
        p->p += 4;
        r = jnew(J_BOOL);
        r->b = 1;
    } else if (c == 'f' && p->end - p->p >= 5 && memcmp(p->p, "false", 5) == 0) {
        p->p += 5;
        r = jnew(J_BOOL);
    } else if (c == 'n' && p->end - p->p >= 4 && memcmp(p->p, "null", 4) == 0) {
        p->p += 4;
        r = jnew(J_NULL);
    } else if (c == '-' || (c >= '0' && c <= '9')) {
        char buf[64];
        size_t n = 0;
        while (p->p < p->end && n < sizeof buf - 1 &&
               (strchr("0123456789+-.eE", *p->p) != NULL)) {
            buf[n++] = *p->p++;
        }
        buf[n] = 0;
        char *end;
        double v = strtod(buf, &end);
        if (end == buf || *end) {
            jp_fail(p, "số không hợp lệ");
        } else {
            r = jnew(J_NUM);
            r->n = v;
        }
    } else {
        jp_fail(p, "giá trị không hợp lệ");
    }
    p->depth--;
    return r;
}

json_t *json_parse(const char *text, size_t len, char *err, size_t errsz)
{
    jp_t p = {text, text + len, 0, err, errsz, 0};
    if (err && errsz)
        err[0] = 0;
    /* bỏ BOM UTF-8 nếu có */
    if (len >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB &&
        (unsigned char)text[2] == 0xBF)
        p.p += 3;
    json_t *v = parse_value(&p);
    if (!v)
        return NULL;
    skip_ws(&p);
    if (p.p != p.end) {
        jp_fail(&p, "dữ liệu thừa sau JSON");
        json_free(v);
        return NULL;
    }
    return v;
}

json_t *json_get(const json_t *obj, const char *key)
{
    if (!obj || obj->type != J_OBJ)
        return NULL;
    for (int i = obj->count - 1; i >= 0; i--)
        if (strcmp(obj->keys[i], key) == 0)
            return obj->items[i];
    return NULL;
}

bool json_has(const json_t *obj, const char *key)
{
    return json_get(obj, key) != NULL;
}

const char *json_str(const json_t *obj, const char *key, const char *def)
{
    json_t *v = json_get(obj, key);
    return (v && v->type == J_STR) ? v->s : def;
}

double json_num(const json_t *obj, const char *key, double def)
{
    json_t *v = json_get(obj, key);
    if (!v)
        return def;
    if (v->type == J_NUM)
        return v->n;
    if (v->type == J_STR && v->s[0]) {
        char *end;
        double d = strtod(v->s, &end);
        if (!*end)
            return d;
    }
    return def;
}

int64_t json_int(const json_t *obj, const char *key, int64_t def)
{
    double d = json_num(obj, key, (double)def);
    if (isnan(d))
        return def;
    if (d > 9.2e18)
        return INT64_MAX;
    if (d < -9.2e18)
        return INT64_MIN;
    return (int64_t)d;
}

int json_bool(const json_t *obj, const char *key, int def)
{
    json_t *v = json_get(obj, key);
    if (!v)
        return def;
    if (v->type == J_BOOL)
        return v->b;
    if (v->type == J_NUM)
        return v->n != 0;
    if (v->type == J_STR)
        return str_eq(v->s, "true") || str_eq(v->s, "1") || str_eq(v->s, "on");
    return def;
}

int json_len(const json_t *arr)
{
    return (arr && (arr->type == J_ARR || arr->type == J_OBJ)) ? arr->count : 0;
}

json_t *json_at(const json_t *arr, int i)
{
    if (!arr || (arr->type != J_ARR && arr->type != J_OBJ) || i < 0 || i >= arr->count)
        return NULL;
    return arr->items[i];
}

/* ================= writer ================= */

void sb_json_str(sb_t *sb, const char *s)
{
    sb_appendc(sb, '"');
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            unsigned char c = *p;
            switch (c) {
            case '"': sb_append(sb, "\\\""); break;
            case '\\': sb_append(sb, "\\\\"); break;
            case '\n': sb_append(sb, "\\n"); break;
            case '\r': sb_append(sb, "\\r"); break;
            case '\t': sb_append(sb, "\\t"); break;
            case '<': sb_append(sb, "\\u003c"); break;
            default:
                if (c < 0x20 || c == 0x7f)
                    sb_printf(sb, "\\u%04x", c);
                else
                    sb_appendc(sb, (char)c);
            }
        }
    }
    sb_appendc(sb, '"');
}

void jw_init(jw_t *w, sb_t *sb)
{
    memset(w, 0, sizeof *w);
    w->sb = sb;
}

static void jw_pre(jw_t *w)
{
    if (w->after_key) {
        w->after_key = 0;
        return;
    }
    if (w->comma[w->depth])
        sb_appendc(w->sb, ',');
    w->comma[w->depth] = 1;
}

void jw_obj(jw_t *w)
{
    jw_pre(w);
    sb_appendc(w->sb, '{');
    if (w->depth < 63)
        w->depth++;
    w->comma[w->depth] = 0;
}

void jw_obj_end(jw_t *w)
{
    if (w->depth > 0)
        w->depth--;
    sb_appendc(w->sb, '}');
}

void jw_arr(jw_t *w)
{
    jw_pre(w);
    sb_appendc(w->sb, '[');
    if (w->depth < 63)
        w->depth++;
    w->comma[w->depth] = 0;
}

void jw_arr_end(jw_t *w)
{
    if (w->depth > 0)
        w->depth--;
    sb_appendc(w->sb, ']');
}

void jw_key(jw_t *w, const char *k)
{
    if (w->comma[w->depth])
        sb_appendc(w->sb, ',');
    w->comma[w->depth] = 1;
    sb_json_str(w->sb, k);
    sb_appendc(w->sb, ':');
    w->after_key = 1;
}

void jw_str(jw_t *w, const char *s)
{
    jw_pre(w);
    sb_json_str(w->sb, s);
}

void jw_int(jw_t *w, int64_t v)
{
    jw_pre(w);
    sb_printf(w->sb, "%lld", (long long)v);
}

void jw_uint(jw_t *w, uint64_t v)
{
    jw_pre(w);
    sb_printf(w->sb, "%llu", (unsigned long long)v);
}

void jw_num(jw_t *w, double v)
{
    jw_pre(w);
    if (isnan(v) || isinf(v))
        sb_append(w->sb, "null");
    else if (v == floor(v) && fabs(v) < 1e15)
        sb_printf(w->sb, "%.0f", v);
    else
        sb_printf(w->sb, "%.10g", v);
}

void jw_bool(jw_t *w, int v)
{
    jw_pre(w);
    sb_append(w->sb, v ? "true" : "false");
}

void jw_null(jw_t *w)
{
    jw_pre(w);
    sb_append(w->sb, "null");
}

void jw_raw(jw_t *w, const char *raw)
{
    jw_pre(w);
    sb_append(w->sb, raw);
}

void jw_kstr(jw_t *w, const char *k, const char *v)
{
    jw_key(w, k);
    jw_str(w, v);
}

void jw_kint(jw_t *w, const char *k, int64_t v)
{
    jw_key(w, k);
    jw_int(w, v);
}

void jw_kuint(jw_t *w, const char *k, uint64_t v)
{
    jw_key(w, k);
    jw_uint(w, v);
}

void jw_knum(jw_t *w, const char *k, double v)
{
    jw_key(w, k);
    jw_num(w, v);
}

void jw_kbool(jw_t *w, const char *k, int v)
{
    jw_key(w, k);
    jw_bool(w, v);
}
