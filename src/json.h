/*
 * Tuấn WireGuard - JSON parser/writer tối giản
 * Tác giả: Tuandethuong
 */
#ifndef TWG_JSON_H
#define TWG_JSON_H

#include <stdint.h>

#include "util.h"

typedef enum { J_NULL = 0, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype_t;

typedef struct json json_t;
struct json {
    jtype_t type;
    int b;
    double n;
    char *s;
    int count;       /* số phần tử (mảng/đối tượng) */
    char **keys;     /* chỉ với đối tượng */
    json_t **items;
};

json_t *json_parse(const char *text, size_t len, char *err, size_t errsz);
void json_free(json_t *j);

json_t *json_get(const json_t *obj, const char *key);
bool json_has(const json_t *obj, const char *key);
const char *json_str(const json_t *obj, const char *key, const char *def);
double json_num(const json_t *obj, const char *key, double def);
int64_t json_int(const json_t *obj, const char *key, int64_t def);
int json_bool(const json_t *obj, const char *key, int def);
int json_len(const json_t *arr);
json_t *json_at(const json_t *arr, int i);

/* ---------- writer ---------- */
typedef struct {
    sb_t *sb;
    int depth;
    int after_key;
    unsigned char comma[64];
} jw_t;

void jw_init(jw_t *w, sb_t *sb);
void jw_obj(jw_t *w);
void jw_obj_end(jw_t *w);
void jw_arr(jw_t *w);
void jw_arr_end(jw_t *w);
void jw_key(jw_t *w, const char *k);
void jw_str(jw_t *w, const char *s);
void jw_int(jw_t *w, int64_t v);
void jw_uint(jw_t *w, uint64_t v);
void jw_num(jw_t *w, double v);
void jw_bool(jw_t *w, int v);
void jw_null(jw_t *w);
void jw_raw(jw_t *w, const char *raw);

void jw_kstr(jw_t *w, const char *k, const char *v);
void jw_kint(jw_t *w, const char *k, int64_t v);
void jw_kuint(jw_t *w, const char *k, uint64_t v);
void jw_knum(jw_t *w, const char *k, double v);
void jw_kbool(jw_t *w, const char *k, int v);

void sb_json_str(sb_t *sb, const char *s);

#endif
