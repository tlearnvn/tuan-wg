/*
 * Tuấn WireGuard - máy chủ HTTP/1.1 nhúng, đa luồng
 * Tác giả: Tuandethuong
 */
#ifndef TWG_HTTP_H
#define TWG_HTTP_H

#include <stdbool.h>
#include <stddef.h>

#include "util.h"

#define HTTP_MAX_HEADERS 64
#define HTTP_HEAD_MAX (32 * 1024)
#define HTTP_BODY_MAX (16 * 1024 * 1024)

typedef struct {
    int fd;
    char ip[64];
    bool from_loopback;
    char method[12];
    char target[4096];
    char path[4096];   /* đã giải mã %XX, không gồm query */
    char query[4096];
    char version[12];
    char *hname[HTTP_MAX_HEADERS];
    char *hval[HTTP_MAX_HEADERS];
    int nheaders;
    char *body;
    size_t body_len;
    bool keep_alive;
    bool responded;
    int status;
    bool https; /* sau reverse proxy có X-Forwarded-Proto: https */
} http_req_t;

typedef void (*http_handler_t)(http_req_t *r);

/* Chạy vòng lặp accept cho tới khi *stop != 0. wake_fd: pipe để đánh thức. */
int http_serve(const char *addr, int port, http_handler_t handler, volatile int *stop, int wake_fd);

const char *http_header(const http_req_t *r, const char *name);
bool http_query(const http_req_t *r, const char *name, char *out, size_t n);
bool http_cookie(const http_req_t *r, const char *name, char *out, size_t n);

void http_respond(http_req_t *r, int status, const char *ctype, const void *body, size_t len,
                  const char *extra_headers);
void http_send_json(http_req_t *r, int status, const sb_t *json, const char *extra_headers);
void http_send_error(http_req_t *r, int status, const char *msg);
const char *http_status_text(int status);
int url_decode(const char *in, char *out, size_t outsz, bool plus_space);

#endif
