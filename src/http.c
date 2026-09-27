/*
 * Tuấn WireGuard - máy chủ HTTP/1.1 nhúng, đa luồng
 * Tác giả: Tuandethuong
 */
#include "http.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "json.h"

#define MAX_CONNS 128
#define MAX_REQ_PER_CONN 500

static int g_active = 0;

typedef struct {
    int fd;
    struct sockaddr_storage sa;
    http_handler_t handler;
} conn_arg_t;

const char *http_status_text(int s)
{
    switch (s) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 413: return "Payload Too Large";
    case 415: return "Unsupported Media Type";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default: return "Unknown";
    }
}

static int send_all(int fd, const char *p, size_t n)
{
    while (n) {
        ssize_t k = send(fd, p, n, MSG_NOSIGNAL);
        if (k < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += k;
        n -= (size_t)k;
    }
    return 0;
}

static ssize_t recv_timeout(int fd, char *buf, size_t n, int timeout_ms)
{
    struct pollfd pfd = {fd, POLLIN, 0};
    for (;;) {
        int r = poll(&pfd, 1, timeout_ms);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return -1;
        ssize_t k = recv(fd, buf, n, 0);
        if (k < 0 && errno == EINTR)
            continue;
        return k;
    }
}

int url_decode(const char *in, char *out, size_t outsz, bool plus_space)
{
    size_t w = 0;
    for (size_t i = 0; in[i]; i++) {
        if (w + 1 >= outsz)
            return -1;
        char c = in[i];
        if (c == '%' && isxdigit((unsigned char)in[i + 1]) && isxdigit((unsigned char)in[i + 2])) {
            char hx[3] = {in[i + 1], in[i + 2], 0};
            int v = (int)strtol(hx, NULL, 16);
            if (v == 0)
                return -1;
            out[w++] = (char)v;
            i += 2;
        } else if (c == '+' && plus_space) {
            out[w++] = ' ';
        } else {
            out[w++] = c;
        }
    }
    out[w] = 0;
    return 0;
}

const char *http_header(const http_req_t *r, const char *name)
{
    for (int i = 0; i < r->nheaders; i++)
        if (strcasecmp(r->hname[i], name) == 0)
            return r->hval[i];
    return NULL;
}

bool http_query(const http_req_t *r, const char *name, char *out, size_t n)
{
    size_t nl = strlen(name);
    const char *p = r->query;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        size_t len = amp ? (size_t)(amp - p) : strlen(p);
        if (len > nl && strncmp(p, name, nl) == 0 && p[nl] == '=') {
            char raw[2048];
            size_t vl = len - nl - 1;
            if (vl >= sizeof raw)
                vl = sizeof raw - 1;
            memcpy(raw, p + nl + 1, vl);
            raw[vl] = 0;
            return url_decode(raw, out, n, true) == 0;
        }
        if (len == nl && strncmp(p, name, nl) == 0) {
            if (n)
                out[0] = 0;
            return true;
        }
        p = amp ? amp + 1 : NULL;
    }
    return false;
}

bool http_cookie(const http_req_t *r, const char *name, char *out, size_t n)
{
    const char *c = http_header(r, "Cookie");
    size_t nl = strlen(name);
    while (c && *c) {
        while (*c == ' ' || *c == ';')
            c++;
        const char *semi = strchr(c, ';');
        size_t len = semi ? (size_t)(semi - c) : strlen(c);
        if (len > nl && strncmp(c, name, nl) == 0 && c[nl] == '=') {
            size_t vl = len - nl - 1;
            if (vl >= n)
                return false;
            memcpy(out, c + nl + 1, vl);
            out[vl] = 0;
            return true;
        }
        c = semi;
    }
    return false;
}

void http_respond(http_req_t *r, int status, const char *ctype, const void *body, size_t len,
                  const char *extra)
{
    if (r->responded)
        return;
    r->responded = true;
    r->status = status;
    sb_t h;
    sb_init(&h);
    sb_printf(&h, "HTTP/1.1 %d %s\r\n", status, http_status_text(status));
    sb_append(&h, "Server: tuan-wg\r\n");
    if (ctype)
        sb_printf(&h, "Content-Type: %s\r\n", ctype);
    sb_printf(&h, "Content-Length: %zu\r\n", len);
    sb_printf(&h, "Connection: %s\r\n", r->keep_alive ? "keep-alive" : "close");
    sb_append(&h, "X-Content-Type-Options: nosniff\r\n"
                  "X-Frame-Options: DENY\r\n"
                  "Referrer-Policy: no-referrer\r\n"
                  "Cross-Origin-Opener-Policy: same-origin\r\n");
    if (!extra || !strstr(extra, "Cache-Control:"))
        sb_append(&h, "Cache-Control: no-store\r\n");
    if (extra)
        sb_append(&h, extra);
    sb_append(&h, "\r\n");
    int rc = send_all(r->fd, h.s, h.len);
    if (rc == 0 && len && strcmp(r->method, "HEAD") != 0)
        rc = send_all(r->fd, body, len);
    if (rc != 0)
        r->keep_alive = false;
    sb_free(&h);
}

void http_send_json(http_req_t *r, int status, const sb_t *json, const char *extra)
{
    http_respond(r, status, "application/json; charset=utf-8", json->s ? json->s : "{}",
                 json->s ? json->len : 2, extra);
}

void http_send_error(http_req_t *r, int status, const char *msg)
{
    sb_t b;
    sb_init(&b);
    jw_t w;
    jw_init(&w, &b);
    jw_obj(&w);
    jw_kstr(&w, "error", msg);
    jw_obj_end(&w);
    http_send_json(r, status, &b, NULL);
    sb_free(&b);
}

static void simple_reply(int fd, int status)
{
    char buf[256];
    int n = snprintf(buf, sizeof buf,
                     "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status,
                     http_status_text(status));
    send_all(fd, buf, (size_t)n);
}

static void peer_ip(const struct sockaddr_storage *sa, char *out, size_t n, bool *loop)
{
    *loop = false;
    if (sa->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &s4->sin_addr, out, (socklen_t)n);
        *loop = (ntohl(s4->sin_addr.s_addr) >> 24) == 127;
    } else if (sa->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
        if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr)) {
            struct in_addr a4;
            memcpy(&a4, &s6->sin6_addr.s6_addr[12], 4);
            inet_ntop(AF_INET, &a4, out, (socklen_t)n);
            *loop = (ntohl(a4.s_addr) >> 24) == 127;
        } else {
            inet_ntop(AF_INET6, &s6->sin6_addr, out, (socklen_t)n);
            *loop = IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr);
        }
    } else {
        str_copy(out, "?", n);
    }
}

/* Phân tích phần đầu request (đã kết thúc bằng NUL). 0 = ok, mã HTTP nếu lỗi */
static int parse_head(http_req_t *r, char *head)
{
    char *line_end = strstr(head, "\r\n");
    if (!line_end)
        return 400;
    *line_end = 0;
    char *sp1 = strchr(head, ' ');
    if (!sp1)
        return 400;
    char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2)
        return 400;
    *sp1 = 0;
    *sp2 = 0;
    if (strlen(head) >= sizeof r->method || strlen(sp1 + 1) >= sizeof r->target ||
        strlen(sp2 + 1) >= sizeof r->version)
        return 400;
    for (char *m = head; *m; m++)
        if (*m < 'A' || *m > 'Z')
            return 400;
    str_copy(r->method, head, sizeof r->method);
    str_copy(r->target, sp1 + 1, sizeof r->target);
    str_copy(r->version, sp2 + 1, sizeof r->version);
    if (strcmp(r->version, "HTTP/1.1") != 0 && strcmp(r->version, "HTTP/1.0") != 0)
        return 400;
    if (r->target[0] != '/')
        return 400;
    char *q = strchr(r->target, '?');
    char rawpath[4096];
    if (q) {
        size_t pl = (size_t)(q - r->target);
        memcpy(rawpath, r->target, pl);
        rawpath[pl] = 0;
        str_copy(r->query, q + 1, sizeof r->query);
    } else {
        str_copy(rawpath, r->target, sizeof rawpath);
        r->query[0] = 0;
    }
    if (url_decode(rawpath, r->path, sizeof r->path, false) != 0)
        return 400;

    char *p = line_end + 2;
    while (*p) {
        char *e = strstr(p, "\r\n");
        if (e)
            *e = 0;
        if (*p == ' ' || *p == '\t')
            return 400; /* không hỗ trợ gập dòng */
        char *colon = strchr(p, ':');
        if (!colon || colon == p)
            return 400;
        *colon = 0;
        char *v = colon + 1;
        while (*v == ' ' || *v == '\t')
            v++;
        size_t vl = strlen(v);
        while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t'))
            v[--vl] = 0;
        if (r->nheaders >= HTTP_MAX_HEADERS)
            return 431;
        r->hname[r->nheaders] = p;
        r->hval[r->nheaders] = v;
        r->nheaders++;
        if (!e)
            break;
        p = e + 2;
    }
    const char *conn = http_header(r, "Connection");
    if (strcmp(r->version, "HTTP/1.1") == 0)
        r->keep_alive = !(conn && strcasestr(conn, "close"));
    else
        r->keep_alive = conn && strcasestr(conn, "keep-alive");
    return 0;
}

static void apply_proxy_headers(http_req_t *r)
{
    if (!r->from_loopback)
        return;
    const char *real = http_header(r, "X-Real-IP");
    const char *xff = http_header(r, "X-Forwarded-For");
    char ip[64] = "";
    if (real && *real) {
        str_copy(ip, real, sizeof ip);
    } else if (xff && *xff) {
        const char *last = strrchr(xff, ',');
        str_copy(ip, last ? last + 1 : xff, sizeof ip);
    }
    str_trim(ip);
    struct in6_addr tmp6;
    struct in_addr tmp4;
    if (ip[0] && (inet_pton(AF_INET, ip, &tmp4) == 1 || inet_pton(AF_INET6, ip, &tmp6) == 1))
        str_copy(r->ip, ip, sizeof r->ip);
    const char *proto = http_header(r, "X-Forwarded-Proto");
    if (proto && strcasecmp(proto, "https") == 0)
        r->https = true;
}

static void *conn_main(void *arg)
{
    conn_arg_t *ca = arg;
    int fd = ca->fd;
    char ip[64];
    bool loop;
    peer_ip(&ca->sa, ip, sizeof ip, &loop);
    char *buf = xmalloc(HTTP_HEAD_MAX + 1);
    size_t have = 0;

    for (int nreq = 0; nreq < MAX_REQ_PER_CONN; nreq++) {
        http_req_t *r = xcalloc(1, sizeof *r);
        r->fd = fd;
        str_copy(r->ip, ip, sizeof r->ip);
        r->from_loopback = loop;
        size_t head_end = 0;
        int timeout = nreq == 0 ? 20000 : 15000;
        for (;;) {
            buf[have] = 0;
            char *e = have >= 4 ? memmem(buf, have, "\r\n\r\n", 4) : NULL;
            if (e) {
                head_end = (size_t)(e - buf) + 4;
                break;
            }
            if (have >= HTTP_HEAD_MAX) {
                simple_reply(fd, 431);
                free(r);
                goto done;
            }
            ssize_t k = recv_timeout(fd, buf + have, HTTP_HEAD_MAX - have, timeout);
            if (k <= 0) {
                free(r);
                goto done;
            }
            have += (size_t)k;
        }
        char save = buf[head_end - 2];
        buf[head_end - 2] = 0;
        int perr = parse_head(r, buf);
        buf[head_end - 2] = save;
        if (perr) {
            simple_reply(fd, perr);
            free(r);
            goto done;
        }
        apply_proxy_headers(r);
        if (http_header(r, "Transfer-Encoding")) {
            simple_reply(fd, 501);
            free(r);
            goto done;
        }
        size_t consumed = head_end;
        const char *cl = http_header(r, "Content-Length");
        if (cl) {
            char *endp;
            errno = 0;
            unsigned long long len = strtoull(cl, &endp, 10);
            if (errno || *endp || !isdigit((unsigned char)cl[0])) {
                simple_reply(fd, 400);
                free(r);
                goto done;
            }
            if (len > HTTP_BODY_MAX) {
                simple_reply(fd, 413);
                free(r);
                goto done;
            }
            r->body = xmalloc((size_t)len + 1);
            size_t already = have - head_end;
            if (already > len)
                already = (size_t)len;
            memcpy(r->body, buf + head_end, already);
            size_t got = already;
            consumed += already;
            while (got < len) {
                ssize_t k = recv_timeout(fd, r->body + got, (size_t)len - got, 30000);
                if (k <= 0) {
                    free(r->body);
                    free(r);
                    goto done;
                }
                got += (size_t)k;
            }
            r->body[len] = 0;
            r->body_len = (size_t)len;
        } else if (!strcmp(r->method, "POST") || !strcmp(r->method, "PUT")) {
            r->body = xstrdup("");
            r->body_len = 0;
        }

        ca->handler(r);
        if (!r->responded)
            http_send_error(r, 500, "Không có phản hồi");
        bool keep = r->keep_alive;
        free(r->body);
        free(r);

        memmove(buf, buf + consumed, have - consumed);
        have -= consumed;
        if (!keep)
            break;
    }
done:
    shutdown(fd, SHUT_RDWR);
    close(fd);
    free(buf);
    free(ca);
    __atomic_sub_fetch(&g_active, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

int http_serve(const char *addr, int port, http_handler_t handler, volatile int *stop, int wake_fd)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    int gai = getaddrinfo(addr && *addr ? addr : NULL, portstr, &hints, &res);
    if (gai != 0 || !res) {
        LOGE("Địa chỉ lắng nghe không hợp lệ '%s': %s", addr, gai_strerror(gai));
        return -1;
    }
    int lfd = socket(res->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    int one = 1, zero = 0;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (res->ai_family == AF_INET6)
        setsockopt(lfd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
    if (bind(lfd, res->ai_addr, res->ai_addrlen) != 0 || listen(lfd, 128) != 0) {
        int e = errno;
        LOGE("Không mở được cổng web %s:%d: %s", addr, port, strerror(e));
        close(lfd);
        freeaddrinfo(res);
        errno = e;
        return -1;
    }
    freeaddrinfo(res);
    LOGI("Giao diện web đang lắng nghe tại %s:%d", addr, port);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 512 * 1024);

    while (!*stop) {
        struct pollfd pfd[2] = {{lfd, POLLIN, 0}, {wake_fd, POLLIN, 0}};
        int pr = poll(pfd, wake_fd >= 0 ? 2 : 1, 1000);
        if (pr < 0 && errno != EINTR)
            break;
        if (*stop)
            break;
        if (pr <= 0)
            continue;
        if (wake_fd >= 0 && (pfd[1].revents & POLLIN)) {
            char tmp[64];
            ssize_t k = read(wake_fd, tmp, sizeof tmp);
            (void)k;
            continue;
        }
        if (!(pfd[0].revents & POLLIN))
            continue;
        conn_arg_t *ca = xcalloc(1, sizeof *ca);
        socklen_t sl = sizeof ca->sa;
        int cfd = accept4(lfd, (struct sockaddr *)&ca->sa, &sl, SOCK_CLOEXEC);
        if (cfd < 0) {
            free(ca);
            if (errno == EMFILE || errno == ENFILE)
                sleep_ms(100);
            continue;
        }
        if (__atomic_load_n(&g_active, __ATOMIC_SEQ_CST) >= MAX_CONNS) {
            simple_reply(cfd, 503);
            close(cfd);
            free(ca);
            continue;
        }
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        struct timeval tv = {30, 0};
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        ca->fd = cfd;
        ca->handler = handler;
        __atomic_add_fetch(&g_active, 1, __ATOMIC_SEQ_CST);
        pthread_t th;
        if (pthread_create(&th, &attr, conn_main, ca) != 0) {
            __atomic_sub_fetch(&g_active, 1, __ATOMIC_SEQ_CST);
            simple_reply(cfd, 503);
            close(cfd);
            free(ca);
        }
    }
    pthread_attr_destroy(&attr);
    close(lfd);
    /* chờ các kết nối đang xử lý kết thúc (tối đa 3 giây) */
    for (int i = 0; i < 30 && __atomic_load_n(&g_active, __ATOMIC_SEQ_CST) > 0; i++)
        sleep_ms(100);
    return 0;
}
