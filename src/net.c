/*
 * Tuấn WireGuard - tiện ích mạng
 * Tác giả: Tuandethuong
 */
#include "net.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util.h"

int ip4_parse(const char *s, uint32_t *out)
{
    struct in_addr a;
    if (!s || inet_pton(AF_INET, s, &a) != 1)
        return -1;
    *out = ntohl(a.s_addr);
    return 0;
}

void ip4_format(uint32_t a, char out[16])
{
    struct in_addr in;
    in.s_addr = htonl(a);
    inet_ntop(AF_INET, &in, out, 16);
}

static int split_prefix(const char *s, char *ip, size_t ipsz, int *prefix, int maxp)
{
    const char *slash = strchr(s, '/');
    size_t n = slash ? (size_t)(slash - s) : strlen(s);
    if (n == 0 || n >= ipsz)
        return -1;
    memcpy(ip, s, n);
    ip[n] = 0;
    if (slash) {
        if (!str_is_digits(slash + 1) || strlen(slash + 1) > 3)
            return -1;
        int p = atoi(slash + 1);
        if (p < 0 || p > maxp)
            return -1;
        *prefix = p;
    } else {
        *prefix = maxp;
    }
    return 0;
}

int cidr4_parse(const char *s, uint32_t *addr, int *prefix)
{
    char ip[64];
    if (split_prefix(s, ip, sizeof ip, prefix, 32) != 0)
        return -1;
    return ip4_parse(ip, addr);
}

int ip6_parse(const char *s, uint8_t out[16])
{
    struct in6_addr a;
    if (!s || inet_pton(AF_INET6, s, &a) != 1)
        return -1;
    memcpy(out, &a, 16);
    return 0;
}

void ip6_format(const uint8_t a[16], char out[46])
{
    inet_ntop(AF_INET6, a, out, 46);
}

int cidr6_parse(const char *s, uint8_t addr[16], int *prefix)
{
    char ip[64];
    if (split_prefix(s, ip, sizeof ip, prefix, 128) != 0)
        return -1;
    return ip6_parse(ip, addr);
}

/* tách danh sách phân cách bởi dấu phẩy, gọi cb cho từng phần tử đã trim */
static int list_normalize(const char *s, char *out, size_t outsz, int (*valid)(const char *))
{
    char buf[2048];
    str_copy(buf, s ? s : "", sizeof buf);
    sb_t b;
    sb_init(&b);
    int count = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        str_trim(tok);
        if (!*tok)
            continue;
        if (!valid(tok) || ++count > 64) {
            sb_free(&b);
            return -1;
        }
        if (b.len)
            sb_append(&b, ", ");
        sb_append(&b, tok);
    }
    if (b.len + 1 > outsz) {
        sb_free(&b);
        return -1;
    }
    str_copy(out, b.s ? b.s : "", outsz);
    sb_free(&b);
    return 0;
}

static int valid_cidr_item(const char *t)
{
    uint32_t a4;
    uint8_t a6[16];
    int p;
    return cidr4_parse(t, &a4, &p) == 0 || cidr6_parse(t, a6, &p) == 0;
}

int cidr_list_normalize(const char *s, char *out, size_t outsz)
{
    return list_normalize(s, out, outsz, valid_cidr_item);
}

static int hostname_valid(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 253)
        return 0;
    size_t label = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '.') {
            if (label == 0)
                return 0;
            label = 0;
            continue;
        }
        if (!(isalnum((unsigned char)c) || c == '-' || c == '_'))
            return 0;
        if (++label > 63)
            return 0;
    }
    return 1;
}

static int valid_dns_item(const char *t)
{
    uint32_t a4;
    uint8_t a6[16];
    return ip4_parse(t, &a4) == 0 || ip6_parse(t, a6) == 0 || hostname_valid(t);
}

int dns_list_normalize(const char *s, char *out, size_t outsz)
{
    return list_normalize(s, out, outsz, valid_dns_item);
}

int host_valid(const char *s)
{
    if (!s || !*s)
        return 0;
    uint32_t a4;
    uint8_t a6[16];
    char tmp[300];
    str_copy(tmp, s, sizeof tmp);
    char *host = tmp;
    /* cho phép "host:port" và "[ipv6]:port" */
    if (host[0] == '[') {
        char *end = strchr(host, ']');
        if (!end)
            return 0;
        *end = 0;
        const char *rest = end + 1;
        if (*rest) {
            if (*rest != ':' || !str_is_digits(rest + 1) || atoi(rest + 1) < 1 ||
                atoi(rest + 1) > 65535)
                return 0;
        }
        return ip6_parse(host + 1, a6) == 0;
    }
    if (ip6_parse(host, a6) == 0)
        return 1;
    char *colon = strrchr(host, ':');
    if (colon) {
        if (!str_is_digits(colon + 1) || atoi(colon + 1) < 1 || atoi(colon + 1) > 65535)
            return 0;
        *colon = 0;
    }
    return ip4_parse(host, &a4) == 0 || hostname_valid(host);
}

int iface_name_valid(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n == 0 || n > 15)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!(isalnum((unsigned char)c) || c == '_' || c == '=' || c == '+' || c == '.' || c == '-'))
            return 0;
    }
    return 1;
}

int net_default_iface(char *out, size_t n)
{
    FILE *f = fopen("/proc/net/route", "re");
    if (!f)
        return -1;
    char line[512];
    int best_metric = 1 << 30;
    int found = -1;
    if (!fgets(line, sizeof line, f)) {
        fclose(f);
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        char iface[64];
        unsigned long dest, gw, mask;
        int flags, refcnt, use, metric;
        if (sscanf(line, "%63s %lx %lx %x %d %d %d %lx", iface, &dest, &gw, &flags, &refcnt, &use,
                   &metric, &mask) != 8)
            continue;
        if (dest == 0 && mask == 0 && (flags & 1) && metric < best_metric) {
            best_metric = metric;
            str_copy(out, iface, n);
            found = 0;
        }
    }
    fclose(f);
    return found;
}

int net_local_ip(char *out, size_t n)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &sa.sin_addr);
    int r = -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0) {
        struct sockaddr_in me;
        socklen_t len = sizeof me;
        if (getsockname(fd, (struct sockaddr *)&me, &len) == 0) {
            inet_ntop(AF_INET, &me.sin_addr, out, (socklen_t)n);
            r = 0;
        }
    }
    close(fd);
    return r;
}

static int http_get_body(const char *host, const char *path, char *out, size_t n, int timeout_ms)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "80", &hints, &res) != 0 || !res)
        return -1;
    int fd = socket(res->ai_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    int r = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (r != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    struct pollfd pfd = {fd, POLLOUT, 0};
    if (poll(&pfd, 1, timeout_ms) <= 0) {
        close(fd);
        return -1;
    }
    int soerr = 0;
    socklen_t sl = sizeof soerr;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
    if (soerr) {
        close(fd);
        return -1;
    }
    char req[512];
    int rl = snprintf(req, sizeof req,
                      "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: tuan-wg\r\nAccept: text/plain\r\n\r\n",
                      path, host);
    if (send(fd, req, (size_t)rl, MSG_NOSIGNAL) != rl) {
        close(fd);
        return -1;
    }
    char buf[4096];
    size_t got = 0;
    double deadline = now_mono() + timeout_ms / 1000.0;
    while (got < sizeof buf - 1) {
        int remain = (int)((deadline - now_mono()) * 1000);
        if (remain <= 0)
            break;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, remain) <= 0)
            break;
        ssize_t k = recv(fd, buf + got, sizeof buf - 1 - got, 0);
        if (k <= 0)
            break;
        got += (size_t)k;
    }
    close(fd);
    buf[got] = 0;
    if (strncmp(buf, "HTTP/1.", 7) != 0 || strncmp(buf + 9, "200", 3) != 0)
        return -1;
    char *body = strstr(buf, "\r\n\r\n");
    if (!body)
        return -1;
    body += 4;
    str_trim(body);
    str_copy(out, body, n);
    return 0;
}

int net_public_ip(char *out, size_t n, int timeout_ms)
{
    static const char *svc[][2] = {
        {"api.ipify.org", "/"}, {"ipv4.icanhazip.com", "/"}, {"ifconfig.me", "/ip"}};
    for (size_t i = 0; i < ARRAY_LEN(svc); i++) {
        char body[128];
        uint32_t a;
        if (http_get_body(svc[i][0], svc[i][1], body, sizeof body, timeout_ms) == 0 &&
            ip4_parse(body, &a) == 0) {
            str_copy(out, body, n);
            return 0;
        }
    }
    return -1;
}

int net_iface_exists(const char *name)
{
    if (!iface_name_valid(name))
        return 0;
    char path[128];
    snprintf(path, sizeof path, "/sys/class/net/%s", name);
    return file_exists(path);
}

static uint64_t read_u64_file(const char *path)
{
    char *s = file_read(path, NULL);
    if (!s)
        return 0;
    uint64_t v = strtoull(s, NULL, 10);
    free(s);
    return v;
}

int net_iface_stats(const char *name, uint64_t *rx, uint64_t *tx)
{
    if (!net_iface_exists(name))
        return -1;
    char path[160];
    snprintf(path, sizeof path, "/sys/class/net/%s/statistics/rx_bytes", name);
    *rx = read_u64_file(path);
    snprintf(path, sizeof path, "/sys/class/net/%s/statistics/tx_bytes", name);
    *tx = read_u64_file(path);
    return 0;
}

int net_iface_ipv4(const char *name, char *out, size_t n)
{
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0)
        return -1;
    int r = -1;
    for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET || strcmp(p->ifa_name, name) != 0)
            continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
        inet_ntop(AF_INET, &sin->sin_addr, out, (socklen_t)n);
        r = 0;
        break;
    }
    freeifaddrs(ifa);
    return r;
}
