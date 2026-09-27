/*
 * Tuấn WireGuard - tiện ích dùng chung
 * Tác giả: Tuandethuong
 */
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int g_log_level = LOG_INFO;

/* ================= memory ================= */

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) {
        fprintf(stderr, "out of memory\n");
        abort();
    }
    return p;
}

void *xcalloc(size_t n, size_t m)
{
    void *p = calloc(n ? n : 1, m ? m : 1);
    if (!p) {
        fprintf(stderr, "out of memory\n");
        abort();
    }
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fprintf(stderr, "out of memory\n");
        abort();
    }
    return q;
}

char *xstrdup(const char *s)
{
    return xstrndup(s ? s : "", s ? strlen(s) : 0);
}

char *xstrndup(const char *s, size_t n)
{
    char *p = xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

/* ================= string builder ================= */

void sb_init(sb_t *b)
{
    b->s = NULL;
    b->len = b->cap = 0;
}

void sb_free(sb_t *b)
{
    free(b->s);
    sb_init(b);
}

void sb_clear(sb_t *b)
{
    b->len = 0;
    if (b->s)
        b->s[0] = 0;
}

void sb_reserve(sb_t *b, size_t extra)
{
    size_t need = b->len + extra + 1;
    if (need <= b->cap)
        return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < need)
        cap *= 2;
    b->s = xrealloc(b->s, cap);
    b->cap = cap;
    b->s[b->len] = 0;
}

void sb_appendn(sb_t *b, const char *s, size_t n)
{
    sb_reserve(b, n);
    memcpy(b->s + b->len, s, n);
    b->len += n;
    b->s[b->len] = 0;
}

void sb_append(sb_t *b, const char *s)
{
    sb_appendn(b, s, strlen(s));
}

void sb_appendc(sb_t *b, char c)
{
    sb_reserve(b, 1);
    b->s[b->len++] = c;
    b->s[b->len] = 0;
}

void sb_vprintf(sb_t *b, const char *fmt, va_list ap)
{
    if (!fmt)
        return;
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap2);
    va_end(ap2);
    if (n <= 0)
        return;
    sb_reserve(b, (size_t)n);
    vsnprintf(b->s + b->len, (size_t)n + 1, fmt, ap);
    b->len += (size_t)n;
}

void sb_printf(sb_t *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    sb_vprintf(b, fmt, ap);
    va_end(ap);
}

char *sb_steal(sb_t *b)
{
    char *s = b->s ? b->s : xstrdup("");
    sb_init(b);
    return s;
}

void sb_html_escape(sb_t *b, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '&': sb_append(b, "&amp;"); break;
        case '<': sb_append(b, "&lt;"); break;
        case '>': sb_append(b, "&gt;"); break;
        case '"': sb_append(b, "&quot;"); break;
        case '\'': sb_append(b, "&#39;"); break;
        default: sb_appendc(b, *s);
        }
    }
}

/* ================= logging ================= */

void log_msg(int level, const char *fmt, ...)
{
    if (level < g_log_level)
        return;
    static const char *names[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    static const int prio[] = {7, 6, 4, 3};
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    if (getenv("JOURNAL_STREAM")) {
        /* systemd-journald tự thêm thời gian; dùng tiền tố mức độ syslog */
        fprintf(stderr, "<%d>%s\n", prio[level], msg);
    } else {
        char ts[32];
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);
        strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
        fprintf(stderr, "%s [%s] %s\n", ts, names[level], msg);
    }
}

/* ================= strings ================= */

size_t str_copy(char *dst, const char *src, size_t size)
{
    size_t n = src ? strlen(src) : 0;
    if (size == 0)
        return n;
    size_t c = n < size - 1 ? n : size - 1;
    if (c)
        memcpy(dst, src, c);
    dst[c] = 0;
    return n;
}

void str_trim(char *s)
{
    if (!s)
        return;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        s[--n] = 0;
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i]))
        i++;
    if (i)
        memmove(s, s + i, n - i + 1);
}

bool str_starts(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

bool str_ends(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && memcmp(s + a - b, suffix, b) == 0;
}

bool str_eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

bool str_ieq(const char *a, const char *b)
{
    return a && b && strcasecmp(a, b) == 0;
}

void str_strip_ctrl(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++) {
        unsigned char c = (unsigned char)*r;
        if (c < 0x20 || c == 0x7f)
            continue;
        *w++ = *r;
    }
    *w = 0;
}

/* Trả về độ dài chuỗi UTF-8 hợp lệ tại p, 0 nếu không hợp lệ */
static int utf8_seq(const unsigned char *p, uint32_t *cp)
{
    unsigned char c = p[0];
    if (c < 0x80) {
        *cp = c;
        return 1;
    }
    int n;
    uint32_t v;
    if ((c & 0xE0) == 0xC0) {
        n = 2;
        v = c & 0x1F;
    } else if ((c & 0xF0) == 0xE0) {
        n = 3;
        v = c & 0x0F;
    } else if ((c & 0xF8) == 0xF0) {
        n = 4;
        v = c & 0x07;
    } else {
        return 0;
    }
    for (int i = 1; i < n; i++) {
        if ((p[i] & 0xC0) != 0x80)
            return 0;
        v = (v << 6) | (p[i] & 0x3F);
    }
    if ((n == 2 && v < 0x80) || (n == 3 && v < 0x800) || (n == 4 && v < 0x10000) || v > 0x10FFFF ||
        (v >= 0xD800 && v <= 0xDFFF))
        return 0;
    *cp = v;
    return n;
}

bool utf8_valid(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        uint32_t cp;
        int n = utf8_seq(p, &cp);
        if (!n)
            return false;
        p += n;
    }
    return true;
}

size_t utf8_len(const char *s)
{
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if ((*p & 0xC0) != 0x80)
            n++;
    return n;
}

void utf8_truncate(char *s, size_t max_bytes)
{
    size_t n = strlen(s);
    if (n <= max_bytes)
        return;
    size_t i = max_bytes;
    while (i > 0 && ((unsigned char)s[i] & 0xC0) == 0x80)
        i--;
    s[i] = 0;
}

static char fold_cp(uint32_t cp)
{
    if (cp < 0x80)
        return (char)cp;
    /* Khối Latin Extended Additional dành cho tiếng Việt: chẵn = hoa, lẻ = thường */
    if (cp >= 0x1EA0 && cp <= 0x1EF9) {
        char base;
        if (cp <= 0x1EB7)
            base = 'a';
        else if (cp <= 0x1EC7)
            base = 'e';
        else if (cp <= 0x1ECB)
            base = 'i';
        else if (cp <= 0x1EE3)
            base = 'o';
        else if (cp <= 0x1EF1)
            base = 'u';
        else
            base = 'y';
        return (cp % 2 == 0) ? (char)toupper(base) : base;
    }
    if (cp >= 0xC0 && cp <= 0xFF) {
        static const char map[] = "AAAAAAACEEEEIIIIDNOOOOOxOUUUUYTsaaaaaaaceeeeiiiidnooooo/ouuuuyty";
        char c = map[cp - 0xC0];
        return (c == 'x' || c == '/') ? 0 : c;
    }
    switch (cp) {
    case 0x102: return 'A';
    case 0x103: return 'a';
    case 0x110: return 'D';
    case 0x111: return 'd';
    case 0x128: return 'I';
    case 0x129: return 'i';
    case 0x168: return 'U';
    case 0x169: return 'u';
    case 0x1A0: return 'O';
    case 0x1A1: return 'o';
    case 0x1AF: return 'U';
    case 0x1B0: return 'u';
    default: break;
    }
    return 0; /* dấu kết hợp (U+0300..U+036F) và ký tự khác: bỏ */
}

void ascii_fold(const char *in, char *out, size_t outsz)
{
    size_t w = 0;
    const unsigned char *p = (const unsigned char *)in;
    while (*p && w + 1 < outsz) {
        uint32_t cp;
        int n = utf8_seq(p, &cp);
        if (!n) {
            p++;
            continue;
        }
        p += n;
        char c = fold_cp(cp);
        if (c)
            out[w++] = c;
    }
    out[w] = 0;
}

void safe_filename(const char *name, char *out, size_t outsz, size_t maxlen)
{
    char tmp[512];
    ascii_fold(name, tmp, sizeof tmp);
    size_t w = 0;
    bool dash = false;
    for (size_t i = 0; tmp[i] && w + 1 < outsz && w < maxlen; i++) {
        char c = tmp[i];
        if (isalnum((unsigned char)c) || c == '_' || c == '=' || c == '+' || c == '.') {
            out[w++] = c;
            dash = false;
        } else if (!dash && w > 0) {
            out[w++] = '-';
            dash = true;
        }
    }
    while (w > 0 && (out[w - 1] == '-' || out[w - 1] == '.'))
        w--;
    out[w] = 0;
    if (w == 0)
        str_copy(out, "client", outsz);
}

bool str_is_digits(const char *s)
{
    if (!s || !*s)
        return false;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s))
            return false;
    return true;
}

int64_t str_to_i64(const char *s, int64_t def)
{
    if (!s || !*s)
        return def;
    char *end;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno || *end)
        return def;
    return (int64_t)v;
}

/* ================= files ================= */

char *file_read(const char *path, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    sb_t b;
    sb_init(&b);
    char buf[65536];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            sb_free(&b);
            return NULL;
        }
        if (n == 0)
            break;
        sb_appendn(&b, buf, (size_t)n);
    }
    close(fd);
    if (len)
        *len = b.len;
    return sb_steal(&b);
}

static int write_all_fd(int fd, const char *data, size_t len)
{
    while (len) {
        ssize_t n = write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        data += n;
        len -= (size_t)n;
    }
    return 0;
}

int file_write_atomic(const char *path, const char *data, size_t len, int mode)
{
    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s.tmp.%d.%08x", path, (int)getpid(), random_u32());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    if (fchmod(fd, (mode_t)mode) != 0 || write_all_fd(fd, data, len) != 0 || fsync(fd) != 0) {
        int e = errno;
        close(fd);
        unlink(tmp);
        errno = e;
        return -1;
    }
    close(fd);
    if (rename(tmp, path) != 0) {
        int e = errno;
        unlink(tmp);
        errno = e;
        return -1;
    }
    return 0;
}

int file_append(const char *path, const char *data, size_t len, int mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    int r = write_all_fd(fd, data, len);
    close(fd);
    return r;
}

int mkdir_p(const char *path, int mode)
{
    char tmp[4096];
    str_copy(tmp, path, sizeof tmp);
    size_t n = strlen(tmp);
    if (n && tmp[n - 1] == '/')
        tmp[n - 1] = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, (mode_t)mode) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, (mode_t)mode) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

bool file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

bool is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int64_t file_mtime_ns(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec + (int64_t)st.st_size;
}

int64_t file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    return (int64_t)st.st_size;
}

/* ================= random ================= */

int random_bytes(void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = getrandom(p, n, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            /* dự phòng: /dev/urandom */
            int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
            if (fd < 0)
                return -1;
            while (n) {
                ssize_t k = read(fd, p, n);
                if (k <= 0) {
                    if (k < 0 && errno == EINTR)
                        continue;
                    close(fd);
                    return -1;
                }
                p += k;
                n -= (size_t)k;
            }
            close(fd);
            return 0;
        }
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

uint32_t random_u32(void)
{
    uint32_t v = 0;
    if (random_bytes(&v, sizeof v) != 0)
        v = (uint32_t)time(NULL) ^ (uint32_t)getpid();
    return v;
}

void hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[in[i] >> 4];
        out[2 * i + 1] = hx[in[i] & 15];
    }
    out[2 * n] = 0;
}

void random_hex(char *out, size_t nbytes)
{
    uint8_t buf[64];
    if (nbytes > sizeof buf)
        nbytes = sizeof buf;
    random_bytes(buf, nbytes);
    hex_encode(buf, nbytes, out);
}

/* ================= time ================= */

int64_t now_unix(void)
{
    return (int64_t)time(NULL);
}

double now_mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

void civil_from_days(int64_t z, int *y, int *m, int *d)
{
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t yy = (int64_t)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    unsigned dd = doy - (153 * mp + 2) / 5 + 1;
    unsigned mm = mp < 10 ? mp + 3 : mp - 9;
    *y = (int)(yy + (mm <= 2));
    *m = (int)mm;
    *d = (int)dd;
}

int64_t days_from_civil(int y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (unsigned)((153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1);
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

/* ================= exec ================= */

static const char *DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

char *find_in_path(const char *prog)
{
    if (strchr(prog, '/'))
        return access(prog, X_OK) == 0 ? xstrdup(prog) : NULL;
    const char *envp = getenv("PATH");
    char paths[4096];
    snprintf(paths, sizeof paths, "%s:%s", DEFAULT_PATH, envp ? envp : "");
    char *save = NULL;
    for (char *dir = strtok_r(paths, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
        if (!*dir)
            continue;
        char full[4096];
        snprintf(full, sizeof full, "%s/%s", dir, prog);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISREG(st.st_mode) && access(full, X_OK) == 0)
            return xstrdup(full);
    }
    return NULL;
}

bool have_cmd(const char *prog)
{
    char *p = find_in_path(prog);
    bool ok = p != NULL;
    free(p);
    return ok;
}

void cmd_result_free(cmd_result_t *r)
{
    free(r->out);
    r->out = NULL;
    r->outlen = 0;
}

static bool env_overridden(const char *entry, const char *const extra[])
{
    if (!extra)
        return false;
    const char *eq = strchr(entry, '=');
    size_t klen = eq ? (size_t)(eq - entry) : strlen(entry);
    for (int i = 0; extra[i]; i++)
        if (strncmp(extra[i], entry, klen) == 0 && extra[i][klen] == '=')
            return true;
    return false;
}

int run_cmd(const char *const argv[], const char *const extra_env[], const char *input,
            int timeout_ms, cmd_result_t *res)
{
    memset(res, 0, sizeof *res);
    res->status = -1;
    char *path = find_in_path(argv[0]);
    if (!path) {
        sb_t b;
        sb_init(&b);
        sb_printf(&b, "không tìm thấy lệnh '%s'", argv[0]);
        res->outlen = b.len;
        res->out = sb_steal(&b);
        return -1;
    }

    extern char **environ;
    size_t n_env = 0, n_extra = 0;
    for (char **e = environ; e && *e; e++)
        n_env++;
    if (extra_env)
        while (extra_env[n_extra])
            n_extra++;
    char **envp = xcalloc(n_env + n_extra + 3, sizeof(char *));
    size_t k = 0;
    char pathvar[4200];
    snprintf(pathvar, sizeof pathvar, "PATH=%s", DEFAULT_PATH);
    if (!env_overridden("PATH=", extra_env))
        envp[k++] = pathvar;
    for (char **e = environ; e && *e; e++) {
        if (str_starts(*e, "PATH=") || env_overridden(*e, extra_env))
            continue;
        envp[k++] = *e;
    }
    for (size_t i = 0; i < n_extra; i++)
        envp[k++] = (char *)extra_env[i];
    envp[k] = NULL;

    int outp[2], inp[2] = {-1, -1};
    if (pipe2(outp, O_CLOEXEC) != 0) {
        free(path);
        free(envp);
        return -1;
    }
    if (input && pipe2(inp, O_CLOEXEC) != 0) {
        close(outp[0]);
        close(outp[1]);
        free(path);
        free(envp);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(outp[0]);
        close(outp[1]);
        if (input) {
            close(inp[0]);
            close(inp[1]);
        }
        free(path);
        free(envp);
        return -1;
    }
    if (pid == 0) {
        /* tiến trình con: chỉ dùng hàm an toàn sau fork */
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = SIG_DFL;
        sigaction(SIGPIPE, &sa, NULL);
        sigaction(SIGCHLD, &sa, NULL);
        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);
        if (input) {
            dup2(inp[0], 0);
        } else {
            int fd = open("/dev/null", O_RDONLY);
            if (fd >= 0)
                dup2(fd, 0);
        }
        dup2(outp[1], 1);
        dup2(outp[1], 2);
        execve(path, (char *const *)argv, envp);
        _exit(127);
    }

    close(outp[1]);
    if (input)
        close(inp[0]);
    free(path);
    free(envp);

    sb_t out;
    sb_init(&out);
    const char *inptr = input;
    size_t inleft = input ? strlen(input) : 0;
    int infd = input ? inp[1] : -1;
    if (infd >= 0 && inleft == 0) {
        close(infd);
        infd = -1;
    }
    if (infd >= 0)
        fcntl(infd, F_SETFL, fcntl(infd, F_GETFL) | O_NONBLOCK);

    double deadline = now_mono() + (timeout_ms > 0 ? timeout_ms : 60000) / 1000.0;
    bool timed_out = false;
    int outfd = outp[0];
    while (outfd >= 0) {
        struct pollfd pfd[2];
        int np = 0;
        pfd[np].fd = outfd;
        pfd[np].events = POLLIN;
        np++;
        if (infd >= 0) {
            pfd[np].fd = infd;
            pfd[np].events = POLLOUT;
            np++;
        }
        int remain = (int)((deadline - now_mono()) * 1000);
        if (remain <= 0) {
            timed_out = true;
            break;
        }
        int r = poll(pfd, (nfds_t)np, remain);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (r == 0) {
            timed_out = true;
            break;
        }
        if (np > 1 && (pfd[1].revents & (POLLOUT | POLLERR | POLLHUP))) {
            ssize_t w = write(infd, inptr, inleft);
            if (w > 0) {
                inptr += w;
                inleft -= (size_t)w;
            }
            if (w < 0 && errno != EAGAIN && errno != EINTR)
                inleft = 0;
            if (inleft == 0) {
                close(infd);
                infd = -1;
            }
        }
        if (pfd[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            char buf[8192];
            ssize_t n = read(outfd, buf, sizeof buf);
            if (n > 0) {
                if (out.len < 4 * 1024 * 1024)
                    sb_appendn(&out, buf, (size_t)n);
            } else if (n == 0 || (errno != EINTR && errno != EAGAIN)) {
                close(outfd);
                outfd = -1;
            }
        }
    }
    if (infd >= 0)
        close(infd);
    if (outfd >= 0)
        close(outfd);
    if (timed_out)
        kill(pid, SIGKILL);

    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
    }
    res->outlen = out.len;
    res->out = sb_steal(&out);
    if (timed_out) {
        res->status = -1;
        return -1;
    }
    res->status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return res->status == 0 ? 0 : -1;
}
