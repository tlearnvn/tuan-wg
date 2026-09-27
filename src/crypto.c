/*
 * Tuấn WireGuard - mật mã
 * Tác giả: Tuandethuong
 *
 * X25519 dựa trên TweetNaCl (public domain) của D. J. Bernstein và cộng sự.
 */
#include "crypto.h"

#include <pthread.h>
#include <string.h>

#include "util.h"

/* ================= SHA-256 ================= */

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void sha256_block(sha256_ctx *c, const uint8_t *blk)
{
    uint32_t w[64];
    for (int t = 0; t < 16; t++)
        w[t] = be32(blk + 4 * t);
    for (int t = 16; t < 64; t++) {
        uint32_t s0 = ROR32(w[t - 15], 7) ^ ROR32(w[t - 15], 18) ^ (w[t - 15] >> 3);
        uint32_t s1 = ROR32(w[t - 2], 17) ^ ROR32(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int t = 0; t < 64; t++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[t] + w[t];
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;
}

void sha256_init(sha256_ctx *c)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, iv, sizeof iv);
    c->len = 0;
    c->n = 0;
}

void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = data;
    c->len += len;
    if (c->n) {
        size_t take = 64 - c->n;
        if (take > len)
            take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take;
        p += take;
        len -= take;
        if (c->n == 64) {
            sha256_block(c, c->buf);
            c->n = 0;
        }
    }
    while (len >= 64) {
        sha256_block(c, p);
        p += 64;
        len -= 64;
    }
    if (len) {
        memcpy(c->buf, p, len);
        c->n = len;
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->n != 56)
        sha256_update(c, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++)
        lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++)
        put_be32(out + 4 * i, c->h[i]);
}

void sha256(const void *data, size_t len, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

static void hmac256_prepare(const uint8_t *key, size_t klen, sha256_ctx *ictx, sha256_ctx *octx)
{
    uint8_t k[64] = {0};
    if (klen > 64)
        sha256(key, klen, k);
    else if (klen)
        memcpy(k, key, klen);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    sha256_init(ictx);
    sha256_update(ictx, ipad, 64);
    sha256_init(octx);
    sha256_update(octx, opad, 64);
    secure_zero(k, sizeof k);
}

void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    sha256_ctx ic, oc;
    hmac256_prepare(key, klen, &ic, &oc);
    uint8_t inner[32];
    sha256_update(&ic, msg, mlen);
    sha256_final(&ic, inner);
    sha256_update(&oc, inner, 32);
    sha256_final(&oc, out);
}

void pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                   uint32_t iterations, uint8_t *out, size_t outlen)
{
    sha256_ctx ictx, octx;
    hmac256_prepare(pw, pwlen, &ictx, &octx);
    uint32_t block = 1;
    while (outlen) {
        uint8_t u[32], t[32], inner[32], cnt[4];
        put_be32(cnt, block);
        sha256_ctx c = ictx;
        sha256_update(&c, salt, saltlen);
        sha256_update(&c, cnt, 4);
        sha256_final(&c, inner);
        c = octx;
        sha256_update(&c, inner, 32);
        sha256_final(&c, u);
        memcpy(t, u, 32);
        for (uint32_t j = 1; j < iterations; j++) {
            c = ictx;
            sha256_update(&c, u, 32);
            sha256_final(&c, inner);
            c = octx;
            sha256_update(&c, inner, 32);
            sha256_final(&c, u);
            for (int k = 0; k < 32; k++)
                t[k] ^= u[k];
        }
        size_t take = outlen < 32 ? outlen : 32;
        memcpy(out, t, take);
        out += take;
        outlen -= take;
        block++;
    }
}

/* ================= SHA-1 ================= */

static void sha1_block(sha1_ctx *c, const uint8_t *blk)
{
    uint32_t w[80];
    for (int t = 0; t < 16; t++)
        w[t] = be32(blk + 4 * t);
    for (int t = 16; t < 80; t++)
        w[t] = ROL32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4];
    for (int t = 0; t < 80; t++) {
        uint32_t f, k;
        if (t < 20) {
            f = (b & cc) | (~b & d);
            k = 0x5A827999;
        } else if (t < 40) {
            f = b ^ cc ^ d;
            k = 0x6ED9EBA1;
        } else if (t < 60) {
            f = (b & cc) | (b & d) | (cc & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ cc ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t tmp = ROL32(a, 5) + f + e + k + w[t];
        e = d;
        d = cc;
        cc = ROL32(b, 30);
        b = a;
        a = tmp;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
}

void sha1_init(sha1_ctx *c)
{
    c->h[0] = 0x67452301;
    c->h[1] = 0xEFCDAB89;
    c->h[2] = 0x98BADCFE;
    c->h[3] = 0x10325476;
    c->h[4] = 0xC3D2E1F0;
    c->len = 0;
    c->n = 0;
}

void sha1_update(sha1_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = data;
    c->len += len;
    while (len) {
        size_t take = 64 - c->n;
        if (take > len)
            take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take;
        p += take;
        len -= take;
        if (c->n == 64) {
            sha1_block(c, c->buf);
            c->n = 0;
        }
    }
}

void sha1_final(sha1_ctx *c, uint8_t out[20])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80, z = 0;
    sha1_update(c, &pad, 1);
    while (c->n != 56)
        sha1_update(c, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++)
        lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha1_update(c, lenb, 8);
    for (int i = 0; i < 5; i++)
        put_be32(out + 4 * i, c->h[i]);
}

void hmac_sha1(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[20])
{
    uint8_t k[64] = {0};
    if (klen > 64) {
        sha1_ctx t;
        sha1_init(&t);
        sha1_update(&t, key, klen);
        sha1_final(&t, k);
    } else if (klen) {
        memcpy(k, key, klen);
    }
    uint8_t ipad[64], opad[64], inner[20];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    sha1_ctx c;
    sha1_init(&c);
    sha1_update(&c, ipad, 64);
    sha1_update(&c, msg, mlen);
    sha1_final(&c, inner);
    sha1_init(&c);
    sha1_update(&c, opad, 64);
    sha1_update(&c, inner, 20);
    sha1_final(&c, out);
    secure_zero(k, sizeof k);
}

/* ================= Base64 / Base32 ================= */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char B64URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t b64_enc(const char *alpha, int pad, const uint8_t *in, size_t n, char *out)
{
    size_t w = 0;
    size_t i = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[w++] = alpha[(v >> 18) & 63];
        out[w++] = alpha[(v >> 12) & 63];
        out[w++] = alpha[(v >> 6) & 63];
        out[w++] = alpha[v & 63];
    }
    if (i < n) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n)
            v |= (uint32_t)in[i + 1] << 8;
        out[w++] = alpha[(v >> 18) & 63];
        out[w++] = alpha[(v >> 12) & 63];
        if (i + 1 < n)
            out[w++] = alpha[(v >> 6) & 63];
        else if (pad)
            out[w++] = '=';
        if (pad)
            out[w++] = '=';
    }
    out[w] = 0;
    return w;
}

size_t base64_encode(const uint8_t *in, size_t n, char *out)
{
    return b64_enc(B64, 1, in, n, out);
}

void base64url_encode(const uint8_t *in, size_t n, char *out)
{
    b64_enc(B64URL, 0, in, n, out);
}

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+' || c == '-')
        return 62;
    if (c == '/' || c == '_')
        return 63;
    return -1;
}

int base64_decode(const char *in, uint8_t *out, size_t outsz)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t w = 0;
    int pad = 0;
    for (const char *p = in; *p; p++) {
        if (*p == '=') {
            pad++;
            continue;
        }
        if (*p == '\n' || *p == '\r' || *p == ' ')
            continue;
        if (pad)
            return -1; /* ký tự sau padding */
        int v = b64val(*p);
        if (v < 0)
            return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (w >= outsz)
                return -1;
            out[w++] = (uint8_t)(acc >> bits);
        }
    }
    if (pad > 2)
        return -1;
    return (int)w;
}

static const char B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

void base32_encode(const uint8_t *in, size_t n, char *out)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[w++] = B32[(acc >> bits) & 31];
        }
    }
    if (bits > 0)
        out[w++] = B32[(acc << (5 - bits)) & 31];
    out[w] = 0;
}

int base32_decode(const char *in, uint8_t *out, size_t outsz)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t w = 0;
    for (const char *p = in; *p; p++) {
        char c = *p;
        if (c == '=' || c == ' ' || c == '-')
            continue;
        if (c >= 'a' && c <= 'z')
            c = (char)(c - 32);
        const char *q = strchr(B32, c);
        if (!q || !c)
            return -1;
        acc = (acc << 5) | (uint32_t)(q - B32);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (w >= outsz)
                return -1;
            out[w++] = (uint8_t)(acc >> bits);
        }
    }
    return (int)w;
}

/* ================= X25519 (TweetNaCl) ================= */

typedef int64_t gf[16];

static const gf GF_121665 = {0xDB41, 1};

static void car25519(gf o)
{
    for (int i = 0; i < 16; i++) {
        o[i] += (int64_t)1 << 16;
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * 65536;
    }
}

static void sel25519(gf p, gf q, int b)
{
    int64_t c = ~((int64_t)b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n)
{
    gf m, t;
    for (int i = 0; i < 16; i++)
        t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n)
{
    for (int i = 0; i < 16; i++)
        o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void gf_add(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; i++)
        o[i] = a[i] + b[i];
}

static void gf_sub(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; i++)
        o[i] = a[i] - b[i];
}

static void gf_mul(gf o, const gf a, const gf b)
{
    int64_t t[31];
    for (int i = 0; i < 31; i++)
        t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++)
        t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++)
        o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void gf_sqr(gf o, const gf a)
{
    gf_mul(o, a, a);
}

static void inv25519(gf o, const gf in)
{
    gf c;
    for (int a = 0; a < 16; a++)
        c[a] = in[a];
    for (int a = 253; a >= 0; a--) {
        gf_sqr(c, c);
        if (a != 2 && a != 4)
            gf_mul(c, c, in);
    }
    for (int a = 0; a < 16; a++)
        o[a] = c[a];
}

void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t z[32];
    gf x, a, b, c, d, e, f;
    for (int i = 0; i < 31; i++)
        z[i] = scalar[i];
    z[31] = (uint8_t)((scalar[31] & 127) | 64);
    z[0] &= 248;
    unpack25519(x, point);
    for (int i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_add(c, b, d);
        gf_sub(b, b, d);
        gf_sqr(d, e);
        gf_sqr(f, a);
        gf_mul(a, c, a);
        gf_mul(c, b, e);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_sqr(b, a);
        gf_sub(c, d, f);
        gf_mul(a, c, GF_121665);
        gf_add(a, a, d);
        gf_mul(c, c, a);
        gf_mul(a, d, f);
        gf_mul(d, b, x);
        gf_sqr(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    gf_mul(a, a, c);
    pack25519(out, a);
    secure_zero(z, sizeof z);
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32])
{
    static const uint8_t nine[32] = {9};
    x25519(out, scalar, nine);
}

int wg_key_valid(const char *b64)
{
    if (!b64 || strlen(b64) != 44 || b64[43] != '=')
        return 0;
    uint8_t k[33];
    return base64_decode(b64, k, sizeof k) == 32;
}

int wg_genkey(char priv_b64[45], char pub_b64[45])
{
    uint8_t priv[32], pub[32];
    if (random_bytes(priv, 32) != 0)
        return -1;
    priv[0] &= 248;
    priv[31] = (uint8_t)((priv[31] & 127) | 64);
    x25519_base(pub, priv);
    base64_encode(priv, 32, priv_b64);
    base64_encode(pub, 32, pub_b64);
    secure_zero(priv, sizeof priv);
    return 0;
}

int wg_genpsk(char psk_b64[45])
{
    uint8_t k[32];
    if (random_bytes(k, 32) != 0)
        return -1;
    base64_encode(k, 32, psk_b64);
    secure_zero(k, sizeof k);
    return 0;
}

int wg_pubkey(const char *priv_b64, char pub_b64[45])
{
    uint8_t priv[33], pub[32];
    if (!wg_key_valid(priv_b64) || base64_decode(priv_b64, priv, sizeof priv) != 32)
        return -1;
    x25519_base(pub, priv);
    base64_encode(pub, 32, pub_b64);
    secure_zero(priv, sizeof priv);
    return 0;
}

/* ================= TOTP ================= */

uint32_t totp_code(const uint8_t *secret, size_t slen, uint64_t t, int step, int digits)
{
    uint64_t counter = t / (uint64_t)step;
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) {
        msg[i] = (uint8_t)(counter & 0xff);
        counter >>= 8;
    }
    uint8_t h[20];
    hmac_sha1(secret, slen, msg, 8, h);
    int off = h[19] & 0x0f;
    uint32_t bin = ((uint32_t)(h[off] & 0x7f) << 24) | ((uint32_t)h[off + 1] << 16) |
                   ((uint32_t)h[off + 2] << 8) | h[off + 3];
    uint32_t mod = 1;
    for (int i = 0; i < digits; i++)
        mod *= 10;
    return bin % mod;
}

int totp_verify(const char *secret_b32, const char *code, uint64_t now, int window)
{
    char digits[16];
    size_t n = 0;
    for (const char *p = code; *p && n < sizeof digits - 1; p++) {
        if (*p >= '0' && *p <= '9')
            digits[n++] = *p;
        else if (*p != ' ' && *p != '-')
            return 0;
    }
    digits[n] = 0;
    if (n != 6)
        return 0;
    uint32_t want = 0;
    for (size_t i = 0; i < n; i++)
        want = want * 10 + (uint32_t)(digits[i] - '0');
    uint8_t secret[64];
    int slen = base32_decode(secret_b32, secret, sizeof secret);
    if (slen <= 0)
        return 0;
    int ok = 0;
    for (int w = -window; w <= window; w++) {
        uint64_t t = now + (int64_t)w * 30;
        if (totp_code(secret, (size_t)slen, t, 30, 6) == want)
            ok = 1;
    }
    secure_zero(secret, sizeof secret);
    return ok;
}

/* ================= misc ================= */

static uint32_t crc_table[256];
static pthread_once_t crc_once = PTHREAD_ONCE_INIT;

static void crc_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_table[i] = c;
    }
}

uint32_t crc32_update(uint32_t crc, const void *data, size_t len)
{
    pthread_once(&crc_once, crc_init);
    const uint32_t *table = crc_table;
    const uint8_t *p = data;
    crc = ~crc;
    for (size_t i = 0; i < len; i++)
        crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
    return ~crc;
}

int ct_equal(const void *a, const void *b, size_t n)
{
    const volatile uint8_t *x = a, *y = b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= (uint8_t)(x[i] ^ y[i]);
    return d == 0;
}

void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--)
        *v++ = 0;
}
