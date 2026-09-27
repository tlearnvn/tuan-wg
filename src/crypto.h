/*
 * Tuấn WireGuard - mật mã: SHA-256, SHA-1, HMAC, PBKDF2, X25519, Base64/32, TOTP, CRC32
 * Tác giả: Tuandethuong
 */
#ifndef TWG_CRYPTO_H
#define TWG_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ---------- SHA-256 ---------- */
typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t n;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const void *data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32]);
void pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                   uint32_t iterations, uint8_t *out, size_t outlen);

/* ---------- SHA-1 (chỉ dùng cho TOTP theo RFC 6238) ---------- */
typedef struct {
    uint32_t h[5];
    uint64_t len;
    uint8_t buf[64];
    size_t n;
} sha1_ctx;

void sha1_init(sha1_ctx *c);
void sha1_update(sha1_ctx *c, const void *data, size_t len);
void sha1_final(sha1_ctx *c, uint8_t out[20]);
void hmac_sha1(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[20]);

/* ---------- Base64 / Base32 ---------- */
size_t base64_encode(const uint8_t *in, size_t n, char *out); /* out >= 4*((n+2)/3)+1 */
int base64_decode(const char *in, uint8_t *out, size_t outsz); /* trả về số byte, -1 nếu lỗi */
void base64url_encode(const uint8_t *in, size_t n, char *out); /* không padding */
void base32_encode(const uint8_t *in, size_t n, char *out);   /* không padding */
int base32_decode(const char *in, uint8_t *out, size_t outsz);

/* ---------- X25519 & khóa WireGuard ---------- */
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);
/* Tạo cặp khóa WireGuard dạng base64 (44 ký tự + NUL) */
int wg_genkey(char priv_b64[45], char pub_b64[45]);
int wg_genpsk(char psk_b64[45]);
int wg_pubkey(const char *priv_b64, char pub_b64[45]);
int wg_key_valid(const char *b64);

/* ---------- TOTP (RFC 6238) ---------- */
uint32_t totp_code(const uint8_t *secret, size_t slen, uint64_t t, int step, int digits);
int totp_verify(const char *secret_b32, const char *code, uint64_t now, int window);

/* ---------- tiện ích ---------- */
uint32_t crc32_update(uint32_t crc, const void *data, size_t len);
int ct_equal(const void *a, const void *b, size_t n);
void secure_zero(void *p, size_t n);

#endif
