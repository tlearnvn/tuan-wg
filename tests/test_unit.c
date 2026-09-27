/*
 * Tuấn WireGuard - kiểm thử đơn vị
 * Chạy: make test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crypto.h"
#include "../src/json.h"
#include "../src/util.h"

static int g_fail = 0, g_pass = 0;

#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (cond) {                                                                                \
            g_pass++;                                                                              \
        } else {                                                                                   \
            g_fail++;                                                                              \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                                          \
            printf(__VA_ARGS__);                                                                   \
            printf("\n");                                                                          \
        }                                                                                          \
    } while (0)

static void hex(const uint8_t *b, size_t n, char *out)
{
    hex_encode(b, n, out);
}

static void unhex(const char *s, uint8_t *out)
{
    size_t n = strlen(s) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void test_sha256(void)
{
    printf("[sha256/hmac/pbkdf2]\n");
    uint8_t d[64];
    char h[129];
    sha256("abc", 3, d);
    hex(d, 32, h);
    CHECK(strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0, "sha256 abc %s", h);
    sha256("", 0, d);
    hex(d, 32, h);
    CHECK(strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0, "sha256 empty");
    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(m, strlen(m), d);
    hex(d, 32, h);
    CHECK(strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0, "sha256 448bit");
    /* 1 triệu chữ 'a' qua nhiều lần update */
    sha256_ctx c;
    sha256_init(&c);
    char a[1000];
    memset(a, 'a', sizeof a);
    for (int i = 0; i < 1000; i++)
        sha256_update(&c, a, 1000);
    sha256_final(&c, d);
    hex(d, 32, h);
    CHECK(strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0, "sha256 million a");

    hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, d);
    hex(d, 32, h);
    CHECK(strcmp(h, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0, "hmac rfc4231 #2");

    pbkdf2_sha256((const uint8_t *)"passwd", 6, (const uint8_t *)"salt", 4, 1, d, 64);
    hex(d, 64, h);
    CHECK(strcmp(h, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783") == 0, "pbkdf2 c=1");
    pbkdf2_sha256((const uint8_t *)"Password", 8, (const uint8_t *)"NaCl", 4, 80000, d, 64);
    hex(d, 64, h);
    CHECK(strcmp(h, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d") == 0, "pbkdf2 c=80000");
}

static void test_sha1_totp(void)
{
    printf("[sha1/totp/base32]\n");
    sha1_ctx c;
    uint8_t d[20];
    char h[41];
    sha1_init(&c);
    sha1_update(&c, "abc", 3);
    sha1_final(&c, d);
    hex(d, 20, h);
    CHECK(strcmp(h, "a9993e364706816aba3e25717850c26c9cd0d89d") == 0, "sha1 abc");
    const uint8_t *sec = (const uint8_t *)"12345678901234567890";
    CHECK(totp_code(sec, 20, 59, 30, 8) == 94287082, "totp 59");
    CHECK(totp_code(sec, 20, 1111111109, 30, 8) == 7081804, "totp 1111111109");
    CHECK(totp_code(sec, 20, 1234567890, 30, 8) == 89005924, "totp 1234567890");
    CHECK(totp_code(sec, 20, 20000000000ULL, 30, 8) == 65353130, "totp 20000000000");
    char b32[64];
    base32_encode(sec, 20, b32);
    CHECK(strcmp(b32, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") == 0, "base32 enc %s", b32);
    uint8_t back[32];
    CHECK(base32_decode("gezdgnbvgy3tqojqgezdgnbvgy3tqojq", back, sizeof back) == 20 && memcmp(back, sec, 20) == 0, "base32 dec");
    CHECK(totp_verify(b32, "287082", 59, 1) == 1, "totp verify");
    CHECK(totp_verify(b32, "287 082", 59 + 30, 1) == 1, "totp verify window");
    CHECK(totp_verify(b32, "287082", 59 + 120, 1) == 0, "totp verify expired");
    CHECK(totp_verify(b32, "12345", 59, 1) == 0, "totp short");
}

static void test_base64(void)
{
    printf("[base64]\n");
    char out[64];
    uint8_t buf[64];
    base64_encode((const uint8_t *)"foobar", 6, out);
    CHECK(strcmp(out, "Zm9vYmFy") == 0, "b64 foobar");
    base64_encode((const uint8_t *)"fooba", 5, out);
    CHECK(strcmp(out, "Zm9vYmE=") == 0, "b64 fooba");
    base64_encode((const uint8_t *)"foob", 4, out);
    CHECK(strcmp(out, "Zm9vYg==") == 0, "b64 foob");
    CHECK(base64_decode("Zm9vYg==", buf, sizeof buf) == 4 && memcmp(buf, "foob", 4) == 0, "b64 dec");
    CHECK(base64_decode("Zm9v!g==", buf, sizeof buf) == -1, "b64 invalid");
    base64url_encode((const uint8_t *)"\xfb\xff", 2, out);
    CHECK(strcmp(out, "-_8") == 0, "b64url %s", out);
}

static void test_x25519(void)
{
    printf("[x25519]\n");
    uint8_t s[32], u[32], o[32];
    char h[65];
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", s);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
    x25519(o, s, u);
    hex(o, 32, h);
    CHECK(strcmp(h, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552") == 0, "rfc7748 v1 %s", h);
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", s);
    x25519_base(o, s);
    hex(o, 32, h);
    CHECK(strcmp(h, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a") == 0, "alice pub");
    uint8_t bob[32], bobpub[32], sh1[32], sh2[32];
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bob);
    x25519_base(bobpub, bob);
    hex(bobpub, 32, h);
    CHECK(strcmp(h, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f") == 0, "bob pub");
    x25519(sh1, s, bobpub);
    x25519(sh2, bob, o);
    hex(sh1, 32, h);
    CHECK(memcmp(sh1, sh2, 32) == 0 && strcmp(h, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742") == 0, "shared");

    char priv[45], pub[45], pub2[45];
    CHECK(wg_genkey(priv, pub) == 0, "genkey");
    CHECK(wg_key_valid(priv) && wg_key_valid(pub), "key valid");
    CHECK(wg_pubkey(priv, pub2) == 0 && strcmp(pub, pub2) == 0, "pubkey roundtrip");
    CHECK(!wg_key_valid("abc"), "invalid key");
}

static void test_json(void)
{
    printf("[json]\n");
    const char *src = "{\"name\":\"Tu\\u1ea5n \\ud83d\\ude00\",\"n\":42,\"f\":1.5,\"b\":true,\"z\":null,"
                      "\"arr\":[1,2,{\"x\":\"y\"}],\"esc\":\"a\\\"b\\\\c\\n\"}";
    char err[128];
    json_t *j = json_parse(src, strlen(src), err, sizeof err);
    CHECK(j != NULL, "parse: %s", err);
    if (j) {
        CHECK(strcmp(json_str(j, "name", ""), "Tu\xe1\xba\xa5n \xf0\x9f\x98\x80") == 0, "unicode");
        CHECK(json_int(j, "n", 0) == 42, "int");
        CHECK(json_num(j, "f", 0) == 1.5, "float");
        CHECK(json_bool(j, "b", 0) == 1, "bool");
        CHECK(json_get(j, "z")->type == J_NULL, "null");
        CHECK(json_len(json_get(j, "arr")) == 3, "arr len");
        CHECK(strcmp(json_str(json_at(json_get(j, "arr"), 2), "x", ""), "y") == 0, "nested");
        CHECK(strcmp(json_str(j, "esc", ""), "a\"b\\c\n") == 0, "escapes");
        json_free(j);
    }
    const char *bad[] = {"{", "[1,]", "{\"a\":}", "\"abc", "tru", "{\"a\" 1}", "[1] x", "01x"};
    for (size_t i = 0; i < ARRAY_LEN(bad); i++) {
        json_t *b = json_parse(bad[i], strlen(bad[i]), err, sizeof err);
        CHECK(b == NULL, "should fail: %s", bad[i]);
        json_free(b);
    }
    /* độ sâu */
    char deep[200];
    memset(deep, '[', 100);
    memset(deep + 100, ']', 100);
    json_t *dj = json_parse(deep, 200, err, sizeof err);
    CHECK(dj == NULL, "depth limit");
    json_free(dj);

    sb_t sb;
    sb_init(&sb);
    jw_t w;
    jw_init(&w, &sb);
    jw_obj(&w);
    jw_kstr(&w, "a", "x\"y\n<");
    jw_kint(&w, "b", -5);
    jw_key(&w, "c");
    jw_arr(&w);
    jw_int(&w, 1);
    jw_obj(&w);
    jw_kbool(&w, "t", 1);
    jw_obj_end(&w);
    jw_null(&w);
    jw_arr_end(&w);
    jw_knum(&w, "d", 2.5);
    jw_obj_end(&w);
    CHECK(strcmp(sb.s, "{\"a\":\"x\\\"y\\n\\u003c\",\"b\":-5,\"c\":[1,{\"t\":true},null],\"d\":2.5}") == 0, "writer: %s", sb.s);
    json_t *rt = json_parse(sb.s, sb.len, err, sizeof err);
    CHECK(rt && strcmp(json_str(rt, "a", ""), "x\"y\n<") == 0, "roundtrip");
    json_free(rt);
    sb_free(&sb);
}

static void test_util(void)
{
    printf("[util]\n");
    char out[64];
    ascii_fold("Trương Anh Tuấn - Đà Nẵng", out, sizeof out);
    CHECK(strcmp(out, "Truong Anh Tuan - Da Nang") == 0, "fold: %s", out);
    ascii_fold("Ứng Ỷ Ỹ ợ ự ỗ", out, sizeof out);
    CHECK(strcmp(out, "Ung Y Y o u o") == 0, "fold2: %s", out);
    safe_filename("iPhone của Tuấn", out, sizeof out, 15);
    CHECK(strcmp(out, "iPhone-cua-Tuan") == 0, "filename: %s", out);
    safe_filename("   ", out, sizeof out, 15);
    CHECK(strcmp(out, "client") == 0, "filename empty");
    safe_filename("Máy tính văn phòng", out, sizeof out, 15);
    CHECK(strlen(out) <= 15, "filename len %s", out);
    char s[64] = "ab\ncd\r\x01" "ef";
    str_strip_ctrl(s);
    CHECK(strcmp(s, "abcdef") == 0, "strip ctrl");
    CHECK(utf8_valid("Tuấn"), "utf8 valid");
    CHECK(!utf8_valid("\xc3\x28"), "utf8 invalid");
    CHECK(utf8_len("Tuấn") == 4, "utf8 len");
    char t[16] = "Tuấn";
    utf8_truncate(t, 4);
    CHECK(strcmp(t, "Tu") == 0, "truncate: %s", t);
    int y, m, d;
    civil_from_days(0, &y, &m, &d);
    CHECK(y == 1970 && m == 1 && d == 1, "civil 0");
    civil_from_days(days_from_civil(2026, 9, 26), &y, &m, &d);
    CHECK(y == 2026 && m == 9 && d == 26, "civil roundtrip");
    CHECK(days_from_civil(2000, 3, 1) == 11017, "days 2000-03-01");

    cmd_result_t r;
    const char *argv[] = {"sh", "-c", "read x; echo got:$x; echo err >&2; exit 3", NULL};
    run_cmd(argv, NULL, "hello\n", 5000, &r);
    CHECK(r.status == 3 && strstr(r.out, "got:hello") && strstr(r.out, "err"), "run_cmd: %d %s", r.status, r.out);
    cmd_result_free(&r);
    const char *argv2[] = {"sleep", "5", NULL};
    double t0 = now_mono();
    run_cmd(argv2, NULL, NULL, 300, &r);
    CHECK(r.status == -1 && now_mono() - t0 < 2, "run_cmd timeout");
    cmd_result_free(&r);
    const char *env[] = {"TWG_TEST=xyz", NULL};
    const char *argv3[] = {"sh", "-c", "echo $TWG_TEST", NULL};
    run_cmd(argv3, env, NULL, 5000, &r);
    CHECK(r.status == 0 && strstr(r.out, "xyz"), "run_cmd env");
    cmd_result_free(&r);
    uint32_t crc = crc32_update(0, "123456789", 9);
    CHECK(crc == 0xCBF43926, "crc32 %08x", crc);
}

void test_more(int *pass, int *fail);

int main(void)
{
    test_sha256();
    test_sha1_totp();
    test_base64();
    test_x25519();
    test_json();
    test_util();
    int p = 0, f = 0;
    test_more(&p, &f);
    g_pass += p;
    g_fail += f;
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
