/*
 * Tuấn WireGuard - kiểm thử đơn vị: dữ liệu, mạng, ZIP, QR, cấu hình WireGuard
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/app.h"
#include "../src/auth.h"
#include "../src/crypto.h"
#include "../src/net.h"
#include "../src/qr.h"
#include "../src/stats.h"
#include "../src/store.h"
#include "../src/wg.h"
#include "../src/zip.h"

static int *P, *F;
#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (cond) {                                                                                \
            (*P)++;                                                                                \
        } else {                                                                                   \
            (*F)++;                                                                                \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                                          \
            printf(__VA_ARGS__);                                                                   \
            printf("\n");                                                                          \
        }                                                                                          \
    } while (0)

static json_t *J(const char *s)
{
    return json_parse(s, strlen(s), NULL, 0);
}

static void test_net(void)
{
    printf("[net]\n");
    char out[512];
    CHECK(cidr_list_normalize(" 0.0.0.0/0 ,::/0", out, sizeof out) == 0 && !strcmp(out, "0.0.0.0/0, ::/0"), "cidr norm: %s", out);
    CHECK(cidr_list_normalize("10.0.0.0/33", out, sizeof out) != 0, "cidr bad prefix");
    CHECK(cidr_list_normalize("10.0.0.1; rm -rf /", out, sizeof out) != 0, "cidr injection");
    CHECK(cidr_list_normalize("10.0.0.0/24\n[Peer]", out, sizeof out) != 0, "cidr newline injection");
    CHECK(dns_list_normalize("1.1.1.1, 2606:4700:4700::1111, corp.local", out, sizeof out) == 0, "dns ok");
    CHECK(dns_list_normalize("1.1.1.1 $(id)", out, sizeof out) != 0, "dns injection");
    CHECK(host_valid("vpn.example.com") && host_valid("1.2.3.4") && host_valid("[2001:db8::1]:51820") &&
              host_valid("vpn.example.com:443") && host_valid("2001:db8::1"),
          "host valid");
    CHECK(!host_valid("bad host") && !host_valid("a..b") && !host_valid("x:99999") && !host_valid(""), "host invalid");
    CHECK(iface_name_valid("wg0") && !iface_name_valid("wg0;ls") && !iface_name_valid("verylonginterfacename"), "iface");
    uint32_t a;
    int p;
    CHECK(cidr4_parse("10.8.0.1/24", &a, &p) == 0 && p == 24 && a == 0x0A080001, "cidr4");
}

static void test_store(void)
{
    printf("[store]\n");
    db_t db;
    db_defaults(&db);
    wg_genkey(db.s.private_key, db.s.public_key);
    char err[256];
    client_t c;
    memset(&c, 0, sizeof c);
    CHECK(client_init_new(&db, &c, err, sizeof err) == 0, "init: %s", err);
    CHECK(!strcmp(c.address, "10.8.0.2"), "first ip %s", c.address);
    json_t *in = J("{\"name\":\"  iPhone của Tuấn\\n[Peer] \",\"note\":\"a\\nb\",\"data_limit\":1000,\"expires_at\":0}");
    CHECK(client_apply_json(&db, &c, -1, in, true, err, sizeof err) == 0, "apply: %s", err);
    CHECK(!strchr(c.name, '\n') && strstr(c.name, "[Peer]"), "name sanitized: %s", c.name);
    CHECK(!strcmp(c.note, "a b"), "note newline->space: '%s'", c.note);
    json_free(in);
    *db_client_add(&db) = c;

    client_t c2;
    memset(&c2, 0, sizeof c2);
    client_init_new(&db, &c2, err, sizeof err);
    CHECK(!strcmp(c2.address, "10.8.0.3"), "second ip %s", c2.address);
    in = J("{\"name\":\"IPHONE CỦA Tuấn\\n[Peer]\"}");
    /* trùng tên (không phân biệt hoa thường với ký tự ASCII) */
    int dup = client_apply_json(&db, &c2, -1, in, true, err, sizeof err);
    json_free(in);
    in = J("{\"name\":\"iphone của Tuấn [Peer]\"}");
    dup = client_apply_json(&db, &c2, -1, in, true, err, sizeof err);
    CHECK(dup != 0, "duplicate name rejected");
    json_free(in);
    in = J("{\"name\":\"May 2\",\"address\":\"10.8.0.2\"}");
    CHECK(client_apply_json(&db, &c2, -1, in, true, err, sizeof err) != 0, "dup ip rejected");
    json_free(in);
    in = J("{\"name\":\"May 2\",\"address\":\"10.9.0.5\"}");
    CHECK(client_apply_json(&db, &c2, -1, in, true, err, sizeof err) != 0, "out of subnet rejected");
    json_free(in);
    in = J("{\"name\":\"May 2\",\"address\":\"10.8.0.1\"}");
    CHECK(client_apply_json(&db, &c2, -1, in, true, err, sizeof err) != 0, "server ip rejected");
    json_free(in);
    in = J("{\"name\":\"May 2\",\"address\":\"10.8.0.50\",\"keepalive\":15,\"mtu\":1280}");
    CHECK(client_apply_json(&db, &c2, -1, in, true, err, sizeof err) == 0 && !strcmp(c2.address, "10.8.0.50"), "custom ip: %s", err);
    json_free(in);
    *db_client_add(&db) = c2;

    /* đổi dải mạng -> đánh lại địa chỉ */
    int flags = 0;
    in = J("{\"address\":\"10.20.0.1/24\"}");
    CHECK(settings_apply_json(&db, in, &flags, err, sizeof err) == 0, "subnet change: %s", err);
    CHECK((flags & APPLY_RESTART_WG) != 0, "restart flag");
    CHECK(!strcmp(db.clients[0].address, "10.20.0.2") && !strcmp(db.clients[1].address, "10.20.0.50"), "renumber: %s %s", db.clients[0].address, db.clients[1].address);
    json_free(in);
    in = J("{\"address\":\"10.20.0.0/24\"}");
    CHECK(settings_apply_json(&db, in, &flags, err, sizeof err) != 0, "network address rejected");
    json_free(in);
    in = J("{\"ipv6\":true,\"address6\":\"fd42:42:42::1/64\"}");
    CHECK(settings_apply_json(&db, in, &flags, err, sizeof err) == 0, "ipv6 on: %s", err);
    CHECK(!strcmp(db.clients[0].address6, "fd42:42:42::2") && !strcmp(db.clients[1].address6, "fd42:42:42::32"), "v6: %s %s", db.clients[0].address6, db.clients[1].address6);
    json_free(in);
    in = J("{\"endpoint\":\"vpn.example.com\",\"web_port\":8443,\"post_up\":\"echo a\\necho b\"}");
    CHECK(settings_apply_json(&db, in, &flags, err, sizeof err) == 0 && (flags & APPLY_RESTART_WEB), "web restart flag");
    CHECK(!strchr(db.s.post_up, '\n'), "postup single line");
    json_free(in);

    /* JSON khứ hồi */
    sb_t b;
    sb_init(&b);
    db_to_json(&db, &b);
    json_t *j = json_parse(b.s, b.len, err, sizeof err);
    CHECK(j != NULL, "db json parse: %s", err);
    db_t db2;
    db_defaults(&db2);
    CHECK(db_from_json(&db2, j, err, sizeof err) == 0 && db2.nclients == 2 && !strcmp(db2.clients[0].name, db.clients[0].name) &&
              db2.s.ipv6 && db2.s.web_port == 8443 && !strcmp(db2.s.private_key, db.s.private_key),
          "db roundtrip");
    json_free(j);
    sb_free(&b);

    /* cấu hình WireGuard */
    sb_t conf;
    sb_init(&conf);
    wg_build_server_conf(&db, &conf, false);
    CHECK(strstr(conf.s, "[Interface]") && strstr(conf.s, "ListenPort = 51820") && strstr(conf.s, "Address = 10.20.0.1/24, fd42:42:42::1/64"), "server conf");
    CHECK(strstr(conf.s, "AllowedIPs = 10.20.0.2/32, fd42:42:42::2/128"), "peer allowed ips");
    CHECK(strstr(conf.s, "PostUp = echo a echo b") || strstr(conf.s, "PostUp = echo aecho b"), "custom postup");
    /* mỗi dòng không chứa ký tự điều khiển, tên không phá cấu trúc */
    int peers = 0;
    for (char *p = conf.s; (p = strstr(p, "[Peer]")); p++)
        peers++;
    CHECK(peers == 2 + 1 /* tên chứa chữ [Peer] trong comment */, "peer count %d", peers);
    sb_free(&conf);
    sb_init(&conf);
    wg_build_server_conf(&db, &conf, true);
    CHECK(!strstr(conf.s, "Address") && !strstr(conf.s, "PostUp") && !strstr(conf.s, "###"), "strip conf");
    sb_free(&conf);
    db.clients[1].enabled = false;
    sb_init(&conf);
    wg_build_server_conf(&db, &conf, true);
    CHECK(strstr(conf.s, db.clients[0].public_key) && !strstr(conf.s, db.clients[1].public_key), "disabled peer omitted");
    sb_free(&conf);
    sb_init(&conf);
    wg_build_client_conf(&db, &db.clients[1], &conf, false);
    CHECK(strstr(conf.s, "Endpoint = vpn.example.com:51820") && strstr(conf.s, "PersistentKeepalive = 15") && strstr(conf.s, "MTU = 1280") &&
              strstr(conf.s, "AllowedIPs = 0.0.0.0/0, ::/0"),
          "client conf:\n%s", conf.s);
    sb_free(&conf);
    char ep[300];
    str_copy(db.s.endpoint, "2001:db8::10", sizeof db.s.endpoint);
    wg_endpoint_string(&db.s, ep, sizeof ep);
    CHECK(!strcmp(ep, "[2001:db8::10]:51820"), "v6 endpoint %s", ep);
    str_copy(db.s.endpoint, "vpn.x.com:443", sizeof db.s.endpoint);
    wg_endpoint_string(&db.s, ep, sizeof ep);
    CHECK(!strcmp(ep, "vpn.x.com:443"), "endpoint with port %s", ep);

    char rules[4096];
    db.s.client_isolation = true;
    str_copy(db.s.wan_iface, "ens3", sizeof db.s.wan_iface);
    wg_auto_postup(&db.s, rules, sizeof rules);
    CHECK(strstr(rules, "-o ens3 -j MASQUERADE") && strstr(rules, "FORWARD -i %i -o %i -j DROP") && strstr(rules, "ip6tables"), "postup: %s", rules);
    wg_auto_postdown(&db.s, rules, sizeof rules);
    CHECK(strstr(rules, "-D POSTROUTING") && !strstr(rules, "-A "), "postdown");

    /* link chia sẻ */
    share_t *s = db_share_add(&db);
    str_copy(s->token, "abc", sizeof s->token);
    str_copy(s->client_id, db.clients[0].id, sizeof s->client_id);
    s->expires_at = 100;
    db_shares_prune(&db, 50);
    CHECK(db.nshares == 1 && db_share_by_token(&db, "abc"), "share alive");
    db_shares_prune(&db, 200);
    CHECK(db.nshares == 0, "share expired pruned");
    db_free(&db);
    db_free(&db2);
}

static void test_auth(void)
{
    printf("[auth]\n");
    char h[192];
    CHECK(auth_hash_password("mật khẩu 123", h, sizeof h) == 0 && str_starts(h, "pbkdf2-sha256$"), "hash");
    CHECK(auth_verify_password("mật khẩu 123", h), "verify ok");
    CHECK(!auth_verify_password("mật khẩu 124", h), "verify wrong");
    CHECK(!auth_verify_password("x", "plain"), "verify bad format");
    char pw[32];
    auth_random_password(pw, 15);
    CHECK(strlen(pw) == 14 && pw[4] == '-' && pw[9] == '-', "random pw %s", pw);
    for (int i = 0; i < 5; i++)
        auth_rate_fail("198.51.100.7");
    CHECK(auth_rate_check("198.51.100.7") > 0, "rate limited");
    CHECK(auth_rate_check("198.51.100.8") == 0, "other ip ok");
    auth_rate_success("198.51.100.7");
    CHECK(auth_rate_check("198.51.100.7") == 0, "reset");
    char tok[65];
    auth_session_create("1.2.3.4", "test", 1, tok);
    CHECK(auth_session_valid(tok), "session valid");
    auth_session_destroy(tok);
    CHECK(!auth_session_valid(tok), "session destroyed");
    CHECK(!auth_session_valid("short"), "bad token");
    char sec[40], uri[512];
    auth_totp_new_secret(sec);
    auth_totp_uri(sec, "admin", uri, sizeof uri);
    CHECK(str_starts(uri, "otpauth://totp/Tu%E1%BA%A5n%20WireGuard:admin?secret="), "uri %s", uri);
    uint8_t key[64];
    int kl = base32_decode(sec, key, sizeof key);
    char code[8];
    snprintf(code, sizeof code, "%06u", totp_code(key, (size_t)kl, (uint64_t)now_unix(), 30, 6));
    CHECK(auth_totp_check(sec, code), "totp ok");
    CHECK(!auth_totp_check(sec, code), "totp replay rejected");
}

static void test_zip_qr(void)
{
    printf("[zip/qr]\n");
    zip_t z;
    zip_init(&z);
    zip_add(&z, "a.conf", "hello", 5, 1700000000);
    zip_add(&z, "Tuấn.conf", "world!", 6, 1700000000);
    sb_t out;
    zip_finish(&z, &out);
    const char *zp = "/tmp/twg-test.zip";
    file_write_atomic(zp, out.s, out.len, 0600);
    sb_free(&out);
    if (have_cmd("unzip")) {
        const char *argv[] = {"unzip", "-p", zp, "a.conf", NULL};
        cmd_result_t r;
        run_cmd(argv, NULL, NULL, 5000, &r);
        CHECK(r.status == 0 && r.out && !strcmp(r.out, "hello"), "unzip content: %s", r.out);
        cmd_result_free(&r);
        const char *argv2[] = {"unzip", "-t", zp, NULL};
        run_cmd(argv2, NULL, NULL, 5000, &r);
        CHECK(r.status == 0, "unzip -t: %s", r.out);
        cmd_result_free(&r);
    } else {
        printf("  (bỏ qua unzip)\n");
    }
    unlink(zp);

    const char *text = "[Interface]\nPrivateKey = aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qga2V5IQ==\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\n\n"
                       "[Peer]\nPublicKey = d29ybGQgaGVsbG8gdGhpcyBpcyBhIHRlc3Qga2V5IQ==\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example.com:51820\n";
    sb_t svg;
    sb_init(&svg);
    CHECK(qr_svg(text, &svg) == 0 && str_starts(svg.s, "<svg") && strstr(svg.s, "</svg>"), "svg");
    sb_free(&svg);
    if (have_cmd("zbarimg")) {
        sb_t pbm;
        sb_init(&pbm);
        qr_pbm(text, 6, &pbm);
        const char *pp = "/tmp/twg-test-qr.pbm";
        file_write_atomic(pp, pbm.s, pbm.len, 0600);
        sb_free(&pbm);
        const char *argv[] = {"zbarimg", "-q", "--raw", pp, NULL};
        cmd_result_t r;
        run_cmd(argv, NULL, NULL, 15000, &r);
        /* zbarimg có thể in cảnh báo dbus; chỉ cần chứa nguyên văn */
        CHECK(r.out && strstr(r.out, text), "qr decode matches");
        cmd_result_free(&r);
        unlink(pp);
    } else {
        printf("  (bỏ qua zbarimg)\n");
    }
}

static void test_stats(void)
{
    printf("[stats]\n");
    series_t s;
    memset(&s, 0, sizeof s);
    for (int i = 0; i < 10; i++)
        series_add(&s, i, 1, 2, 5);
    CHECK(s.n == 5 && s.b[0].k == 5 && s.b[4].k == 9, "series keep");
    series_add(&s, 9, 10, 10, 5);
    CHECK(s.b[4].rx == 11, "series same key");
    uint64_t rx, tx;
    series_sum_range(&s, 6, 8, &rx, &tx);
    CHECK(rx == 3 && tx == 6, "sum range");
    free(s.b);
    CHECK(key_day(0, 420) == 0 && key_day(86400 - 7 * 3600, 420) == 1, "day key tz");
    CHECK(key_month(1790467200, 420) == 2026 * 12 + 8, "month key");
    char lab[16];
    key_day_label(20723, lab, sizeof lab);
    CHECK(!strcmp(lab, "2026-09-27"), "label %s", lab);
}

void test_more(int *pass, int *fail)
{
    P = pass;
    F = fail;
    test_net();
    test_store();
    test_auth();
    test_zip_qr();
    test_stats();
}
