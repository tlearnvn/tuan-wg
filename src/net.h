/*
 * Tuấn WireGuard - tiện ích mạng: IP/CIDR, phát hiện card mạng, IP công khai
 * Tác giả: Tuandethuong
 */
#ifndef TWG_NET_H
#define TWG_NET_H

#include <stddef.h>
#include <stdint.h>

int ip4_parse(const char *s, uint32_t *out);
void ip4_format(uint32_t a, char out[16]);
int cidr4_parse(const char *s, uint32_t *addr, int *prefix);
int ip6_parse(const char *s, uint8_t out[16]);
void ip6_format(const uint8_t a[16], char out[46]);
int cidr6_parse(const char *s, uint8_t addr[16], int *prefix);

/* Kiểm tra & chuẩn hóa danh sách CIDR ("0.0.0.0/0, ::/0") */
int cidr_list_normalize(const char *s, char *out, size_t outsz);
/* Kiểm tra & chuẩn hóa danh sách DNS (IP hoặc tên miền tìm kiếm) */
int dns_list_normalize(const char *s, char *out, size_t outsz);
/* Tên máy/IP dùng làm Endpoint */
int host_valid(const char *s);
int iface_name_valid(const char *s);

int net_default_iface(char *out, size_t n);
int net_local_ip(char *out, size_t n);
int net_public_ip(char *out, size_t n, int timeout_ms);
int net_iface_exists(const char *name);
int net_iface_stats(const char *name, uint64_t *rx, uint64_t *tx);
int net_iface_ipv4(const char *name, char *out, size_t n);

#endif
