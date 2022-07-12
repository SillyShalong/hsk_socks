#pragma once

#define SOCKS_VERSION              0x05
#define SOCKS5_METHOD_NOAUTH       0x00
#define SOCKS5_METHOD_UNACCEPTABLE 0xff

#define SOCKS5_CMD_CONNECT       0x01
#define SOCKS5_CMD_BIND          0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

#define SOCKS5_ATYP_IPV4   0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6   0x04

#define SOCKS5_REP_SUCCEEDED              0x00
#define SOCKS5_REP_GENERAL                0x01
#define SOCKS5_REP_CONN_DISALLOWED        0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE    0x03
#define SOCKS5_REP_HOST_UNREACHABLE       0x04
#define SOCKS5_REP_CONN_REFUSED           0x05
#define SOCKS5_REP_TTL_EXPIRED            0x06
#define SOCKS5_REP_CMD_NOT_SUPPORTED      0x07
#define SOCKS5_REP_ADDRTYPE_NOT_SUPPORTED 0x08
#define SOCKS5_REP_FF_UNASSIGNED          0x09

#include <cstdint>

struct method_select_request {
    uint8_t ver;
    uint8_t nmethods;
    uint8_t methods[0];
} __attribute__ ((aligned (1)));

struct method_select_response {
    uint8_t ver;
    uint8_t method;
} __attribute__ ((aligned (1)));

struct socks5_request {
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    uint8_t dst_var[0];
} __attribute__ ((aligned (1)));

struct socks5_response {
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atyp;
} __attribute__ ((aligned (1)));