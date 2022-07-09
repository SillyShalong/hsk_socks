#pragma once

#include <ev.h>

#define SOCKET_BUF_SIZE (16 * 1024 - 1) // 16383 Byte, equals to the max chunk size
#define SOCKS5_STAGE_INIT 0
#define SOCKS5_STAGE_HANDSHAKE 1
#define SOCKS5_STAGE_STREAM 2

struct remote_t;
struct server_t;

struct buffer_t {
    int len;
    char* data;
};

struct server_ctx_t {
    ev_io io;
    server_t* server;
};

struct remote_ctx_t {
    ev_io io;
    remote_t* remote;
};

struct server_t {
    int fd;
    int stage;
    buffer_t* buffer;
    server_ctx_t* read_io_ctx;
    server_ctx_t* write_io_ctx;
    remote_t* remote;
};

struct remote_t {
    int fd;
    buffer_t* buffer;
    remote_ctx_t* read_io_ctx;
    remote_ctx_t* write_io_ctx;
    server_t* server;
};





