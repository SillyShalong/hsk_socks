#pragma once

#include <ev.h>
#include "sockutils.h"
#include "util.h"
#include "csignal"

#define SOCKET_BUF_SIZE (16 * 1024 - 1) // 16383 Byte, equals to the max chunk size

#define SOCKS5_STAGE_INIT 0
#define SOCKS5_STAGE_HANDSHAKE 1
#define SOCKS5_STAGE_STREAM 2

#define IPV4_INADDR_LEN (socklen_t) sizeof(in_addr)
#define PORT_LEN (uint16_t) sizeof(in_port_t)
#define CONNECT_TIMEOUT 10

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
    ev_timer connect_timer_watcher;
    int fd;
    bool connected;
    buffer_t* buffer;
    remote_ctx_t* read_io_ctx;
    remote_ctx_t* write_io_ctx;
    server_t* server;
    sockaddr_storage addr;
    socklen_t addr_len;
};

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigusr1_watcher;

void signal_cb(struct ev_loop* loop, ev_signal *w, int revents);

void socks_accept_cb(struct ev_loop* loop, ev_io* watcher, int revents);

void socks5_server_run(const char* server_host, const char* server_port);


