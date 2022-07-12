#include "socks5_server.h"
#include "socks5.h"
#include "sockutils.h"
#include <string>

// handle ev signal
void signal_cb(struct ev_loop* loop, ev_signal *w, int revents) {
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
            case SIGUSR1:
            case SIGINT:
            case SIGTERM:
                ev_signal_stop(EV_DEFAULT, &sigint_watcher);
                ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
                ev_signal_stop(EV_DEFAULT, &sigusr1_watcher);
                ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

// close and free socks5 server
static void close_and_free_server(struct ev_loop* loop, server_t* server) {
    if (server->fd > 0) {
        if (server->read_io_ctx) {
            ev_io_stop(loop, &server->read_io_ctx->io);
        }
        server->read_io_ctx = nullptr;
        if (server->write_io_ctx) {
            ev_io_stop(loop, &server->write_io_ctx->io);
        }
        server->write_io_ctx = nullptr;

        close(server->fd);
        //LOG_INFO("close_downstream, server->fd: %i", server->fd);

        if (server->buffer) {
            if (server->buffer->data) {
                free(server->buffer->data);
                server->buffer->data = nullptr;
            }
            free(server->buffer);
            server->buffer = nullptr;
        }
    }
}

// close and free remote connection
static void close_and_free_remote(struct ev_loop* loop, remote_t* remote) {
    if (remote->fd > 0) {
        ev_timer_stop(loop, &remote->connect_timer_watcher);
        if (remote->read_io_ctx) {
            ev_io_stop(loop, &remote->read_io_ctx->io);
        }
        remote->read_io_ctx = nullptr;
        if (remote->write_io_ctx) {
            ev_io_stop(loop, &remote->write_io_ctx->io);
        }
        remote->write_io_ctx = nullptr;
        close(remote->fd);
        //LOG_INFO("close_upstream, server->fd: %i", remote->fd);

        remote->fd = 10000;
        if (remote->buffer) {
            if (remote->buffer->data) {
                free(remote->buffer->data);
                remote->buffer->data = nullptr;
            }
            free(remote->buffer);
            remote->buffer = nullptr;
        }
    }
}

// handle when remote connect() timeout
static void remote_timeout_cb(struct ev_loop* loop, ev_timer *watcher, int) {
    auto *remote = (remote_t*) watcher;
    server_t *server = remote->server;
    LOG_INFO("remote tcp connection timeout");
    close_and_free_remote(loop, remote);
    close_and_free_server(loop, server);
}

// upstream event read
static void remote_read_cb(struct ev_loop* loop, ev_io* watcher, int revents) {
    if (revents == EV_READ) {
        auto* remote_ctx = (remote_ctx_t*) watcher;
        remote_t* remote = remote_ctx->remote;
        if (!remote->connected) {
            return;
        }
        server_t* server = remote->server;
        buffer_t* buffer = remote->buffer;
        int read_n = (int) recv(remote->fd, buffer->data + buffer->len, SOCKET_BUF_SIZE - buffer->len, 0);
        if (read_n == 0) {
            close_and_free_server(loop, server);
            close_and_free_remote(loop, remote);
            return;
        }
        if (read_n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            } else {
                LOG_PERROR("remote_read_cb");
                close_and_free_server(loop, server);
                close_and_free_remote(loop, remote);
                return;
            }
        }
        buffer->len += read_n;
        int relay_back_n = (int) send(server->fd, buffer->data, buffer->len, 0);
        if (relay_back_n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                relay_back_n = 0; // to register ev watcher
            } else {
                LOG_PERROR("relay_back_send");
                close_and_free_server(loop, server);
                close_and_free_remote(loop, remote);
                return;
            }
        }
        if (relay_back_n < buffer->len) {
            // watch ev send
            server->buffer->len = buffer->len - relay_back_n;
            memcpy(server->buffer->data, buffer->data + relay_back_n, server->buffer->len);
            buffer->len = 0;
            ev_io_stop(loop, &remote->read_io_ctx->io);
            ev_io_stop(loop, &server->read_io_ctx->io);  // disable local upstream
            ev_io_start(loop, &server->write_io_ctx->io);// enable local downstream
            return;
        }
        buffer->len = 0;
    }
}

// upstream event write
static void remote_write_cb(struct ev_loop* loop, ev_io* watcher, int wevents) {
    if (wevents == EV_WRITE) {
        auto* remote_ctx = (remote_ctx_t*) watcher;
        remote_t* remote = remote_ctx->remote;
        server_t* server = remote->server;
        if (!remote->connected) {
            struct sockaddr_storage addr{};
            socklen_t len = sizeof addr;
            if (remote->fd > 0) {
                int r = getpeername(remote->fd, (struct sockaddr *) &addr, &len);
                if (r == 0) {
                    ev_timer_stop(loop, &remote->connect_timer_watcher);
                    remote->connected = true;
                    if (remote->buffer->len == 0) {
                        ev_io_stop(loop, &remote->write_io_ctx->io);
                        ev_io_start(loop, &server->read_io_ctx->io);
                        return;
                    }
                    ev_io_start(loop, &remote->read_io_ctx->io);
                    ev_io_start(loop, &server->read_io_ctx->io);
                } else {
                    LOG_PERROR("getpeername");
                    // not connected
                    close_and_free_remote(loop, remote);
                    close_and_free_server(loop, server);
                    return;
                }
            }
        }
        buffer_t *buffer = remote->buffer;
        int write_n = (int) send(remote->fd, buffer->data, buffer->len, 0);
        if (write_n == 0) {
            close_and_free_server(loop, remote->server);
            close_and_free_remote(loop, remote);
            return;
        }
        if (write_n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            } else {
                LOG_PERROR("remote_write_cb");
                close_and_free_server(loop, remote->server);
                close_and_free_remote(loop, remote);
                return;
            }
        }
        if (write_n < buffer->len) {
            buffer->len -= write_n;
            memmove(buffer->data, buffer->data + write_n, buffer->len);
            return;
        }
        // remote upstream all sent
        buffer->len = 0;
        // disable remote upstream io
        ev_io_stop(loop, &remote->write_io_ctx->io);
        // recover remote downstream io
        ev_io_start(loop, &remote->read_io_ctx->io);
    }
}

// socks5 method exchange
static void socks_init(struct ev_loop* loop, server_t* server) {
    buffer_t* buffer = server->buffer;
    auto* request = (method_select_request*) buffer->data;
    if (request->ver != SOCKS_VERSION) { // 只支持socks5
        LOG_WARN("sock ver not supported: %u", (int)request->ver);
        close_and_free_server(loop, server);
        return;
    }
    if (buffer->len < sizeof(method_select_request)) {
        return; // 需要继续等待完整的客户端协议数据
    }
    if (buffer->len < request->nmethods + sizeof(method_select_request)) {
        return; // 需要继续等待完整的客户端协议数据
    }
    method_select_response response = {};
    response.ver = request->ver;
    response.method = SOCKS5_METHOD_UNACCEPTABLE;
    // 只支持no auth
    for (int method_num = 0; method_num < request->nmethods; ++method_num) {
        if (request->methods[method_num] == SOCKS5_METHOD_NOAUTH) {
            response.method = SOCKS5_METHOD_NOAUTH;
            break;
        }
    }
    if (send(server->fd, &response, sizeof(response), 0) != sizeof(response)) {
        LOG_WARN("send method select response failed");
        close_and_free_server(loop, server);
        return;
    }
    if (response.method == SOCKS5_METHOD_UNACCEPTABLE) {
        close_and_free_server(loop, server);
        return;
    }
    server->stage = SOCKS5_STAGE_HANDSHAKE; // 设置为socks握手阶段
    int init_request_len = ((int) request->nmethods + (int) sizeof(method_select_request));
    buffer->len -= init_request_len;
    if (buffer->len > 0) { // 有多余协议字节仍未被解析
        memmove(buffer->data, buffer->data + init_request_len, buffer->len);
    }
}

// socks5 handshake, only support connect command, determine if its ipv4 or domain request
static void socks_handshake(struct ev_loop* loop, server_t* server) {
    buffer_t* buffer = server->buffer;
    auto* request = (socks5_request*) buffer->data;
    if (buffer->len < sizeof(socks5_request)) {
        return; // wait util entire request stream
    }
    if (request->cmd == SOCKS5_CMD_CONNECT) {
        sockaddr_in remote_addr{};
        if (request->atyp == SOCKS5_ATYP_IPV4) {
            int request_len = int(sizeof(socks5_request) + IPV4_INADDR_LEN + PORT_LEN);
            if (buffer->len < request_len) {
                return; // wait util entire request stream
            }
            char ipv4_addr_name[INET_ADDRSTRLEN];
            memset(ipv4_addr_name, 0, sizeof(ipv4_addr_name));
            char* ipv4_addr_ptr = buffer->data + sizeof(socks5_request);
            char* port_ptr = buffer->data + sizeof(socks5_request) + IPV4_INADDR_LEN;
            uint16_t remote_port = *(uint16_t *) port_ptr;
            inet_ntop(AF_INET, ipv4_addr_ptr, ipv4_addr_name, sizeof(ipv4_addr_name));
            LOG_INFO("upstream -> %s:%u", ipv4_addr_name, ntohs(remote_port));
            remote_addr.sin_family = AF_INET;
            remote_addr.sin_port = remote_port;
            memcpy(&remote_addr.sin_addr.s_addr, ipv4_addr_ptr, sizeof(in_addr_t));
            buffer->len -= request_len;
            if (buffer->len > 0) {
                memmove(buffer->data, buffer->data + request_len, buffer->len);
            }
        } else if (request->atyp == SOCKS5_ATYP_DOMAIN) {
            auto domain_name_len = (int8_t)request->dst_var[0];
            int domain_connect_len = int(sizeof(socks5_request) + 1 + domain_name_len + 2);
            if (buffer->len < domain_connect_len) {
                return; // wait util entire request stream
            }
            char domain_name[domain_name_len+1];
            domain_name[domain_name_len] = '\0';
            uint16_t nport_num = *(uint16_t *) &request->dst_var[domain_name_len + 1];
            memcpy(domain_name, &request->dst_var[1], domain_name_len);
            if (resolve_hostname(domain_name, &remote_addr) == -1) {
                LOG_ERROR("resolve hostname failure, fd:%i domain:%s", server->fd, domain_name);
                close_and_free_server(loop, server);
                return;
            }
            remote_addr.sin_port = nport_num;
            char ipv4_addr_name[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &remote_addr.sin_addr, ipv4_addr_name, sizeof(ipv4_addr_name));
            LOG_INFO("upstream -> %s(%s):%u", domain_name, ipv4_addr_name, ntohs(nport_num));
            buffer->len -= domain_connect_len;
            if (buffer->len > 0) {
                memmove(buffer->data, buffer->data + domain_connect_len, buffer->len);
            }
        } else if (request->atyp == SOCKS5_ATYP_IPV6) {
            close_and_free_server(loop, server);
            LOG_ERROR("does not support ipv6 fd:%i", server->fd);
            return;
        }
        // create remote socket
        if ((server->remote->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            close_and_free_server(loop, server);
            return;
        }
        // reply to client fake handshake response, which always succeed
        sockaddr_in fake {};
        memset(&fake, 0, sizeof(fake));
        char response_buff[1024];
        socks5_response response = {};
        response.ver = SOCKS_VERSION;
        response.rep = SOCKS5_REP_SUCCEEDED;
        response.rsv = 0x00;
        response.atyp = SOCKS5_ATYP_IPV4; // only support remote ipv4 right now
        memcpy(response_buff, &response, sizeof(socks5_response));
        memcpy(response_buff + sizeof(socks5_response), &fake.sin_addr, IPV4_INADDR_LEN);
        memcpy(response_buff + sizeof(socks5_response) + IPV4_INADDR_LEN, &fake.sin_port, sizeof(fake.sin_port));
        int reply_size = sizeof(struct socks5_response) + IPV4_INADDR_LEN + sizeof(fake.sin_port);
        int send_size = (int) send(server->fd, response_buff, reply_size, 0);
        if (send_size < reply_size) {
            LOG_ERROR("handshake failure fd:%i", server->fd);
            close_and_free_server(loop, server);
            return;
        }
        sock_set_nonblock(server->remote->fd);
        memcpy(&(server->remote->addr), &remote_addr, sizeof(remote_addr));
        server->remote->addr_len = sizeof(remote_addr);
        server->stage = SOCKS5_STAGE_STREAM;
        ev_io_init(&server->remote->read_io_ctx->io, remote_read_cb, server->remote->fd, EV_READ);
        ev_io_init(&server->remote->write_io_ctx->io, remote_write_cb, server->remote->fd, EV_WRITE);
        ev_io_start(loop, &server->remote->read_io_ctx->io);
    } else {
        close_and_free_server(loop, server);
        close_and_free_remote(loop, server->remote);
        LOG_WARN("only support socks5 connect command, client_request_cmd:%c", request->cmd);
    }
}

// socks5 upstream to remote server
static void socks_stream(struct ev_loop* loop, server_t* server) {
    remote_t* remote = server->remote;
    buffer_t* buffer = remote->buffer;
    // append server buffer -> remote buffer
    if (buffer->len + server->buffer->len > SOCKET_BUF_SIZE) {
        buffer->data = (char*) realloc(buffer->data, buffer->len + server->buffer->len);
    }
    memcpy(buffer->data + buffer->len, server->buffer->data, server->buffer->len);
    buffer->len += server->buffer->len;
    // reset server buffer
    server->buffer->len = 0;
    if (!remote->connected) {
        int conn_ret = connect(remote->fd,(sockaddr*)& remote->addr, remote->addr_len);
        if (conn_ret == 0) {
            server->remote->connected = true;
            return;
        } else if (conn_ret == -1) {
            if (errno != EINPROGRESS) {
                LOG_PERROR("connect remote");
                close_and_free_server(loop, server);
                close_and_free_remote(loop, server->remote);
                return;
            } else {
                ev_timer_start(loop, &remote->connect_timer_watcher);
                ev_io_stop(loop, &server->read_io_ctx->io);
                ev_io_start(loop, &remote->write_io_ctx->io);
                return;
            }
        }
    }
    // relay data stream to remote dst
    int send_n = (int) send(remote->fd, buffer->data, buffer->len, MSG_NOSIGNAL);
    if (send_n == 0) {
        // nonblock socket should close when send_n==0
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
        return;
    }
    // otherwise cannot be sent or not all sent yet
    if (send_n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            send_n = 0; // watch upstream ev watch
        } else {
            LOG_PERROR("relay to remote stream");
            close_and_free_server(loop, server);
            close_and_free_remote(loop, remote);
        }
    }
    if (send_n < buffer->len) {
        buffer->len -= send_n;
        memmove(buffer->data, buffer->data + send_n, buffer->len);
        ev_io_stop(loop, &remote->read_io_ctx->io);   // disable remote down stream watcher
        ev_io_start(loop, &remote->write_io_ctx->io); // enable remote up stream watcher
        return;
    }
    // all relay buffer has been sent
    buffer->len = 0;
    // so we can start watch remote read io
    ev_io_start(loop, &remote->read_io_ctx->io);
}

// socks5 event read
static void socks_read_cb(struct ev_loop* loop, ev_io* watcher, int revents) {
    if (revents == EV_READ) {
        auto *server_ctx = (server_ctx_t*) watcher;
        buffer_t* buff = server_ctx->server->buffer;
        server_t* server = server_ctx->server;
        ssize_t read_n = recv(watcher->fd, buff->data + buff->len, SOCKET_BUF_SIZE - buff->len, 0);
        if (read_n == 0) { // nonblock socket收到0, 关闭连接
            close_and_free_server(loop, server_ctx->server);
            close_and_free_remote(loop, server->remote);
            return;
        }
        if (read_n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            } else {
                LOG_PERROR("read_cb");
                close_and_free_server(loop, server_ctx->server);
                close_and_free_remote(loop, server->remote);
                return;
            }
        }
        buff->len += (int) read_n;
        // socks5协议解码
        while (true) {
            switch (server->stage) {
                case SOCKS5_STAGE_INIT: {
                    socks_init(loop, server);
                    return;
                }
                case SOCKS5_STAGE_HANDSHAKE: {
                    socks_handshake(loop, server);
                    return;
                }
                case SOCKS5_STAGE_STREAM: {
                    socks_stream(loop, server);
                    return;
                }
            }
        }
    }
}

// socks5 event write
static void socks_write_cb(struct ev_loop* loop, ev_io* watcher, int wevents) {
    if (wevents == EV_WRITE) {
        auto *server_ctx = (server_ctx_t *) watcher;
        server_t *server = server_ctx->server;
        remote_t *remote = server->remote;
        buffer_t* buffer = server->buffer;
        int send_n = (int) send(server->fd, buffer->data, buffer->len, 0);
        if (send_n == 0) {
            close_and_free_server(loop, server);
            close_and_free_remote(loop, remote);
            return;
        }
        if (send_n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            } else {
                LOG_PERROR("sock_write_cb");
                close_and_free_server(loop, server);
                close_and_free_remote(loop, remote);
                return;
            }
        }
        if (send_n < buffer->len) {
            buffer->len -= send_n;
            memmove(buffer->data, buffer->data + send_n, buffer->len);
            return;
        }
        // downstream all sent
        buffer->len = 0;
        ev_io_stop(loop, &server->write_io_ctx->io); // disable local downstrea
        ev_io_start(loop, &remote->read_io_ctx->io);
        ev_io_start(loop, &server->read_io_ctx->io); // recover local upstream
    }
}

void socks_accept_cb(struct ev_loop* loop, ev_io* watcher, int revents) {
    if (revents & EV_READ) {
        struct sockaddr addr = {};
        socklen_t addr_len = sizeof(addr);
        int client_fd = accept(watcher->fd, &addr, &addr_len);
        if (client_fd == -1) {
            LOG_PERROR("accept client failure");
            return;
        }
        // 设置读写监听，创建local和remote context
        auto* server = static_cast<server_t*>(malloc(sizeof(remote_t)));
        server->fd = client_fd;
        server->stage = SOCKS5_STAGE_INIT;
        server->buffer = static_cast<buffer_t *>(malloc(sizeof(buffer_t)));
        server->buffer->data = static_cast<char *>(malloc(SOCKET_BUF_SIZE));
        server->buffer->len = 0;
        server->read_io_ctx = static_cast<server_ctx_t *>(malloc(sizeof(server_ctx_t)));
        server->read_io_ctx->server = server;
        server->write_io_ctx = static_cast<server_ctx_t *>(malloc(sizeof(server_ctx_t)));
        server->write_io_ctx->server = server;
        sock_set_nonblock(client_fd); // 设置nonblock

        auto* remote = static_cast<remote_t*>(malloc(sizeof(remote_t)));
        remote->fd = -1;
        remote->connected = false;
        remote->buffer = static_cast<buffer_t *>(malloc(sizeof(buffer_t)));
        remote->buffer->data = static_cast<char *>(malloc(SOCKET_BUF_SIZE));
        remote->buffer->len = 0;
        remote->read_io_ctx = static_cast<remote_ctx_t *>(malloc(sizeof(remote_ctx_t)));
        remote->read_io_ctx->remote = remote;
        remote->write_io_ctx = static_cast<remote_ctx_t *>(malloc(sizeof(remote_ctx_t)));
        remote->write_io_ctx->remote = remote;
        server->remote = remote;
        remote->server = server;

        ev_timer_init(&remote->connect_timer_watcher, remote_timeout_cb, CONNECT_TIMEOUT, 0);
        ev_io_init(&server->read_io_ctx->io, socks_read_cb, client_fd, EV_READ);
        ev_io_init(&server->write_io_ctx->io, socks_write_cb, client_fd, EV_WRITE);
        ev_io_start(loop, &server->read_io_ctx->io);
    }
}