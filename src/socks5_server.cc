#include "socks5_server.h"
#include "socks5.h"
#include "sockutils.h"
#include <string>
#include <chrono>
#include <iostream>

// handle ev signal
void signal_cb(struct ev_loop* loop, ev_signal *w, int revents) {
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
            case SIGUSR1:
            case SIGINT:
            case SIGTERM:
                LOG_INFO("signal term received");
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
    }
    if (server->buffer) {
        if (server->buffer->data) {
            free(server->buffer->data);
            server->buffer->data = nullptr;
        }
        free(server->buffer);
        server->buffer = nullptr;
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
    }
    if (remote->buffer) {
        if (remote->buffer->data) {
            free(remote->buffer->data);
            remote->buffer->data = nullptr;
        }
        free(remote->buffer);
        remote->buffer = nullptr;
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
        int read_n = (int) recv(remote->fd, remote->buffer->data + remote->buffer->len, SOCKET_BUF_SIZE - remote->buffer->len, 0);
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
        remote->buffer->len += read_n;
        int relay_back_n = (int) send(server->fd, remote->buffer->data, remote->buffer->len, 0);
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
        if (relay_back_n < remote->buffer->len) {
            // watch ev send
            remote->buffer->len -= relay_back_n;
            memmove(remote->buffer->data, remote->buffer->data + relay_back_n, remote->buffer->len);
            ev_io_stop(loop, &remote->read_io_ctx->io);
            ev_io_start(loop, &server->write_io_ctx->io);
            return;
        }
        remote->buffer->len = 0;
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
                    if (server->buffer->len == 0) {
                        ev_io_stop(loop, &remote->write_io_ctx->io);
                        // continue downstream read
                        ev_io_start(loop, &server->read_io_ctx->io);
                        return;
                    }
                } else {
                    LOG_PERROR("getpeername");
                    // not connected
                    close_and_free_remote(loop, remote);
                    close_and_free_server(loop, server);
                    return;
                }
            }
        }
        int write_n = (int) send(remote->fd, server->buffer->data, server->buffer->len, 0);
        if (write_n == 0) {
            close_and_free_server(loop, server);
            close_and_free_remote(loop, remote);
            return;
        }
        if (write_n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            } else {
                LOG_PERROR("remote_write_cb");
                close_and_free_server(loop, server);
                close_and_free_remote(loop, remote);
                return;
            }
        }
        if (write_n < server->buffer->len) {
            server->buffer->len -= write_n;
            memmove(server->buffer->data, server->buffer->data + write_n, server->buffer->len);
            return;
        }
        // remote upstream all sent
        server->buffer->len = 0;
        ev_io_stop(loop, &remote->write_io_ctx->io);
        ev_io_start(loop, &server->read_io_ctx->io);
    }
}

// socks5 method exchange
static void socks_init(struct ev_loop* loop, server_t* server) {
    buffer_t* buffer = server->buffer;
    remote_t* remote = server->remote;
    auto* request = (method_select_request*) buffer->data;
    if (request->ver != SOCKS_VERSION) { // 只支持socks5
        LOG_WARN("sock ver not supported: %u", (int)request->ver);
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
        return;
    }
    if (buffer->len < sizeof(method_select_request)) {
        return; // wait util entire request streamed
    }
    if (buffer->len < request->nmethods + sizeof(method_select_request)) {
        return; // wait util entire request streamed
    }
    method_select_response response {};
    response.ver = request->ver;
    response.method = SOCKS5_METHOD_UNACCEPTABLE;
    // support no auth only
    for (int method_num = 0; method_num < request->nmethods; ++method_num) {
        if (request->methods[method_num] == SOCKS5_METHOD_NOAUTH) {
            response.method = SOCKS5_METHOD_NOAUTH; // no auth method found
            break;
        }
    }
    if (send(server->fd, &response, sizeof(response), 0) != sizeof(response)) {
        LOG_WARN("send method select response failed");
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
        return;
    }
    if (response.method == SOCKS5_METHOD_UNACCEPTABLE) {
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
        return;
    }
    // socks5 init completed, so set socks5 stage to handshake
    server->stage = SOCKS5_STAGE_HANDSHAKE;
    // socks5 init request total bytes
    int init_request_len = ((int) request->nmethods + (int) sizeof(method_select_request));
    buffer->len -= init_request_len;
    if (buffer->len > 0) {
        // extra bytes of the next request, move it to the front
        memmove(buffer->data, buffer->data + init_request_len, buffer->len);
    }
}

// socks5 handshake, only support connect command, determine if its ipv4 or domain request
static void socks_handshake(struct ev_loop* loop, server_t* server) {
    buffer_t* buffer = server->buffer;
    remote_t* remote = server->remote;
    auto* request = (socks5_request*) buffer->data;
    if (buffer->len < sizeof(socks5_request)) {
        return; // wait util entire request stream
    }
    if (request->cmd == SOCKS5_CMD_CONNECT) {
        sockaddr_in remote_addr {};
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
            memcpy(&remote_addr.sin_addr.s_addr, ipv4_addr_ptr, sizeof(in_addr));
            buffer->len -= request_len;
            if (buffer->len > 0) {
                // move extra bytes to the front
                memmove(buffer->data, buffer->data + request_len, buffer->len);
            }
        } else if (request->atyp == SOCKS5_ATYP_DOMAIN) {
            // first byte of the request indicate the domain length
            auto domain_name_len = (int8_t)request->dst_var[0];
            int domain_connect_len = int(sizeof(socks5_request) + 1 + domain_name_len + 2);
            if (buffer->len < domain_connect_len) {
                return; // wait util entire request stream
            }
            char domain_name[domain_name_len+1];
            domain_name[domain_name_len] = '\0';
            uint16_t nport_num = *(uint16_t *) &request->dst_var[domain_name_len + 1];
            memcpy(domain_name, &request->dst_var[1], domain_name_len);

            auto start = std::chrono::system_clock::now();
            if (resolve_hostname(domain_name, &remote_addr) == -1) {
                LOG_ERROR("resolve hostname failure, fd:%i domain:%s", server->fd, domain_name);
                close_and_free_server(loop, server);
                close_and_free_remote(loop, remote);
                return;
            }
            auto end = std::chrono::system_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            double sec = double(duration.count()) * std::chrono::microseconds::period::num / std::chrono::microseconds::period::den;
            if (sec > 1) {
                LOG_WARN("dns resolve costs: %f", sec);
            }
            remote_addr.sin_port = nport_num;
            char ipv4_addr_name[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &remote_addr.sin_addr, ipv4_addr_name, sizeof(ipv4_addr_name));
            LOG_INFO("upstream -> %s(%s):%u", domain_name, ipv4_addr_name, ntohs(nport_num));
            buffer->len -= domain_connect_len;
            if (buffer->len > 0) {
                // move extra bytes to the front
                memmove(buffer->data, buffer->data + domain_connect_len, buffer->len);
            }
        } else if (request->atyp == SOCKS5_ATYP_IPV6) {
            close_and_free_server(loop, server);
            close_and_free_remote(loop, remote);
            LOG_ERROR("does not support ipv6 fd:%i", server->fd);
            return;
        }
        // create remote socket
        if ((server->remote->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            close_and_free_server(loop, server);
            close_and_free_remote(loop, remote);
            return;
        }
        // reply to client fake handshake response, which always succeed
        sockaddr_in fake {};
        memset(&fake, 0, sizeof(fake));
        int reply_size = sizeof(struct socks5_response) + IPV4_INADDR_LEN + sizeof(fake.sin_port);
        char response_buff[reply_size];
        socks5_response response = {};
        response.ver = SOCKS_VERSION;
        response.rep = SOCKS5_REP_SUCCEEDED;
        response.rsv = 0x00;
        response.atyp = SOCKS5_ATYP_IPV4; // only support remote ipv4 right now
        memcpy(response_buff, &response, sizeof(socks5_response));
        memcpy(response_buff + sizeof(socks5_response), &fake.sin_addr, IPV4_INADDR_LEN);
        memcpy(response_buff + sizeof(socks5_response) + IPV4_INADDR_LEN, &fake.sin_port, sizeof(fake.sin_port));
        int send_size = (int) send(server->fd, response_buff, reply_size, 0);
        if (send_size < reply_size) {
            LOG_ERROR("handshake failure fd:%i", server->fd);
            close_and_free_server(loop, server);
            close_and_free_remote(loop, remote);
            return;
        }
#ifdef SO_NOSIGPIPE // MACOS has this
        int opt = 1;
        setsockopt(server->remote->fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        sock_set_nonblock(server->remote->fd);
        memcpy(&(server->remote->addr), &remote_addr, sizeof(remote_addr));
        server->remote->addr_len = sizeof(remote_addr);
        server->stage = SOCKS5_STAGE_STREAM; // set to socks5 stream stage
        // init remote io
        ev_io_init(&server->remote->read_io_ctx->io, remote_read_cb, server->remote->fd, EV_READ);
        ev_io_init(&server->remote->write_io_ctx->io, remote_write_cb, server->remote->fd, EV_WRITE);
        ev_io_start(loop, &server->remote->read_io_ctx->io);
    } else {
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
        LOG_WARN("only support socks5 connect command, client_request_cmd:%c", request->cmd);
    }
}

// socks5 upstream to remote server
static void socks_stream(struct ev_loop* loop, server_t* server) {
    remote_t* remote = server->remote;
    if (!remote->connected) {
        int conn_ret = connect(remote->fd,(sockaddr*)& remote->addr, remote->addr_len);
        if (conn_ret == 0) {
            // immediately connected
            server->remote->connected = true;
        } else if (conn_ret == -1) {
            if (errno != EINPROGRESS) {
                LOG_PERROR("connect remote");
                close_and_free_server(loop, server);
                close_and_free_remote(loop, remote);
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
    int send_n = (int) send(remote->fd, server->buffer->data, server->buffer->len, 0);
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
            return;
        }
    }
    if (send_n < server->buffer->len) {
        server->buffer->len -= send_n;
        memmove(server->buffer->data, server->buffer->data + send_n, server->buffer->len);
        ev_io_stop(loop, &server->read_io_ctx->io);   // disable socks5 downstream read
        ev_io_start(loop, &remote->write_io_ctx->io); // enable remote up stream watcher
        return;
    }
    // all relay buffer has been sent
    server->buffer->len = 0;
    // so we can start watch remote read io
    ev_io_start(loop, &remote->read_io_ctx->io);
}

// socks5 event read
static void socks_read_cb(struct ev_loop* loop, ev_io* watcher, int revents) {
    if (revents == EV_READ) {
        auto *server_ctx = (server_ctx_t*) watcher;
        buffer_t* buff = server_ctx->server->buffer;
        server_t* server = server_ctx->server;
        remote_t* remote = server->remote;
        ssize_t read_n = recv(watcher->fd, buff->data + buff->len, SOCKET_BUF_SIZE - buff->len, 0);
        if (read_n == 0) { // socks5 client closed
            close_and_free_server(loop, server);
            close_and_free_remote(loop, remote);
            return;
        }
        if (read_n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // nonblock socket means it's not ready, but there's no error
                return;
            } else {
                LOG_PERROR("read_cb");
                close_and_free_server(loop, server);
                close_and_free_remote(loop, remote);
                return;
            }
        }
        // increment received buffer length
        buff->len += (int) read_n;

        // handle socks5 protocol
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
        int send_n = (int) send(server->fd, remote->buffer->data, remote->buffer->len, 0);
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
        if (send_n < remote->buffer->len) {
            remote->buffer->len -= send_n;
            memmove(remote->buffer->data, remote->buffer->data + send_n, remote->buffer->len);
            return;
        }
        // downstream all sent
        remote->buffer->len = 0;
        ev_io_stop(loop, &server->write_io_ctx->io);
        ev_io_start(loop, &remote->read_io_ctx->io);
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
        } else {
            LOG_INFO("accept fd:%i", client_fd);
        }
        // create server and remote context
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
        sock_set_nonblock(client_fd); // set nonblock socket so we can be event driven

        auto* remote = static_cast<remote_t*>(malloc(sizeof(remote_t)));
        remote->fd = -1; // will be created in the future
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

        // watch remote connect() timeout
        ev_timer_init(&remote->connect_timer_watcher, remote_timeout_cb, CONNECT_TIMEOUT, 0);
        ev_io_init(&server->read_io_ctx->io, socks_read_cb, client_fd, EV_READ);
        ev_io_init(&server->write_io_ctx->io, socks_write_cb, client_fd, EV_WRITE);
        ev_io_start(loop, &server->read_io_ctx->io);
    }
}

void socks5_server_run(const char* server_host, const char* server_port) {
    struct ev_loop *loop = EV_DEFAULT;

    // create socks5 server socket
    int listen_fd = sock_create_bind(server_host, server_port);

    sock_set_nonblock(listen_fd);
    LOG_INFO("socks server listening on: %s:%s", server_host, server_port);
    sock_listening(listen_fd);
    ev_signal_init(&sigusr1_watcher, signal_cb, SIGUSR1);
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigusr1_watcher);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    struct ev_io listen_ev_io = {};
    ev_io_init(&listen_ev_io, socks_accept_cb, listen_fd, EV_READ);
    ev_io_start(loop, &listen_ev_io);
    ev_loop(loop, 0);
}
