#include "socks5_server.h"
#include <iostream>
#include <string>
#include "socks5.h"
#include "sockutils.h"
#include <cassert>

using std::cout;
using std::endl;

static void remote_read_cb(struct ev_loop* loop, ev_io* watcher, int revents);
static void remote_write_cb(struct ev_loop* loop, ev_io* watcher, int wevents);

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigchld_watcher;
static struct ev_signal sigusr1_watcher;


static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
#ifndef __MINGW32__
//            case SIGCHLD:
//                if (!is_plugin_running()) {
//                    LOGE("plugin service exit unexpectedly");
//                    ret_val = -1;
//                } else
//                    return;
            case SIGUSR1:
#endif
            case SIGINT:
            case SIGTERM:
                ev_signal_stop(EV_DEFAULT, &sigint_watcher);
                ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
                ev_signal_stop(EV_DEFAULT, &sigchld_watcher);
                ev_signal_stop(EV_DEFAULT, &sigusr1_watcher);
#else
                #ifndef LIB_ONLY
            ev_io_stop(EV_DEFAULT, &plugin_watcher.io);
#endif
#endif
                ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

static void close_and_free_server(struct ev_loop* loop, server_t* server) {
    //std::cout << "close_and_free_server, server->fd: " << server->fd << std::endl;
    if (server->read_io_ctx) {
        ev_io_stop(loop, &server->read_io_ctx->io);
    }
    server->read_io_ctx = nullptr;
    if (server->write_io_ctx) {
        ev_io_stop(loop, &server->write_io_ctx->io);
    }
    server->write_io_ctx = nullptr;
    if (server->fd > 0) {
        close(server->fd);
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

static void close_and_free_remote(struct ev_loop* loop, remote_t* remote) {
    //std::cout << "close_and_free_remote, remote->fd: " << remote->fd << std::endl;
    if (remote->read_io_ctx) {
        ev_io_stop(loop, &remote->read_io_ctx->io);
    }
    if (remote->write_io_ctx) {
        ev_io_stop(loop, &remote->write_io_ctx->io);
    }
    if (remote->fd > 0) {
        close(remote->fd);
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

// socks5 method交换
static void socks_init(struct ev_loop* loop, server_t* server) {
    buffer_t* buffer = server->buffer;
    auto* request = (method_select_request*) buffer->data;
    if (request->ver != SVERSION) { // 只支持socks5
        std::cerr << "sock ver not supported: " << (int)request->ver << std::endl;
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
    response.method = METHOD_UNACCEPTABLE;
    // 只支持no auth
    for (int method_num = 0; method_num < request->nmethods; ++method_num) {
        if (request->methods[method_num] == METHOD_NOAUTH) {
            response.method = METHOD_NOAUTH;
            break;
        }
    }
    if (send(server->fd, &response, sizeof(response), 0) != sizeof(response)) {
        std::cerr << "send method select response failed: " << std::endl;
        close_and_free_server(loop, server);
        return;
    }
    if (response.method == METHOD_UNACCEPTABLE) {
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

// socks5 握手
static void socks_handshake(struct ev_loop* loop, server_t* server) {
    buffer_t* buffer = server->buffer;
    auto* request = (socks5_request*) buffer->data;
    if (buffer->len < sizeof(socks5_request)) {
        return; // 需要继续等待完整的客户端协议数据
    }
    if (request->cmd == SOCKS5_CMD_CONNECT) {
        uint16_t dst_port;
        sockaddr_in remote_addr = {};
        if (request->atyp == SOCKS5_ATYP_IPV4) {
            int ipv4_addr_len = sizeof(in_addr);
            int ipv4_dst_connect = int(sizeof(socks5_request) + ipv4_addr_len + 2);
            if (buffer->len < ipv4_dst_connect) {
                return; // 需要继续等待完整的客户端协议数据
            }
            char ipv4_addr_name[16];
            memset(ipv4_addr_name, 0, sizeof(ipv4_addr_name));
            char* ipv4_addr_ptr = buffer->data + sizeof(socks5_request);
            char* port_ptr = buffer->data + sizeof(socks5_request) + ipv4_addr_len;
            dst_port = *(uint16_t *) port_ptr;
            inet_ntop(AF_INET, ipv4_addr_ptr, ipv4_addr_name, INET_ADDRSTRLEN);
            sockaddr_in sock_addr = {};
            memset(&sock_addr, 0, sizeof(sockaddr_in));
            char response_buff[1024];
            socks5_response response = {};
            response.ver = SVERSION;
            response.rep = SOCKS5_REP_SUCCEEDED;
            response.rsv = 0x00;
            response.atyp = request->atyp;
            memcpy(response_buff, &response, sizeof(socks5_response));
            memcpy(response_buff + sizeof(socks5_response), &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
            memcpy(response_buff + sizeof(socks5_response) + sizeof(sock_addr.sin_addr), &sock_addr.sin_port, sizeof(sock_addr.sin_port));
            int reply_size = sizeof(struct socks5_response) + sizeof(sock_addr.sin_addr) + sizeof(sock_addr.sin_port);
            int send_size = (int) send(server->fd, response_buff, reply_size, 0);
            if (send_size < reply_size) {
                std::cerr << "handshake failure" << endl;
                close_and_free_server(loop, server);
                return;
            }
            remote_addr.sin_family = AF_INET;
            remote_addr.sin_port = dst_port;
            memcpy(&remote_addr.sin_addr.s_addr, ipv4_addr_ptr, sizeof(in_addr_t));
            buffer->len -= ipv4_dst_connect;
            if (buffer->len > 0) {
                memmove(buffer->data, buffer->data + ipv4_dst_connect, buffer->len);
            }
        } else if (request->atyp == SOCKS5_ATYP_DOMAIN) {
            int8_t domain_name_len = request->dst_var[0];
            int domain_connect_len = int(sizeof(socks5_request) + 1 + domain_name_len + 2);
            if (buffer->len < domain_connect_len) {
                return; // 需要继续等待完整的客户端协议数据
            }
            char domain_name[domain_name_len+1];
            domain_name[domain_name_len] = '\0';
            uint16_t port_num = ntohs(*(uint16_t *) &request->dst_var[domain_name_len + 1]);
            memcpy(domain_name, &request->dst_var[1], domain_name_len);
            if (resolve_hostname(domain_name, &remote_addr) == -1) {
                std::cerr << "resolve hostname failure: " << domain_name << std::endl;
                close_and_free_server(loop, server);
                close_and_free_remote(loop, server->remote);
                return;
            }
            remote_addr.sin_port = htons(port_num);
            char ipbuf[16];
            cout << "dst host: " << domain_name << "(" << inet_ntop(AF_INET, &remote_addr.sin_addr, ipbuf, 16) << ")" << " dst port: " << port_num << " ";
            // reply to client fake
            sockaddr_in fake {};
            memset(&fake, 0, sizeof(fake));
            char response_buff[1024];
            socks5_response response = {};
            response.ver = SVERSION;
            response.rep = SOCKS5_REP_SUCCEEDED;
            response.rsv = 0x00;
            response.atyp = SOCKS5_ATYP_IPV4;
            memcpy(response_buff, &response, sizeof(socks5_response));
            memcpy(response_buff + sizeof(socks5_response), &fake.sin_addr, sizeof(fake.sin_addr));
            memcpy(response_buff + sizeof(socks5_response) + sizeof(fake.sin_addr), &fake.sin_port, sizeof(fake.sin_port));
            int reply_size = sizeof(struct socks5_response) + sizeof(fake.sin_addr) + sizeof(fake.sin_port);
            int send_size = (int) send(server->fd, response_buff, reply_size, 0);
            if (send_size < reply_size) {
                std::cerr << "handshake failure" << endl;
                close_and_free_server(loop, server);
                return;
            }
            buffer->len -= domain_connect_len;
            if (buffer->len > 0) {
                memmove(buffer->data, buffer->data + domain_connect_len, buffer->len);
            }
        } else if (request->atyp == SOCKS5_ATYP_IPV6) {
            std::cerr << "does not support ipv6 yet" << std::endl;
            return;
        }

        // TODO connect
        // 开启sockserver 和 remote server的通道
        if ((server->remote->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            close_and_free_server(loop, server);
        }
        socklen_t sock_len = sizeof(sockaddr_in);
        cout << "start connect" << endl;
        if (connect(server->remote->fd, reinterpret_cast<struct sockaddr *>(&remote_addr), sock_len) == -1) {
            perror("connect remote");
            close_and_free_server(loop, server);
            close_and_free_remote(loop, server->remote);
            return;
        } else {
            std::cout << "connected" << std::endl;
        }
        sock_set_nonblock(server->remote->fd);


        server->stage = SOCKS5_STAGE_STREAM;
        ev_io_init(&server->remote->read_io_ctx->io, remote_read_cb, server->remote->fd, EV_READ);
        ev_io_init(&server->remote->write_io_ctx->io, remote_write_cb, server->remote->fd, EV_WRITE);
        ev_io_start(loop, &server->remote->read_io_ctx->io);
    } else {
        throw std::runtime_error(std::string ("only support socks5 connect command: ") + std::to_string((int)request->cmd));
    }
}

// socks5 upstream to remote server
static void socks_stream(struct ev_loop* loop, server_t* server) {
    remote_t* remote = server->remote;
    buffer_t* buffer = remote->buffer;
    // append server buffer -> remote buffer
//    print_data(server->buffer->data, server->buffer->len);
    if (buffer->len + server->buffer->len > SOCKET_BUF_SIZE) {
        std::cout << "shit" << std::endl;
    }
    memcpy(buffer->data + buffer->len, server->buffer->data, server->buffer->len);
    buffer->len += server->buffer->len;
    // reset server buffer
    server->buffer->len = 0;
    // relay data stream to remote dst
    int send_n = (int) send(remote->fd, buffer->data, buffer->len, 0);
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
            perror("relay to remote stream");
            close_and_free_server(loop, server);
            close_and_free_remote(loop, remote);
        }
    }
    if (send_n < buffer->len) {
        std::cout << "upstream: send buffer len: " << send_n << " < " << buffer->len << std::endl;
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

static void sock_read_cb(struct ev_loop* loop, ev_io* watcher, int revents) {
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
                perror("read_cb");
                close_and_free_server(loop, server_ctx->server);
                close_and_free_remote(loop, server->remote);
                return;
            }
        }
        buff->len += (int) read_n;
        // socks5协议解码
        while (true) {
            switch (server->stage) {
                case 0: {
                    socks_init(loop, server);
                    return;
                }
                case 1: {
                    //export_bin(buff->data, buff->len);
                    socks_handshake(loop, server);
                    return;
                }
                case 2: {// stream
                    socks_stream(loop, server);
                    return;
                }
            }
        }
    }
}

static void sock_write_cb(struct ev_loop* loop, ev_io* watcher, int wevents) {
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
                perror("sock_write_cb");
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

static void sock_accept_cb(struct ev_loop* loop, ev_io* watcher, int revents) {
    if (revents & EV_READ) {
        struct sockaddr addr = {};
        socklen_t addr_len = sizeof(addr);
        int client_fd = accept(watcher->fd, &addr, &addr_len);
        if (client_fd == -1) {
            perror("accept client failure");
            return;
        }
        //std::cout << "accept client: " << client_fd << std::endl;
        // 设置读写监听，创建local和remote context
        auto* server = static_cast<server_t*>(malloc(sizeof(remote_t)));
        server->fd = client_fd;
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
        remote->buffer = static_cast<buffer_t *>(malloc(sizeof(buffer_t)));
        remote->buffer->data = static_cast<char *>(malloc(SOCKET_BUF_SIZE));
        remote->buffer->len = 0;
        remote->read_io_ctx = static_cast<remote_ctx_t *>(malloc(sizeof(remote_ctx_t)));
        remote->read_io_ctx->remote = remote;
        remote->write_io_ctx = static_cast<remote_ctx_t *>(malloc(sizeof(remote_ctx_t)));
        remote->write_io_ctx->remote = remote;
        server->remote = remote;
        remote->server = server;

        ev_io_init(&server->read_io_ctx->io, sock_read_cb, client_fd, EV_READ);
        ev_io_init(&server->write_io_ctx->io, sock_write_cb, client_fd, EV_WRITE);
        ev_io_start(loop, &server->read_io_ctx->io);
    }
}

// upstream read
static void remote_read_cb(struct ev_loop* loop, ev_io* watcher, int revents) {
    if (revents == EV_READ) {
        auto* remote_ctx = (remote_ctx_t*) watcher;
        remote_t* remote = remote_ctx->remote;
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
                perror("remote_read_cb");
                close_and_free_server(loop, server);
                close_and_free_remote(loop, remote);
                return;
            }
        }
        buffer->len += read_n;
        int relay_back_n = (int) send(server->fd, buffer->data, buffer->len, 0);
        //std::cout << std::string(buffer->data) << std::endl;
        if (relay_back_n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                relay_back_n = 0; // to register ev watcher
            } else {
                perror("relay_back_send");
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

static void remote_write_cb(struct ev_loop* loop, ev_io* watcher, int wevents) {
    if (wevents == EV_WRITE) {
        auto* remote_ctx = (remote_ctx_t*) watcher;
        remote_t* remote = remote_ctx->remote;
        buffer_t* buffer = remote->buffer;
        assert(buffer->len == 0);
        int write_n = (int) send(remote->fd, buffer->data, SOCKET_BUF_SIZE, 0);
        if (write_n == 0) {
            close_and_free_server(loop, remote->server);
            close_and_free_remote(loop, remote);
            return;
        }
        if (write_n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            } else {
                perror("remote_write_cb");
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
    } else {
        std::cerr << "remote_write_cb event unknown: " << wevents << std::endl;
    }
}


int main(int argc, char** argv) {
    struct ev_loop *loop = EV_DEFAULT;
    int listen_fd = sock_create_bind("127.0.0.1", "6788");
    sock_set_nonblock(listen_fd);
    std::cout << "socks server listening on: " << 6788 << std::endl;
    sock_listening(listen_fd);
//    ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
//    ev_signal_start(EV_DEFAULT, &sigchld_watcher);

    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    struct ev_io listen_ev_io = {};
    ev_io_init(&listen_ev_io, sock_accept_cb, listen_fd, EV_READ);
    ev_io_start(loop, &listen_ev_io);
    ev_loop(loop, 0);
    return EXIT_SUCCESS;
}