#include "socks5_server.h"

int main(int argc, char** argv) {
    const char *server_host = "127.0.0.1";
    const char *server_port = "6788";
    if (argc >= 3) {
        server_host = argv[1];
        server_port = argv[2];
    }
    struct ev_loop *loop = EV_DEFAULT;
    int listen_fd = sock_create_bind(server_host, server_port);
    setbuf(stdout, nullptr);
    sock_set_nonblock(listen_fd);
    LOG_INFO("socks server listening on: %s\n", server_port);
    sock_listening(listen_fd);
    ev_signal_init(&sigusr1_watcher, signal_cb, SIGUSR1);
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigusr1_watcher);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);


#ifndef SO_NOSIGPIPE
//    ev_signal_init(&sigpip_watcher, signal_cb, SIGPIPE);
//    ev_signal_start(EV_DEFAULT, &sigpip_watcher);
//    signal(SIGPIPE, SIG_IGN);
//    signal(SIGABRT, SIG_IGN);
//    sigaction(SIGPIPE,signal_cb, NULL);
    auto temp = (struct sigaction){SIG_IGN};
    sigaction(SIGPIPE, &temp, nullptr);

    sigaction(SIGABRT, &temp, nullptr);

#endif

    struct ev_io listen_ev_io = {};
    ev_io_init(&listen_ev_io, sock_accept_cb, listen_fd, EV_READ);
    ev_io_start(loop, &listen_ev_io);
    ev_loop(loop, 0);
    return EXIT_SUCCESS;
}