#include <ev.h>
#include <iostream>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

using namespace std;

int create_and_bind(const string& addr, const string& port) {
    addrinfo hints = {};
    addrinfo *result;
    int listen_fd;
    memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int s = getaddrinfo(addr.c_str(), port.c_str(), &hints, &result);
    if (s != 0) {
        return -1;
    }
    if (result == nullptr) {
        return -1;
    }
    for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        listen_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_fd == -1) {
            continue;
        }
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        // reuse port
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) != 0) {
            close(listen_fd);
            listen_fd = -1;
        }
    }
    freeaddrinfo(result);
    return listen_fd;
}

void read_cb(struct ev_loop *loop, ev_io *watcher, int revents) {
    char buffer[1024];
    ssize_t read_n;
    if (EV_ERROR & revents) {
        perror("got invalid event");
        return;
    }
    int client_fd = watcher->fd;
    read_n = recv(client_fd, buffer, sizeof(buffer), 0);
    if(read_n < 0) {
        perror("read error");
        return;
    }
    if (read_n == 0) {
        ev_io_stop(loop, watcher);
        free(watcher);
        close(client_fd);
        perror("peer might closing");
        return;
    }
    printf("message: %s\n", buffer);
    memset(buffer, 0, sizeof(buffer));
}

void accept_cb(struct ev_loop* loop, ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        perror("got invalid event");
        return;
    }
    sockaddr_in client_addr = {};
    socklen_t addr_len = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));
    int client_fd = accept(watcher->fd, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);
    if (client_fd == -1) {
        std::cerr <<"cannot accept" << std::endl;
        return;
    }
    int opt = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
    ev_io *client_io = static_cast<ev_io *>(malloc(sizeof(struct ev_io)));
    ev_io_init(client_io, read_cb, client_fd, EV_READ);
    ev_io_start(loop, client_io);

//    close(client_fd);
}

int main() {
    std::cout << ev_version_major() << std::endl;
    std::cout << ev_version_minor() << std::endl;

    struct ev_loop* loop = EV_DEFAULT;
    int listen_fd = create_and_bind("127.0.0.1", "7778");
    int backlog = 10;
    if (listen(listen_fd, backlog)) {
        perror("listen error");
        return -1;
    }

    ev_io listen_io;
    ev_io_init(&listen_io, accept_cb, listen_fd, EV_READ);
    ev_io_start(loop, &listen_io);
    while (true) {
        ev_run(loop, 0);
    }
    return 0;
}