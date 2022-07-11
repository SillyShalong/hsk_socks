#include <cstdlib>
#include <sys/socket.h>
#include <cstdio>
#include <sys/fcntl.h>
#include <netdb.h>
#include <cstring>
#include <unistd.h>

void sock_listening(int fd) {
    int backlog = 1024;
    if (listen(fd, backlog) == -1) {
        perror("listen to fd");
    }
}

int sock_set_nonblock(int fd) {
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int sock_create_bind(const char* addr, const char* port) {
    addrinfo hints = {};
    addrinfo *result;
    int listen_fd;
    memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int s = getaddrinfo(addr, port, &hints, &result);
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
#ifdef SO_NOSIGPIPE // MACOS has this
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

int resolve_hostname(char *hostname, sockaddr_in *sockaddr) {
    struct addrinfo hints{};
    struct addrinfo *servinfo;
    int rv;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0; /* Any protocol */
    hints.ai_flags = AI_PASSIVE;
    if ( (rv = getaddrinfo( hostname , "http" , &hints , &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for (addrinfo *p = servinfo; p != nullptr; p = p->ai_next) {
        auto *h = (struct sockaddr_in *) p->ai_addr;
        memcpy(sockaddr, h, sizeof(struct sockaddr_in));
        fflush(stdout);
        break;
    }

    freeaddrinfo(servinfo); // all done with this structure
    return 0;
}

void export_bin(char *data, int len) {
    for (auto i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void print_data(char *data, int len) {
    for (auto i = 0; i < len; ++i) {
        printf("%c", data[i]);
    }
    printf("\n");
}

size_t get_sockaddr_len(struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}