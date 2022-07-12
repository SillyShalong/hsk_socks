#include "socks5_server.h"

int main(int argc, char** argv) {
    const char *server_host = "127.0.0.1";
    const char *server_port = "6788";
    if (argc >= 3) {
        server_host = argv[1];
        server_port = argv[2];
    }
    socks5_server_run(server_host, server_port);
    return EXIT_SUCCESS;
}