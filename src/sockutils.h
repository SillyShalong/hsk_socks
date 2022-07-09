#pragma once
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <cstdio>
#include <cstring>
#include <cstddef>

void sock_listening(int fd);

int sock_set_nonblock(int fd);

int sock_create_bind(const char* addr, const char* port);

int resolve_hostname(char *hostname, sockaddr_in *sockaddr);

void export_bin(char *data, int len);

void print_data(char *data, int len);

size_t get_sockaddr_len(struct sockaddr *addr);