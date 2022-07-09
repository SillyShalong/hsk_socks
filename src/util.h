#include <cstdio>
#include <cerrno>

#define ERROR_LOG(x) perror(x)

#define LOG_INFO(...) fprintf(stdout, __VA_ARGS__)

#define LOG_ERROR(...) fprintf(stderr, __VA_ARGS__)
