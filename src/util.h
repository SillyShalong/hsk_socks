#include <cstdio>
#include <cerrno>
#include <cstdlib>

#define LOG_PERROR(x) perror(x)

#define LOG_INFO(...) fprintf(stdout, __VA_ARGS__)

#define LOG_ERROR(...) fprintf(stderr, __VA_ARGS__)

#define LOG_WARN(...) fprintf(stderr, __VA_ARGS__)