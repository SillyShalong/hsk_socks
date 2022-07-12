#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <ctime>

#define LOG_TIME_FORMAT "%Y%m%d %H:%M:%S"

#define LOG_X(level, format, ...) \
do { \
         time_t now = time(NULL); \
         char timestr[20];    \
         strftime(timestr, 20, LOG_TIME_FORMAT, localtime(&now)); \
         fprintf(stdout, "[%s][" level "] ", timestr); \
         fprintf(stdout, format "\n", ##__VA_ARGS__); \
         fflush(stdout); \
} while (0)

#define LOG_PERROR(x) perror(x)
#define LOG_INFO(format, ...)  LOG_X("INFO",  format, ##__VA_ARGS__)
#define LOG_WARN(format, ...)  LOG_X("WARN",  format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) LOG_X("ERROR", format, ##__VA_ARGS__)