#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include "logger_traits.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level;

int logger_init(const char *filepath, bool to_stdout);
void logger_set_level(log_level level);
void logger_log(log_level level, const char *fmt, ...);
void logger_flush(void);
void logger_shutdown(void);

#define LOG_DEBUGF(fmt, ...) logger_log(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFOF(fmt, ...)  logger_log(LOG_INFO,  fmt, ##__VA_ARGS__)
#define LOG_WARNF(fmt, ...)  logger_log(LOG_WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERRORF(fmt, ...) logger_log(LOG_ERROR, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
