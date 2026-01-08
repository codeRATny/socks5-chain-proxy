#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#include <synchapi.h>
#else
#include <unistd.h>
#endif

#include "queue.h"

static LOG_MUTEX_T log_mutex;
static LOG_COND_T log_cond;
static LOG_THREAD_T log_thread;
static bool log_thread_running = false;
static bool log_to_stdout = true;
static FILE *log_file = NULL;
static queue log_queue;
static log_level min_level = LOG_INFO;

static const char *level_str(log_level lvl) {
    switch (lvl) {
    case LOG_DEBUG: return "DEBUG";
    case LOG_INFO: return "INFO";
    case LOG_WARN: return "WARN";
    case LOG_ERROR: return "ERROR";
    default: return "UNK";
    }
}

static void enqueue_line(char *line) {
    LOG_MUTEX_LOCK(&log_mutex);
    queue_push(&log_queue, line);
    LOG_COND_SIGNAL(&log_cond);
    LOG_MUTEX_UNLOCK(&log_mutex);
}

#ifdef _WIN32
static DWORD WINAPI log_worker(LPVOID arg) {
#else
static void *log_worker(void *arg) {
#endif
    (void)arg;
    LOG_MUTEX_LOCK(&log_mutex);
    while (log_thread_running) {
        while (queue_empty(&log_queue) && log_thread_running) {
            LOG_COND_WAIT(&log_cond, &log_mutex);
        }
        while (!queue_empty(&log_queue)) {
            char *line = NULL;
            if (queue_pop(&log_queue, (void **)&line) == 0 && line) {
                LOG_MUTEX_UNLOCK(&log_mutex);
                if (log_to_stdout) {
                    fputs(line, stdout);
                    fflush(stdout);
                }
                if (log_file) {
                    fputs(line, log_file);
                    fflush(log_file);
                }
                free(line);
                LOG_MUTEX_LOCK(&log_mutex);
            }
        }
    }
    LOG_MUTEX_UNLOCK(&log_mutex);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static void format_and_enqueue(log_level level, const char *fmt, va_list ap) {
    if (level < min_level) return;
    char ts[64];
    struct tm tmv;
#ifdef _WIN32
    /* FILETIME is 100-ns since 1601-01-01 */
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli; uli.LowPart = ft.dwLowDateTime; uli.HighPart = ft.dwHighDateTime;
    uint64_t t100 = uli.QuadPart;
    uint64_t ns = (t100 % 10000000ULL) * 100ULL;
    time_t sec = (time_t)((t100 / 10000000ULL) - 11644473600ULL);
    localtime_s(&tmv, &sec);
    snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d.%03llu",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (unsigned long long)(ns / 1000000ULL));
#else
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    localtime_r(&tv.tv_sec, &tmv);
    snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec, tv.tv_nsec / 1000000);
#endif

    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, ap);

    size_t len = strlen(ts) + strlen(level_str(level)) + strlen(msg) + 8;
    char *line = (char *)LOG_MALLOC(len);
    if (!line) return;
    snprintf(line, len, "%s [%s] %s\n", ts, level_str(level), msg);
    enqueue_line(line);
}

int logger_init(const char *filepath, bool to_stdout_flag) {
    log_to_stdout = to_stdout_flag;
    if (filepath) {
        log_file = fopen(filepath, "a");
        if (!log_file) return -1;
    }
    queue_init(&log_queue, 32);
    LOG_MUTEX_INIT(&log_mutex);
    LOG_COND_INIT(&log_cond);
    log_thread_running = true;
    if (LOG_THREAD_CREATE(&log_thread, log_worker, NULL) != 0) {
        log_thread_running = false;
        return -1;
    }
    return 0;
}

void logger_set_level(log_level level) {
    min_level = level;
}

void logger_log(log_level level, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    format_and_enqueue(level, fmt, ap);
    va_end(ap);
}

void logger_flush(void) {
    LOG_MUTEX_LOCK(&log_mutex);
    LOG_COND_BROADCAST(&log_cond);
    LOG_MUTEX_UNLOCK(&log_mutex);
}

void logger_shutdown(void) {
    LOG_MUTEX_LOCK(&log_mutex);
    log_thread_running = false;
    LOG_COND_BROADCAST(&log_cond);
    LOG_MUTEX_UNLOCK(&log_mutex);
    LOG_THREAD_JOIN(log_thread);
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    /* drain queue */
    while (!queue_empty(&log_queue)) {
        char *line = NULL;
        if (queue_pop(&log_queue, (void **)&line) == 0 && line) {
            free(line);
        }
    }
    queue_free(&log_queue);
    LOG_MUTEX_DESTROY(&log_mutex);
    LOG_COND_DESTROY(&log_cond);
}
