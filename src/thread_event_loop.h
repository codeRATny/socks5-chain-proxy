#pragma once

#include "event_loop.h"

#include <stdbool.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct thread_event_loop {
    struct ev_loop loop;
#ifdef _WIN32
    HANDLE thread;
#else
    pthread_t thread;
#endif
    bool running;
    bool started;
} thread_event_loop;

int thread_event_loop_start(thread_event_loop *tel, unsigned entries);
void thread_event_loop_stop(thread_event_loop *tel);
void thread_event_loop_join(thread_event_loop *tel);
struct ev_loop *thread_event_loop_get(thread_event_loop *tel);

#ifdef __cplusplus
}
#endif
