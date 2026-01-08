#include "thread_event_loop.h"

#include <string.h>
#include <stdint.h>

#ifdef _WIN32
static DWORD WINAPI thread_loop_runner(LPVOID arg) {
#else
static void *thread_loop_runner(void *arg) {
#endif
    thread_event_loop *tel = (thread_event_loop *)arg;
    if (!tel) {
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }
    ev_loop_run(&tel->loop);
    tel->running = false;
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int thread_event_loop_start(thread_event_loop *tel, unsigned entries) {
    if (!tel) return -1;
    memset(tel, 0, sizeof(*tel));
    int ret = ev_loop_init(&tel->loop, entries);
    if (ret != 0) return ret;
    tel->running = true;
    tel->started = true;
#ifdef _WIN32
    tel->thread = CreateThread(NULL, 0, thread_loop_runner, tel, 0, NULL);
    if (tel->thread == NULL) {
        int err = (int)GetLastError();
        ev_loop_close(&tel->loop);
        tel->running = false;
        return err != 0 ? -err : -1;
    }
#else
    ret = pthread_create(&tel->thread, NULL, thread_loop_runner, tel);
    if (ret != 0) {
        ev_loop_close(&tel->loop);
        tel->running = false;
        return ret;
    }
#endif
    return 0;
}

void thread_event_loop_stop(thread_event_loop *tel) {
    if (!tel || !tel->started) return;
    ev_loop_stop(&tel->loop);
    /* wake the loop in case it's blocked */
    uint64_t one = 1;
#ifdef _WIN32
    char b = 1;
    send(tel->loop.wake_send, &b, 1, 0);
#else
    write(tel->loop.wake_fd, &one, sizeof(one));
#endif
}

void thread_event_loop_join(thread_event_loop *tel) {
    if (!tel || !tel->started) return;
#ifdef _WIN32
    WaitForSingleObject(tel->thread, INFINITE);
    CloseHandle(tel->thread);
#else
    pthread_join(tel->thread, NULL);
#endif
    ev_loop_close(&tel->loop);
    tel->running = false;
    tel->started = false;
}

struct ev_loop *thread_event_loop_get(thread_event_loop *tel) {
    if (!tel) return NULL;
    return &tel->loop;
}
