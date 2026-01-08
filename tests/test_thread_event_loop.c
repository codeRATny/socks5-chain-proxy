#include <assert.h>
#include <stdatomic.h>
#include "thread_event_loop.h"
#include "event_loop.h"

static atomic_int ran = 0;

static void task_inc(struct ev_loop *loop, void *arg) {
    (void)loop; (void)arg;
    ran++;
    ev_loop_stop(loop);
}

static void task_stop_only(struct ev_loop *loop, void *arg) {
    (void)arg;
    ev_loop_stop(loop);
}

int main(void) {
    thread_event_loop tel;
    assert(thread_event_loop_start(&tel, 32) == 0);
    struct ev_loop *loop = thread_event_loop_get(&tel);
    assert(loop != NULL);
    assert(ev_loop_post(loop, task_inc, NULL) == 0);

    thread_event_loop_join(&tel);
    assert(ran == 1);

    /* restart loop to ensure stop/join can be called externally */
    assert(thread_event_loop_start(&tel, 16) == 0);
    loop = thread_event_loop_get(&tel);
    assert(loop != NULL);
    thread_event_loop_stop(&tel);
    assert(ev_loop_post(loop, task_stop_only, NULL) == 0);
    thread_event_loop_join(&tel);
    return 0;
}
