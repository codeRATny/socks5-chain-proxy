#include "event_loop.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define NSEC_PER_MSEC 1000000ULL

/* thread-local pointer to the currently running loop */
static __thread struct ev_loop *tls_loop = NULL;

static void on_wake(struct ev_loop *loop, struct ev_io_op *op, int res);

static struct ev_io_op *ev_op_new(ev_op_type type, int fd, void *owner,
                                  void (*cb)(struct ev_loop *, struct ev_io_op *, int)) {
    struct ev_io_op *op = (struct ev_io_op *)EV_MALLOC(sizeof(struct ev_io_op));
    if (op) memset(op, 0, sizeof(*op));
    if (!op) return NULL;
    op->type = type;
    op->fd = fd;
    op->owner = owner;
    op->cb = cb;
    op->addrlen = sizeof(struct sockaddr_storage);
    return op;
}

void ev_op_release(struct ev_io_op *op) {
    if (!op) return;
    if (op->buf) EV_FREE(op->buf);
    EV_FREE(op);
}

int ev_loop_init(struct ev_loop *loop, unsigned entries) {
    if (!loop) return -EINVAL;
    memset(loop, 0, sizeof(*loop));
    int ret = io_uring_queue_init(entries, &loop->ring, 0);
    if (ret < 0) return ret;
    loop->should_stop = false;
    queue_init(&loop->tasks, 8);
    EV_MUTEX_INIT(&loop->tasks_lock);
    loop->wake_fd = EV_EVENTFD(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (loop->wake_fd < 0) return -errno;
    return 0;
}

void ev_loop_close(struct ev_loop *loop) {
    if (!loop) return;
    io_uring_queue_exit(&loop->ring);
    queue_free(&loop->tasks);
    if (loop->wake_fd >= 0) close(loop->wake_fd);
    EV_MUTEX_DESTROY(&loop->tasks_lock);
}

void ev_loop_stop(struct ev_loop *loop) {
    if (loop) loop->should_stop = true;
}

struct ev_loop *ev_loop_current(void) {
    return tls_loop;
}

int ev_loop_post(struct ev_loop *loop, void (*fn)(struct ev_loop *, void *), void *arg) {
    if (!loop || !fn) return -EINVAL;
    struct ev_task *t = (struct ev_task *)EV_MALLOC(sizeof(struct ev_task));
    if (!t) return -ENOMEM;
    t->fn = fn;
    t->arg = arg;
    int need_wake = 0;
    if (ev_loop_current() == loop) {
        if (queue_push(&loop->tasks, t) != 0) {
            EV_FREE(t);
            return -ENOMEM;
        }
    } else {
        EV_MUTEX_LOCK(&loop->tasks_lock);
        if (queue_push(&loop->tasks, t) != 0) {
            EV_MUTEX_UNLOCK(&loop->tasks_lock);
            EV_FREE(t);
            return -ENOMEM;
        }
        EV_MUTEX_UNLOCK(&loop->tasks_lock);
        need_wake = 1;
    }
    if (need_wake) {
        uint64_t v = 1;
        write(loop->wake_fd, &v, sizeof(v));
    }
    return 0;
}

static int submit_and_set(struct ev_loop *loop, struct io_uring_sqe *sqe, struct ev_io_op *op) {
    if (!sqe || !op) {
        ev_op_release(op);
        return -ENOMEM;
    }
    io_uring_sqe_set_data(sqe, op);
    return io_uring_submit(&loop->ring);
}

int ev_submit_accept(struct ev_loop *loop, int listen_fd, void *owner,
                     void (*cb)(struct ev_loop *, struct ev_io_op *, int)) {
    if (!loop) return -EINVAL;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);
    struct ev_io_op *op = ev_op_new(EV_OP_ACCEPT, listen_fd, owner, cb);
    if (!op) return -ENOMEM;
    io_uring_prep_accept(sqe, listen_fd, (struct sockaddr *)&op->addr, &op->addrlen, 0);
    return submit_and_set(loop, sqe, op);
}

int ev_submit_recv(struct ev_loop *loop, int fd, size_t len, int flags,
                   void *owner,
                   void (*cb)(struct ev_loop *, struct ev_io_op *, int)) {
    if (!loop) return -EINVAL;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);
    struct ev_io_op *op = ev_op_new(EV_OP_RECV, fd, owner, cb);
    if (!op) return -ENOMEM;
    op->len = len;
    op->flags = flags;
    op->user_tag = 0;
    op->buf = (uint8_t *)EV_MALLOC(len);
    if (!op->buf) {
        ev_op_release(op);
        return -ENOMEM;
    }
    io_uring_prep_recv(sqe, fd, op->buf, len, flags);
    return submit_and_set(loop, sqe, op);
}

static void on_wake(struct ev_loop *loop, struct ev_io_op *op, int res) {
    (void)res;
    if (!loop || !op) return;
    uint64_t tmp = 0;
    if (op->buf && op->len >= sizeof(uint64_t)) {
        memcpy(&tmp, op->buf, sizeof(uint64_t));
    } else {
        read(loop->wake_fd, &tmp, sizeof(tmp));
    }
    /* rearm */
    ev_submit_recv(loop, loop->wake_fd, sizeof(uint64_t), 0, loop, on_wake);
}

int ev_submit_send(struct ev_loop *loop, int fd, const uint8_t *data, size_t len,
                   int flags, void *owner,
                   void (*cb)(struct ev_loop *, struct ev_io_op *, int),
                   int user_tag) {
    if (!loop) return -EINVAL;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);
    struct ev_io_op *op = ev_op_new(EV_OP_SEND, fd, owner, cb);
    if (!op) return -ENOMEM;
    op->len = len;
    op->flags = flags;
    op->user_tag = user_tag;
    op->buf = (uint8_t *)EV_MALLOC(len);
    if (!op->buf) {
        ev_op_release(op);
        return -ENOMEM;
    }
    memcpy(op->buf, data, len);
    io_uring_prep_send(sqe, fd, op->buf, len, flags);
    return submit_and_set(loop, sqe, op);
}

int ev_submit_connect(struct ev_loop *loop, int fd, const struct sockaddr *addr,
                      socklen_t addrlen, void *owner,
                      void (*cb)(struct ev_loop *, struct ev_io_op *, int)) {
    if (!loop) return -EINVAL;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);
    struct ev_io_op *op = ev_op_new(EV_OP_CONNECT, fd, owner, cb);
    if (!op) return -ENOMEM;
    memcpy(&op->addr, addr, addrlen);
    op->addrlen = addrlen;
    op->user_tag = 0;
    io_uring_prep_connect(sqe, fd, addr, addrlen);
    return submit_and_set(loop, sqe, op);
}

int ev_submit_timeout(struct ev_loop *loop, uint64_t timeout_ms, bool repeat,
                      void *owner,
                      void (*cb)(struct ev_loop *, struct ev_io_op *, int)) {
    if (!loop) return -EINVAL;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);
    struct ev_io_op *op = ev_op_new(EV_OP_TIMEOUT, -1, owner, cb);
    if (!op) return -ENOMEM;
    op->repeat = repeat;
    op->ts.tv_sec = timeout_ms / 1000ULL;
    op->ts.tv_nsec = (timeout_ms % 1000ULL) * NSEC_PER_MSEC;
    io_uring_prep_timeout(sqe, &op->ts, 0, 0);
    return submit_and_set(loop, sqe, op);
}

int ev_loop_run(struct ev_loop *loop) {
    if (!loop) return -EINVAL;
    tls_loop = loop;
    /* arm wakeup reader */
    ev_submit_recv(loop, loop->wake_fd, sizeof(uint64_t), 0, loop, on_wake);
    while (!loop->should_stop) {
        /* run queued tasks (lock when coming from other threads) */
        EV_MUTEX_LOCK(&loop->tasks_lock);
        while (!queue_empty(&loop->tasks)) {
            struct ev_task *t = NULL;
            if (queue_pop(&loop->tasks, (void **)&t) == 0 && t && t->fn) {
                EV_MUTEX_UNLOCK(&loop->tasks_lock);
                t->fn(loop, t->arg);
                EV_MUTEX_LOCK(&loop->tasks_lock);
            }
            if (t) EV_FREE(t);
        }
        EV_MUTEX_UNLOCK(&loop->tasks_lock);

        struct io_uring_cqe *cqe = NULL;
        int ret = io_uring_wait_cqe(&loop->ring, &cqe);
        if (ret < 0) {
            if (ret == -EINTR) continue;
            tls_loop = NULL;
            return ret;
        }
        struct ev_io_op *op = (struct ev_io_op *)io_uring_cqe_get_data(cqe);
        int res = cqe->res;
        io_uring_cqe_seen(&loop->ring, cqe);
        if (op && op->cb) {
            if (op->type == EV_OP_TIMEOUT && op->repeat && res == 0) {
                uint64_t ms = (uint64_t)op->ts.tv_sec * 1000ULL + (uint64_t)op->ts.tv_nsec / NSEC_PER_MSEC;
                ev_submit_timeout(loop, ms, true, op->owner, op->cb);
            }
            op->cb(loop, op, res);
        }
        ev_op_release(op);
    }
    tls_loop = NULL;
    return 0;
}
