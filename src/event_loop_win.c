#ifdef _WIN32
#include "event_loop.h"

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#ifndef EV_MALLOC
#define EV_MALLOC malloc
#define EV_FREE free
#endif

/* thread-local pointer to the currently running loop */
static __thread struct ev_loop *tls_loop = NULL;

struct poll_item {
    WSAPOLLFD pfd;
    struct ev_io_op *op;
};

struct timeout_item {
    struct ev_io_op *op;
    uint64_t due_ms;
};

static uint64_t now_ms(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart / 10000ULL;
}

static void set_nonblock(ev_fd_t fd) {
    u_long on = 1;
    ioctlsocket(fd, FIONBIO, &on);
}

static ev_fd_t make_wake_socketpair(ev_fd_t *out_send) {
    ev_fd_t listener = INVALID_SOCKET;
    ev_fd_t s1 = INVALID_SOCKET, s2 = INVALID_SOCKET;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) goto fail;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0) goto fail;
    if (listen(listener, 1) != 0) goto fail;
    if (getsockname(listener, (struct sockaddr *)&addr, &addrlen) != 0) goto fail;
    s1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s1 == INVALID_SOCKET) goto fail;
    set_nonblock(s1);
    connect(s1, (struct sockaddr *)&addr, addrlen);
    s2 = accept(listener, NULL, NULL);
    if (s2 == INVALID_SOCKET) goto fail;
    closesocket(listener);
    set_nonblock(s2);
    *out_send = s1;
    return s2;
fail:
    if (listener != INVALID_SOCKET) closesocket(listener);
    if (s1 != INVALID_SOCKET) closesocket(s1);
    if (s2 != INVALID_SOCKET) closesocket(s2);
    *out_send = INVALID_SOCKET;
    return INVALID_SOCKET;
}

static struct ev_io_op *ev_op_new(ev_op_type type, ev_fd_t fd, void *owner,
                                  void (*cb)(struct ev_loop *, struct ev_io_op *, int)) {
    struct ev_io_op *op = (struct ev_io_op *)EV_MALLOC(sizeof(struct ev_io_op));
    if (!op) return NULL;
    memset(op, 0, sizeof(*op));
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
    (void)entries;
    if (!loop) return -1;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
    memset(loop, 0, sizeof(*loop));
    queue_init(&loop->tasks, 8);
    EV_MUTEX_INIT(&loop->tasks_lock);
    vector_init(&loop->poll_items, sizeof(struct poll_item), 16);
    vector_init(&loop->timeouts, sizeof(struct timeout_item), 8);
    loop->should_stop = false;
    loop->wake_fd = make_wake_socketpair(&loop->wake_send);
    if (loop->wake_fd == INVALID_SOCKET || loop->wake_send == INVALID_SOCKET) return -1;
    struct poll_item wp = { .pfd = { .fd = loop->wake_fd, .events = POLLRDNORM, .revents = 0 }, .op = NULL };
    vector_push(&loop->poll_items, &wp);
    return 0;
}

void ev_loop_close(struct ev_loop *loop) {
    if (!loop) return;
    if (loop->wake_fd != INVALID_SOCKET) closesocket(loop->wake_fd);
    if (loop->wake_send != INVALID_SOCKET) closesocket(loop->wake_send);
    vector_free(&loop->poll_items);
    vector_free(&loop->timeouts);
    queue_free(&loop->tasks);
    EV_MUTEX_DESTROY(&loop->tasks_lock);
    WSACleanup();
}

void ev_loop_stop(struct ev_loop *loop) { if (loop) loop->should_stop = true; }

struct ev_loop *ev_loop_current(void) { return tls_loop; }

static void run_tasks(struct ev_loop *loop) {
    while (!queue_empty(&loop->tasks)) {
        struct ev_task *t = NULL;
        if (queue_pop(&loop->tasks, (void **)&t) == 0 && t) {
            t->fn(loop, t->arg);
            EV_FREE(t);
        }
    }
}

int ev_loop_post(struct ev_loop *loop, void (*fn)(struct ev_loop *, void *), void *arg) {
    if (!loop || !fn) return -1;
    struct ev_task *t = (struct ev_task *)EV_MALLOC(sizeof(struct ev_task));
    if (!t) return -1;
    t->fn = fn; t->arg = arg;
    int need_wake = (ev_loop_current() != loop);
    EV_MUTEX_LOCK(&loop->tasks_lock);
    if (queue_push(&loop->tasks, t) != 0) {
        EV_MUTEX_UNLOCK(&loop->tasks_lock);
        EV_FREE(t);
        return -1;
    }
    EV_MUTEX_UNLOCK(&loop->tasks_lock);
    if (need_wake) {
        char b = 1;
        send(loop->wake_send, &b, 1, 0);
    }
    return 0;
}

static int add_poll(struct ev_loop *loop, ev_fd_t fd, short events, struct ev_io_op *op) {
    struct poll_item item;
    item.pfd.fd = fd;
    item.pfd.events = events;
    item.pfd.revents = 0;
    item.op = op;
    return vector_push(&loop->poll_items, &item);
}

static void remove_poll_idx(struct ev_loop *loop, size_t idx) {
    size_t n = vector_size(&loop->poll_items);
    if (idx >= n) return;
    if (idx + 1 < n) {
        struct poll_item *dst = (struct poll_item *)vector_get(&loop->poll_items, idx);
        struct poll_item *src = (struct poll_item *)vector_get(&loop->poll_items, idx + 1);
        size_t move = (n - idx - 1) * sizeof(struct poll_item);
        memmove(dst, src, move);
    }
    loop->poll_items.size -= 1;
}

int ev_submit_accept(struct ev_loop *loop, int listen_fd, void *owner,
                     void (*cb)(struct ev_loop *, struct ev_io_op *, int)) {
    if (!loop) return -1;
    struct ev_io_op *op = ev_op_new(EV_OP_ACCEPT, (ev_fd_t)listen_fd, owner, cb);
    if (!op) return -1;
    return add_poll(loop, (ev_fd_t)listen_fd, POLLIN, op);
}

int ev_submit_recv(struct ev_loop *loop, int fd, size_t len, int flags,
                   void *owner,
                   void (*cb)(struct ev_loop *, struct ev_io_op *, int)) {
    if (!loop) return -1;
    struct ev_io_op *op = ev_op_new(EV_OP_RECV, (ev_fd_t)fd, owner, cb);
    if (!op) return -1;
    op->len = len; op->flags = flags;
    op->buf = (uint8_t *)EV_MALLOC(len);
    if (!op->buf) { ev_op_release(op); return -1; }
    return add_poll(loop, (ev_fd_t)fd, POLLIN, op);
}

int ev_submit_send(struct ev_loop *loop, int fd, const uint8_t *data, size_t len,
                   int flags, void *owner,
                   void (*cb)(struct ev_loop *, struct ev_io_op *, int),
                   int user_tag) {
    if (!loop) return -1;
    struct ev_io_op *op = ev_op_new(EV_OP_SEND, (ev_fd_t)fd, owner, cb);
    if (!op) return -1;
    op->len = len; op->flags = flags; op->user_tag = user_tag;
    op->buf = (uint8_t *)EV_MALLOC(len);
    if (!op->buf) { ev_op_release(op); return -1; }
    memcpy(op->buf, data, len);
    return add_poll(loop, (ev_fd_t)fd, POLLOUT, op);
}

int ev_submit_connect(struct ev_loop *loop, int fd, const struct sockaddr *addr,
                      socklen_t addrlen, void *owner,
                      void (*cb)(struct ev_loop *, struct ev_io_op *, int)) {
    if (!loop) return -1;
    set_nonblock((ev_fd_t)fd);
    connect((ev_fd_t)fd, addr, addrlen);
    struct ev_io_op *op = ev_op_new(EV_OP_CONNECT, (ev_fd_t)fd, owner, cb);
    if (!op) return -1;
    memcpy(&op->addr, addr, addrlen);
    op->addrlen = addrlen;
    return add_poll(loop, (ev_fd_t)fd, POLLOUT, op);
}

int ev_submit_timeout(struct ev_loop *loop, uint64_t timeout_ms, bool repeat,
                      void *owner,
                      void (*cb)(struct ev_loop *, struct ev_io_op *, int)) {
    if (!loop || !cb) return -1;
    struct ev_io_op *op = ev_op_new(EV_OP_TIMEOUT, INVALID_SOCKET, owner, cb);
    if (!op) return -1;
    op->repeat = repeat;
    op->ts.tv_sec = (timeout_ms / 1000);
    op->ts.tv_nsec = (timeout_ms % 1000) * 1000000ULL;
    struct timeout_item item = { .op = op, .due_ms = now_ms() + timeout_ms };
    return vector_push(&loop->timeouts, &item);
}

int ev_loop_run(struct ev_loop *loop) {
    if (!loop) return -1;
    tls_loop = loop;
    while (!loop->should_stop) {
        run_tasks(loop);

        uint64_t now = now_ms();
        int wait_ms = 1000;
        size_t tcount = vector_size(&loop->timeouts);
        for (size_t i = 0; i < tcount; ) {
            struct timeout_item *ti = (struct timeout_item *)vector_get(&loop->timeouts, i);
            if (ti->due_ms <= now) {
                ti->op->cb(loop, ti->op, 0);
                if (ti->op->repeat) {
                    ti->due_ms = now + (uint64_t)ti->op->ts.tv_sec * 1000ULL + ti->op->ts.tv_nsec / 1000000ULL;
                    i++;
                } else {
                    ev_op_release(ti->op);
                    if (i + 1 < tcount) {
                        struct timeout_item *dst = (struct timeout_item *)vector_get(&loop->timeouts, i);
                        struct timeout_item *src = (struct timeout_item *)vector_get(&loop->timeouts, i + 1);
                        size_t move = (tcount - i - 1) * sizeof(struct timeout_item);
                        memmove(dst, src, move);
                    }
                    loop->timeouts.size -= 1; tcount--; /* no i++ */
                }
            } else {
                int delta = (int)(ti->due_ms - now);
                if (delta < wait_ms) wait_ms = delta;
                i++;
            }
        }

        int nitems = (int)vector_size(&loop->poll_items);
        if (nitems == 0) {
            Sleep(wait_ms > 0 ? wait_ms : 0);
            continue;
        }

        fd_set rfds, wfds;
        FD_ZERO(&rfds); FD_ZERO(&wfds);
        SOCKET maxfd = 0;
        for (int idx = 0; idx < nitems; ++idx) {
            struct poll_item *pi = (struct poll_item *)vector_get(&loop->poll_items, (size_t)idx);
            if (!pi) continue;
            if (pi->pfd.events & POLLIN) FD_SET(pi->pfd.fd, &rfds);
            if (pi->pfd.events & POLLOUT) FD_SET(pi->pfd.fd, &wfds);
            if (pi->pfd.fd > maxfd) maxfd = pi->pfd.fd;
        }
        struct timeval tv;
        tv.tv_sec = wait_ms / 1000;
        tv.tv_usec = (wait_ms % 1000) * 1000;
        int rc = select((int)maxfd + 1, &rfds, &wfds, NULL, &tv);
        if (rc <= 0) continue;

        for (int idx = 0; idx < nitems; ++idx) {
            struct poll_item *pi = (struct poll_item *)vector_get(&loop->poll_items, (size_t)idx);
            if (!pi) continue;
            int ready = (FD_ISSET(pi->pfd.fd, &rfds) || FD_ISSET(pi->pfd.fd, &wfds));
            if (!ready) continue;
            if (pi->pfd.fd == loop->wake_fd) {
                char buf[8]; recv(loop->wake_fd, buf, sizeof(buf), 0);
                continue;
            }
            struct ev_io_op *op = pi->op;
            if (!op) continue;
            int res = 0;
            switch (op->type) {
            case EV_OP_ACCEPT: {
                ev_fd_t cfd = accept(op->fd, (struct sockaddr *)&op->addr, &op->addrlen);
                if (cfd == INVALID_SOCKET) res = -WSAGetLastError(); else res = (int)cfd;
                remove_poll_idx(loop, (size_t)idx); nitems--; idx--;
                op->cb(loop, op, res);
                ev_op_release(op);
                break;
            }
            case EV_OP_RECV: {
                int n = recv(op->fd, (char *)op->buf, (int)op->len, op->flags);
                if (n == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK) {
                        /* re-arm and wait */
                        continue;
                    }
                    res = -err;
                } else {
                    res = n;
                }
                remove_poll_idx(loop, (size_t)idx); nitems--; idx--;
                op->cb(loop, op, res);
                ev_op_release(op);
                break;
            }
            case EV_OP_SEND: {
                int n = send(op->fd, (const char *)op->buf, (int)op->len, op->flags);
                if (n == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK) {
                        /* re-arm and wait */
                        continue;
                    }
                    res = -err;
                } else {
                    res = n;
                }
                remove_poll_idx(loop, (size_t)idx); nitems--; idx--;
                op->cb(loop, op, res);
                ev_op_release(op);
                break;
            }
            case EV_OP_CONNECT: {
                int err = 0; int optlen = sizeof(err);
                getsockopt(op->fd, SOL_SOCKET, SO_ERROR, (char *)&err, &optlen);
                res = (err == 0) ? 0 : -err;
                remove_poll_idx(loop, (size_t)idx); nitems--; idx--;
                op->cb(loop, op, res);
                ev_op_release(op);
                break;
            }
            default:
                break;
            }
        }
    }
    tls_loop = NULL;
    return 0;
}

#endif /* _WIN32 */
