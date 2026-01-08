#pragma once

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET ev_fd_t;
#else
#include <liburing.h>
#include <sys/socket.h>
typedef int ev_fd_t;
#endif
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "queue.h"
#include "event_loop_traits.h"
#ifdef _WIN32
#include "vector.h"
#endif

struct ev_loop;

typedef enum {
    EV_OP_ACCEPT,
    EV_OP_RECV,
    EV_OP_SEND,
    EV_OP_CONNECT,
    EV_OP_TIMEOUT,
} ev_op_type;

struct ev_io_op {
    ev_op_type type;
    ev_fd_t fd;
    void *owner;          /* user data (e.g., connection pointer) */
    uint8_t *buf;         /* malloc'ed buffer for recv/send */
    size_t len;           /* buffer length */
    int flags;            /* recv/send flags */
    struct sockaddr_storage addr; /* accept/connect addr storage */
    socklen_t addrlen;
    int user_tag;         /* free-form field for caller */
    bool repeat;          /* for timeout */
    struct timespec ts; /* for timeout */
    void (*cb)(struct ev_loop *loop, struct ev_io_op *op, int res);
};

struct ev_loop {
#ifndef _WIN32
    struct io_uring ring;
#endif
    bool should_stop;
    queue tasks; /* queued tasks to run in loop thread */
    EV_MUTEX_T tasks_lock;
    ev_fd_t wake_fd;
#ifdef _WIN32
    ev_fd_t wake_send;
    vector poll_items;
    vector timeouts;
#endif
};

int ev_loop_init(struct ev_loop *loop, unsigned entries);
void ev_loop_close(struct ev_loop *loop);
void ev_loop_stop(struct ev_loop *loop);

/* Thread-local access to the current loop */
struct ev_loop *ev_loop_current(void);

/* Post a task to run on the loop thread (not thread-safe for cross-thread use) */
int ev_loop_post(struct ev_loop *loop, void (*fn)(struct ev_loop *, void *), void *arg);

/* Submission helpers */
int ev_submit_accept(struct ev_loop *loop, int listen_fd, void *owner,
                     void (*cb)(struct ev_loop *, struct ev_io_op *, int));
int ev_submit_recv(struct ev_loop *loop, int fd, size_t len, int flags,
                   void *owner,
                   void (*cb)(struct ev_loop *, struct ev_io_op *, int));
int ev_submit_send(struct ev_loop *loop, int fd, const uint8_t *data, size_t len,
                   int flags, void *owner,
                   void (*cb)(struct ev_loop *, struct ev_io_op *, int),
                   int user_tag);
int ev_submit_connect(struct ev_loop *loop, int fd, const struct sockaddr *addr,
                      socklen_t addrlen, void *owner,
                      void (*cb)(struct ev_loop *, struct ev_io_op *, int));
int ev_submit_timeout(struct ev_loop *loop, uint64_t timeout_ms, bool repeat,
                      void *owner,
                      void (*cb)(struct ev_loop *, struct ev_io_op *, int));

/* Run loop */
int ev_loop_run(struct ev_loop *loop);

/* Utility */
void ev_op_release(struct ev_io_op *op);
