#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>

#include "event_loop.h"

static void task_stop(struct ev_loop *loop, void *arg) {
    (void)arg;
    ev_loop_stop(loop);
}

static void on_timeout(struct ev_loop *loop, struct ev_io_op *op, int res) {
    (void)op;
    assert(res == 0 || res == -ETIME);
    ev_loop_stop(loop);
}

static void on_recv(struct ev_loop *loop, struct ev_io_op *op, int res) {
    assert(res == 4);
    assert(memcmp(op->buf, "ping", 4) == 0);
    ev_loop_stop(loop);
}

static void on_send_complete(struct ev_loop *loop, struct ev_io_op *op, int res) {
    (void)loop; (void)op;
    assert(res == 4);
}

struct accept_ctx {
    int accepted;
};

static void on_accept_cb(struct ev_loop *loop, struct ev_io_op *op, int res) {
    struct accept_ctx *actx = (struct accept_ctx *)op->owner;
    assert(res >= 0);
    actx->accepted = 1;
    close(res);
    ev_loop_stop(loop);
}

static void on_connect_cb(struct ev_loop *loop, struct ev_io_op *op, int res) {
    (void)loop;
    assert(res == 0);
    close(op->fd);
}

static void test_timeout(struct ev_loop *loop) {
    loop->should_stop = false;
    if (ev_submit_timeout(loop, 10, false, NULL, on_timeout) >= 0) {
        int rc = ev_loop_run(loop);
        assert(rc == 0);
    }
}

static void test_task_post(struct ev_loop *loop) {
    loop->should_stop = false;
    assert(ev_loop_post(loop, task_stop, NULL) == 0);
    int rc = ev_loop_run(loop);
    assert(rc == 0);
}

static void test_send_recv(struct ev_loop *loop) {
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    int flags = fcntl(fds[0], F_GETFL, 0); fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(fds[1], F_GETFL, 0); fcntl(fds[1], F_SETFL, flags | O_NONBLOCK);

    loop->should_stop = false;
    assert(ev_submit_recv(loop, fds[0], 4, 0, NULL, on_recv) >= 0);
    assert(ev_submit_send(loop, fds[1], (const uint8_t *)"ping", 4, 0, NULL, on_send_complete, 0) >= 0);
    int rc = ev_loop_run(loop);
    assert(rc == 0);
    close(fds[0]);
    close(fds[1]);
}

static void test_accept_connect(struct ev_loop *loop) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(lfd >= 0);
    int opt = 1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(lfd, 8) == 0);
    socklen_t alen = sizeof(addr);
    assert(getsockname(lfd, (struct sockaddr *)&addr, &alen) == 0);

    struct accept_ctx actx = {0};
    loop->should_stop = false;
    assert(ev_submit_accept(loop, lfd, &actx, on_accept_cb) >= 0);

    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(cfd >= 0);
    int flags = fcntl(cfd, F_GETFL, 0); fcntl(cfd, F_SETFL, flags | O_NONBLOCK);
    assert(ev_submit_connect(loop, cfd, (struct sockaddr *)&addr, sizeof(addr), NULL, on_connect_cb) >= 0);

    int rc = ev_loop_run(loop);
    assert(rc == 0);
    assert(actx.accepted == 1);
    close(lfd);
}

static void *poster(void *arg) {
    struct ev_loop *loop = (struct ev_loop *)arg;
    usleep(2000);
    ev_loop_post(loop, task_stop, NULL);
    return NULL;
}

static void test_wake_post(struct ev_loop *loop) {
    loop->should_stop = false;
    pthread_t t; pthread_create(&t, NULL, poster, loop);
    int rc = ev_loop_run(loop);
    assert(rc == 0);
    pthread_join(t, NULL);
}

int main(void) {
    struct ev_loop loop;
    assert(ev_loop_init(&loop, 64) == 0);

    test_timeout(&loop);
    test_task_post(&loop);
    test_send_recv(&loop);
    test_accept_connect(&loop);
    test_wake_post(&loop);

    ev_loop_close(&loop);
    return 0;
}
