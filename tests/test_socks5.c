#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>

#include "socks5_proxy.h"
#include "thread_event_loop.h"

static int create_listen(uint16_t *port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    assert(getsockname(fd, (struct sockaddr *)&addr, &len) == 0);
    *port_out = ntohs(addr.sin_port);
    assert(listen(fd, 4) == 0);
    return fd;
}

static void set_timeout(int fd, int sec) {
    struct timeval tv = {.tv_sec = sec, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int read_full(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

struct upstream_args {
    int listen_fd;
    bool require_auth;
    bool method_ok;
    bool auth_received;
    bool auth_ok;
    bool connect_seen;
    bool accepted;
};

static void *upstream_server(void *arg) {
    struct upstream_args *ua = (struct upstream_args *)arg;
    int listen_fd = ua->listen_fd;
    int flags = fcntl(listen_fd, F_GETFL, 0); fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK);
    for (int i=0;i<50;++i) { /* 5s */
        struct timeval tv = {.tv_sec=0,.tv_usec=100000};
        fd_set rf; FD_ZERO(&rf); FD_SET(listen_fd, &rf);
        int r = select(listen_fd+1, &rf, NULL, NULL, &tv);
        if (r > 0 && FD_ISSET(listen_fd, &rf)) break;
        if (i==49) return NULL;
        usleep(100000);
    }
    int cfd = accept(listen_fd, NULL, NULL);
    if (cfd < 0) return NULL;
    ua->accepted = true;
    set_timeout(cfd, 3);
    /* greeting */
    uint8_t buf[512];
    ssize_t n = read(cfd, buf, sizeof(buf));
    if (n < 2) { close(cfd); return NULL; }
    /* ensure client offered expected method */
    ua->method_ok = false;
    for (int i=0;i<buf[1] && 2+i<n;i++) {
        if ((!ua->require_auth && buf[2+i]==0x00) || (ua->require_auth && buf[2+i]==0x02)) {
            ua->method_ok = true; break;
        }
    }
    uint8_t rep[2] = {0x05, ua->require_auth ? 0x02 : 0x00};
    write(cfd, rep, 2);

    if (ua->require_auth) {
        ua->auth_received = true;
        n = read(cfd, buf, sizeof(buf));
        if (n < 2 || buf[0] != 0x01) { close(cfd); return NULL; }
        uint8_t ulen = buf[1];
        size_t need = 2 + ulen + 1;
        while ((size_t)n < need + 1 && (size_t)n < sizeof(buf)) {
            ssize_t m = read(cfd, buf + n, sizeof(buf) - n);
            if (m <= 0) break;
            n += m;
        }
        uint8_t plen = buf[2 + ulen];
        need = 3 + ulen + plen;
        while ((size_t)n < need && (size_t)n < sizeof(buf)) {
            ssize_t m = read(cfd, buf + n, sizeof(buf) - n);
            if (m <= 0) break;
            n += m;
        }
        write(cfd, (uint8_t[]){0x01,0x00}, 2);
        ua->auth_ok = true;
    }

    /* request */
    n = read(cfd, buf, sizeof(buf));
    if (n < 4) { close(cfd); return NULL; }
    ua->connect_seen = true;
    uint8_t atyp = buf[3];
    size_t need = 0;
    size_t pos = 4;
    if (atyp == 0x01) need = 4; /* ipv4 */
    else if (atyp == 0x03) { need = (size_t)buf[pos]; pos++; }
    else if (atyp == 0x04) need = 16;
    pos += need + 2; /* address + port */
    while ((size_t)n < pos) {
        ssize_t m = read(cfd, buf + n, sizeof(buf) - n);
        if (m <= 0) break;
        n += m;
    }
    uint8_t reply[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
    write(cfd, reply, 10);
    /* echo tunnel */
    while ((n = read(cfd, buf, sizeof(buf))) > 0) {
        write(cfd, buf, (size_t)n);
    }
    close(cfd);
    return NULL;
}

static void run_proxy_round(bool upstream_auth) {
    uint16_t up_port = 0; int up_fd = create_listen(&up_port);
    struct upstream_args ua = {.listen_fd = up_fd, .require_auth = upstream_auth};
    pthread_t up_thread; pthread_create(&up_thread, NULL, upstream_server, &ua);

    uint16_t proxy_port = 0; int proxy_fd = create_listen(&proxy_port);
    close(proxy_fd);

    thread_event_loop tel; assert(thread_event_loop_start(&tel, 256) == 0);
    socks5_proxy proxy; memset(&proxy, 0, sizeof(proxy));
    const char *uuser = upstream_auth ? "uu" : NULL;
    const char *upass = upstream_auth ? "pp" : NULL;
    assert(socks5_proxy_init_with_loop(&proxy, thread_event_loop_get(&tel),
                                       "127.0.0.1", proxy_port,
                                       "127.0.0.1", up_port,
                                       NULL, NULL, uuser, upass,
                                       false, upstream_auth) == 0);
    assert(socks5_proxy_start(&proxy) == 0);

    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    set_timeout(cfd, 3);
    struct sockaddr_in caddr = {0}; caddr.sin_family = AF_INET; caddr.sin_port = htons(proxy_port); caddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(connect(cfd, (struct sockaddr *)&caddr, sizeof(caddr)) == 0);

    uint8_t greet[] = {0x05,0x01,0x00};
    write(cfd, greet, sizeof(greet));
    uint8_t rep[2]; assert(read_full(cfd, rep, 2)==0);
    assert(rep[0]==0x05);
    assert(rep[1]==0x00);

    /* client->proxy auth is disabled in test */

    uint8_t req[10] = {0x05,0x01,0x00,0x01,127,0,0,1,0x1F,0x90}; /* connect 127.0.0.1:8080 */
    write(cfd, req, 10);
    uint8_t rpl[10]; assert(read_full(cfd, rpl, 10)==0);
    assert(rpl[0]==0x05 && rpl[1]==0x00);

    write(cfd, "ping", 4);
    uint8_t echo[4]; assert(read_full(cfd, echo, 4)==0);
    assert(memcmp(echo, "ping", 4)==0);

    close(cfd);
    thread_event_loop_stop(&tel);
    thread_event_loop_join(&tel);
    socks5_proxy_close(&proxy);
    pthread_join(up_thread, NULL);
    close(up_fd);

    /* handshake assertions */
    assert(ua.method_ok == true);
    if (upstream_auth) {
        assert(ua.auth_received == true);
        assert(ua.auth_ok == true);
    } else {
        assert(ua.auth_received == false);
    }
    assert(ua.accepted == true);
    assert(ua.connect_seen == true);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    alarm(10); /* safety timeout for hangs */
    run_proxy_round(false);
    run_proxy_round(true);
    return 0;
}
