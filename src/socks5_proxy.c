#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "socks5_traits.h"

#include "socks5_proxy.h"
#include "event_loop.h"
#include "logger.h"

#ifdef _WIN32
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define close(fd) closesocket(fd)
#define read(fd,buf,len) recv((fd),(char *)(buf),(int)(len),0)
#define write(fd,buf,len) send((fd),(const char *)(buf),(int)(len),0)
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
static const char *sock_errstr(void) { static char buf[64]; int e = WSAGetLastError(); snprintf(buf, sizeof(buf), "wsa-%d", e); return buf; }
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define sock_errstr() strerror(errno)
#endif

#define SOCKS_VERSION 0x05
#define SOCKS_NO_AUTH 0x00
#define SOCKS_USERPASS 0x02
#define SOCKS_AUTH_VERSION 0x01
#define SOCKS_CMD_CONNECT 0x01

#define ATYP_IPV4 0x01
#define ATYP_DOMAIN 0x03
#define ATYP_IPV6 0x04

#define REP_SUCCEEDED 0x00
#define REP_GENERAL_FAILURE 0x01
#define REP_CMD_NOT_SUPPORTED 0x07
#define REP_ADDR_NOT_SUPPORTED 0x08

#define MAX_ADDR_LEN 256
#define IO_BUF_SIZE 4096

typedef enum {
    CS_METHODS_COUNT,
    CS_METHODS,
    CS_USER_LEN,
    CS_USERNAME,
    CS_PASS_LEN,
    CS_PASSWORD,
    CS_REQUEST,
    CS_ADDRTYPE,
    CS_ADDRLEN,
    CS_ADDR,
    CS_PORT,
    CS_WAIT_UPSTREAM,
    CS_TUNNEL,
    CS_CLOSED,
} client_state;

typedef enum {
    US_BEGIN,
    US_METHOD_REPLY,
    US_AUTH_REPLY,
    US_REPLY_HEADER,
    US_REPLY_ADDRLEN,
    US_REPLY_ADDR,
    US_TUNNEL,
    US_CLOSED,
} upstream_state;

typedef struct connection connection_t;

typedef struct {
    struct ev_loop *loop; /* may be external */
    bool owns_loop;
    int listen_fd;
    struct sockaddr_storage upstream_addr;
    socklen_t upstream_len;
    char *up_user;
    char *up_pass;
    char *auth_user;
    char *auth_pass;
    bool require_upstream_auth;
    bool auth_required;
} proxy_ctx;

struct connection {
    proxy_ctx *ctx;
    int client_fd;
    int upstream_fd;
    char client_addr[64];
    client_state cstate;
    upstream_state ustate;
    uint8_t addr_type;
    uint8_t addr_len;
    uint8_t addr_buf[MAX_ADDR_LEN];
    uint16_t dst_port;
    uint8_t reply_buf[4 + MAX_ADDR_LEN + 2];
    size_t reply_len;
    bool closing;
    bool base_released;
    bool close_after_send;
    bool auth_required;
    int refcnt;
};

static void conn_hold(connection_t *c) { if (c) c->refcnt++; }
static void conn_release(connection_t *c) {
    if (!c) return;
    c->refcnt--;
    if (c->refcnt <= 0) {
    SOCKS_FREE(c);
    }
}

static void set_nonblock(int fd) {
#ifdef _WIN32
    u_long on = 1;
    ioctlsocket(fd, FIONBIO, &on);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
#endif
}

static void fill_client_addr(connection_t *conn, int fd) {
    if (!conn) return;
    struct sockaddr_storage ss; socklen_t slen = sizeof(ss);
    if (getpeername(fd, (struct sockaddr *)&ss, &slen) == 0) {
        char host[NI_MAXHOST];
        if (getnameinfo((struct sockaddr *)&ss, slen, host, sizeof(host), NULL, 0, NI_NUMERICHOST) == 0) {
            snprintf(conn->client_addr, sizeof(conn->client_addr), "%s", host);
            return;
        }
    }
    snprintf(conn->client_addr, sizeof(conn->client_addr), "fd-%d", fd);
}

static void close_connection(connection_t *conn) {
    if (!conn) return;
    LOG_INFOF("closing connection fd=%d", conn->client_fd);
        if (!conn->closing) {
            conn->closing = true;
            LOG_INFOF("disconnect client=%s", conn->client_addr[0] ? conn->client_addr : "unknown");
        }
    if (conn->client_fd >= 0) {
        close(conn->client_fd);
        conn->client_fd = -1;
    }
    if (conn->upstream_fd >= 0) {
        close(conn->upstream_fd);
        conn->upstream_fd = -1;
    }
    if (!conn->base_released) {
        conn->base_released = true;
        conn_release(conn); /* release base reference */
    }
}

static int create_listener(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERRORF("socket() failed: %s", sock_errstr());
        return -1;
    }
    int enable = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (!host || host[0] == '\0') {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        LOG_ERRORF("invalid listen host %s", host);
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERRORF("bind %s:%d failed: %s", host ? host : "0.0.0.0", port, sock_errstr());
        close(fd);
        return -1;
    }
    if (listen(fd, SOMAXCONN) < 0) {
        LOG_ERRORF("listen failed: %s", sock_errstr());
        close(fd);
        return -1;
    }
    set_nonblock(fd);
    return fd;
}

static bool resolve_upstream(const char *host, int port, struct sockaddr_storage *out, socklen_t *outlen) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *res = NULL;
    int ret = getaddrinfo(host, port_str, &hints, &res);
    if (ret != 0) {
        LOG_ERRORF("resolve upstream %s:%d failed: %s", host, port, gai_strerror(ret));
        return false;
    }

    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
            memcpy(out, ai->ai_addr, ai->ai_addrlen);
            *outlen = (socklen_t)ai->ai_addrlen;
            freeaddrinfo(res);
            return true;
        }
    }
    freeaddrinfo(res);
    return false;
}

/* Forward declarations for callbacks */
static void on_accept(struct ev_loop *loop, struct ev_io_op *op, int res);
static void on_client_read(struct ev_loop *loop, struct ev_io_op *op, int res);
static void on_client_send(struct ev_loop *loop, struct ev_io_op *op, int res);
static void on_upstream_read(struct ev_loop *loop, struct ev_io_op *op, int res);
static void on_upstream_send(struct ev_loop *loop, struct ev_io_op *op, int res);
static void on_upstream_connect(struct ev_loop *loop, struct ev_io_op *op, int res);

/* Helpers to submit operations while holding refs */
static int submit_client_recv(connection_t *c, size_t len, int flags) {
    if (!c || c->client_fd < 0 || c->closing) return -1;
    conn_hold(c);
    return SOCKS_SUBMIT_RECV(c->ctx->loop, c->client_fd, len, flags, c, on_client_read);
}

static int submit_upstream_recv(connection_t *c, size_t len, int flags) {
    if (!c || c->upstream_fd < 0 || c->closing) return -1;
    conn_hold(c);
    return SOCKS_SUBMIT_RECV(c->ctx->loop, c->upstream_fd, len, flags, c, on_upstream_read);
}

static int submit_client_send(connection_t *c, const uint8_t *data, size_t len, int flags, bool close_after, int tag) {
    if (!c || c->client_fd < 0) return -1;
    conn_hold(c);
    int ret = SOCKS_SUBMIT_SEND(c->ctx->loop, c->client_fd, data, len, flags, c, on_client_send, tag);
    if (close_after) c->close_after_send = true;
    return ret;
}

static int submit_upstream_send(connection_t *c, const uint8_t *data, size_t len, int flags, int tag) {
    if (!c || c->upstream_fd < 0) return -1;
    conn_hold(c);
    return SOCKS_SUBMIT_SEND(c->ctx->loop, c->upstream_fd, data, len, flags, c, on_upstream_send, tag);
}

static int submit_upstream_connect(connection_t *c) {
    if (!c) return -1;
    int fd = socket(c->ctx->upstream_addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    set_nonblock(fd);
    c->upstream_fd = fd;
    conn_hold(c);
    return SOCKS_SUBMIT_CONNECT(c->ctx->loop, fd, (struct sockaddr *)&c->ctx->upstream_addr,
                             c->ctx->upstream_len, c, on_upstream_connect);
}

static void send_failure_and_close(connection_t *c, uint8_t rep) {
    uint8_t resp[10] = {SOCKS_VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0};
    c->closing = true;
    LOG_WARNF("sending failure rep=%u to %s", rep, c->client_addr);
    submit_client_send(c, resp, sizeof(resp), MSG_NOSIGNAL, true, 0);
}

/* State handlers */
static void handle_client_handshake(connection_t *c, uint8_t *data, int len) {
    if (!c) return;
    switch (c->cstate) {
    case CS_METHODS_COUNT: {
        if (len != 2 || data[0] != SOCKS_VERSION || data[1] == 0) {
            LOG_WARNF("invalid methods header from %s", c->client_addr);
            close_connection(c);
            return;
        }
        c->cstate = CS_METHODS;
        submit_client_recv(c, (size_t)data[1], MSG_WAITALL);
        break;
    }
    case CS_METHODS: {
        uint8_t method = c->auth_required ? SOCKS_USERPASS : SOCKS_NO_AUTH;
        uint8_t resp[2] = {SOCKS_VERSION, method};
        if (method == SOCKS_NO_AUTH) {
            c->cstate = CS_REQUEST;
            submit_client_send(c, resp, sizeof(resp), MSG_NOSIGNAL, false, 0);
            submit_client_recv(c, 3, MSG_WAITALL);
        } else {
            c->cstate = CS_USER_LEN;
            submit_client_send(c, resp, sizeof(resp), MSG_NOSIGNAL, false, 0);
            submit_client_recv(c, 2, MSG_WAITALL);
        }
        break;
    }
    case CS_USER_LEN: {
        if (len != 2 || data[0] != SOCKS_AUTH_VERSION || data[1] == 0) {
            close_connection(c);
            return;
        }
        c->cstate = CS_USERNAME;
        submit_client_recv(c, (size_t)data[1], MSG_WAITALL);
        break;
    }
    case CS_USERNAME: {
        if (!c->ctx->auth_user || strncmp((char *)data, c->ctx->auth_user, (size_t)len) != 0) {
            uint8_t resp[2] = {SOCKS_AUTH_VERSION, 0x01};
            LOG_WARNF("auth failed (user) from %s", c->client_addr);
            submit_client_send(c, resp, sizeof(resp), MSG_NOSIGNAL, true, 0);
            return;
        }
        c->cstate = CS_PASS_LEN;
        submit_client_recv(c, 1, MSG_WAITALL);
        break;
    }
    case CS_PASS_LEN: {
        if (len != 1 || data[0] == 0) {
            close_connection(c);
            return;
        }
        c->cstate = CS_PASSWORD;
        submit_client_recv(c, (size_t)data[0], MSG_WAITALL);
        break;
    }
    case CS_PASSWORD: {
        uint8_t resp[2] = {SOCKS_AUTH_VERSION, 0x00};
        if (!c->ctx->auth_pass || strncmp((char *)data, c->ctx->auth_pass, (size_t)len) != 0) {
            resp[1] = 0x01;
            LOG_WARNF("auth failed (pass) from %s", c->client_addr);
            submit_client_send(c, resp, sizeof(resp), MSG_NOSIGNAL, true, 0);
            return;
        }
        c->cstate = CS_REQUEST;
        submit_client_send(c, resp, sizeof(resp), MSG_NOSIGNAL, false, 0);
        submit_client_recv(c, 3, MSG_WAITALL);
        break;
    }
    case CS_REQUEST: {
        if (len != 3 || data[0] != SOCKS_VERSION || data[1] != SOCKS_CMD_CONNECT) {
            LOG_WARNF("unsupported cmd %d from %s", len >=2 ? data[1] : -1, c->client_addr);
            send_failure_and_close(c, REP_CMD_NOT_SUPPORTED);
            return;
        }
        c->cstate = CS_ADDRTYPE;
        submit_client_recv(c, 1, MSG_WAITALL);
        break;
    }
    case CS_ADDRTYPE: {
        c->addr_type = data[0];
        if (c->addr_type == ATYP_IPV4) {
            c->cstate = CS_ADDR;
            submit_client_recv(c, 4, MSG_WAITALL);
        } else if (c->addr_type == ATYP_DOMAIN) {
            c->cstate = CS_ADDRLEN;
            submit_client_recv(c, 1, MSG_WAITALL);
        } else if (c->addr_type == ATYP_IPV6) {
            c->cstate = CS_ADDR;
            submit_client_recv(c, 16, MSG_WAITALL);
        } else {
            LOG_WARNF("addr type %u not supported from %s", c->addr_type, c->client_addr);
            send_failure_and_close(c, REP_ADDR_NOT_SUPPORTED);
        }
        break;
    }
    case CS_ADDRLEN: {
        size_t alen = (size_t)data[0];
        if (alen == 0 || alen > MAX_ADDR_LEN) {
            LOG_WARNF("addr len invalid (%zu) from %s", alen, c->client_addr);
            send_failure_and_close(c, REP_ADDR_NOT_SUPPORTED);
            return;
        }
        c->cstate = CS_ADDR;
        submit_client_recv(c, alen, MSG_WAITALL);
        break;
    }
    case CS_ADDR: {
        if (len <= 0 || len > MAX_ADDR_LEN) {
            LOG_WARNF("addr bytes invalid len=%d from %s", len, c->client_addr);
            send_failure_and_close(c, REP_ADDR_NOT_SUPPORTED);
            return;
        }
        c->addr_len = (uint8_t)len;
        memcpy(c->addr_buf, data, (size_t)c->addr_len);
        c->cstate = CS_PORT;
        submit_client_recv(c, 2, MSG_WAITALL);
        break;
    }
    case CS_PORT: {
        if (len != 2) {
            LOG_WARNF("port len invalid from %s", c->client_addr);
            send_failure_and_close(c, REP_GENERAL_FAILURE);
            return;
        }
        c->dst_port = ((uint16_t)data[0] << 8) | data[1];
        LOG_INFOF("request from %s -> dst type=%u port=%u", c->client_addr, c->addr_type, c->dst_port);
        c->cstate = CS_WAIT_UPSTREAM;
        submit_upstream_connect(c);
        break;
    }
    default:
        break;
    }
}

static void handle_upstream_handshake(connection_t *c, uint8_t *data, int len) {
    if (!c) return;
    switch (c->ustate) {
    case US_METHOD_REPLY: {
        if (len != 2 || data[0] != SOCKS_VERSION) {
            LOG_WARNF("upstream method reply invalid for %s", c->client_addr);
            send_failure_and_close(c, REP_GENERAL_FAILURE);
            return;
        }
        uint8_t method = data[1];
        if (method == SOCKS_NO_AUTH) {
            /* proceed to connect request */
        } else if (method == SOCKS_USERPASS && c->ctx->up_user && c->ctx->up_pass) {
            size_t ulen = strlen(c->ctx->up_user);
            size_t plen = strlen(c->ctx->up_pass);
            if (ulen > 255 || plen > 255) {
                LOG_ERRORF("upstream credentials too long");
                send_failure_and_close(c, REP_GENERAL_FAILURE);
                return;
            }
            uint8_t authreq[2 + 255 + 1 + 255];
            size_t pos = 0;
            authreq[pos++] = SOCKS_AUTH_VERSION;
            authreq[pos++] = (uint8_t)ulen;
            memcpy(authreq + pos, c->ctx->up_user, ulen); pos += ulen;
            authreq[pos++] = (uint8_t)plen;
            memcpy(authreq + pos, c->ctx->up_pass, plen); pos += plen;
            c->ustate = US_AUTH_REPLY;
            submit_upstream_send(c, authreq, pos, MSG_NOSIGNAL, 0);
            submit_upstream_recv(c, 2, MSG_WAITALL);
            break;
        } else {
            LOG_WARNF("upstream method unsupported (%u) for %s", method, c->client_addr);
            send_failure_and_close(c, REP_GENERAL_FAILURE);
            return;
        }
        /* send connect request */
        uint8_t req[4 + MAX_ADDR_LEN + 2];
        size_t pos = 0;
        req[pos++] = SOCKS_VERSION;
        req[pos++] = SOCKS_CMD_CONNECT;
        req[pos++] = 0x00;
        req[pos++] = c->addr_type;
        if (c->addr_type == ATYP_DOMAIN) {
            req[pos++] = c->addr_len;
        }
        memcpy(req + pos, c->addr_buf, c->addr_len); pos += c->addr_len;
        req[pos++] = (uint8_t)((c->dst_port >> 8) & 0xff);
        req[pos++] = (uint8_t)(c->dst_port & 0xff);
        c->ustate = US_REPLY_HEADER;
        submit_upstream_send(c, req, pos, MSG_NOSIGNAL, 0);
        submit_upstream_recv(c, 4, MSG_WAITALL);
        break;
    }
    case US_AUTH_REPLY: {
        if (len != 2 || data[0] != SOCKS_AUTH_VERSION || data[1] != 0x00) {
            LOG_WARNF("upstream auth failed for %s", c->client_addr);
            send_failure_and_close(c, REP_GENERAL_FAILURE);
            return;
        }
        /* auth ok, now send connect */
        uint8_t req[4 + MAX_ADDR_LEN + 2];
        size_t pos = 0;
        req[pos++] = SOCKS_VERSION;
        req[pos++] = SOCKS_CMD_CONNECT;
        req[pos++] = 0x00;
        req[pos++] = c->addr_type;
        if (c->addr_type == ATYP_DOMAIN) {
            req[pos++] = c->addr_len;
        }
        memcpy(req + pos, c->addr_buf, c->addr_len); pos += c->addr_len;
        req[pos++] = (uint8_t)((c->dst_port >> 8) & 0xff);
        req[pos++] = (uint8_t)(c->dst_port & 0xff);
        c->ustate = US_REPLY_HEADER;
        submit_upstream_send(c, req, pos, MSG_NOSIGNAL, 0);
        submit_upstream_recv(c, 4, MSG_WAITALL);
        break;
    }
    case US_REPLY_HEADER: {
        if (len != 4 || data[0] != SOCKS_VERSION) {
            LOG_WARNF("upstream reply header failed for %s code=%d", c->client_addr, len>=2?data[1]:-1);
            send_failure_and_close(c, REP_GENERAL_FAILURE);
            return;
        }
        memcpy(c->reply_buf, data, 4);
        c->reply_len = 4;
        if (data[1] != REP_SUCCEEDED) {
            send_failure_and_close(c, data[1]);
            return;
        }
        uint8_t atyp = data[3];
        if (atyp == ATYP_DOMAIN) {
            c->ustate = US_REPLY_ADDRLEN;
            submit_upstream_recv(c, 1, MSG_WAITALL);
        } else if (atyp == ATYP_IPV4) {
            c->ustate = US_REPLY_ADDR;
            submit_upstream_recv(c, 4 + 2, MSG_WAITALL);
        } else if (atyp == ATYP_IPV6) {
            c->ustate = US_REPLY_ADDR;
            submit_upstream_recv(c, 16 + 2, MSG_WAITALL);
        } else {
            send_failure_and_close(c, REP_ADDR_NOT_SUPPORTED);
        }
        break;
    }
    case US_REPLY_ADDRLEN: {
        size_t alen = (size_t)data[0];
        if (alen == 0 || alen > MAX_ADDR_LEN) {
            LOG_WARNF("upstream reply addrlen bad (%zu) for %s", alen, c->client_addr);
            send_failure_and_close(c, REP_ADDR_NOT_SUPPORTED);
            return;
        }
        c->ustate = US_REPLY_ADDR;
        submit_upstream_recv(c, alen + 2, MSG_WAITALL);
        break;
    }
    case US_REPLY_ADDR: {
        memcpy(c->reply_buf + c->reply_len, data, (size_t)len);
        c->reply_len += (size_t)len;
        /* forward reply to client */
        c->cstate = CS_TUNNEL;
        c->ustate = US_TUNNEL;
        LOG_INFOF("tunnel established for %s", c->client_addr);
    submit_client_send(c, c->reply_buf, c->reply_len, MSG_NOSIGNAL, false, 0);
        /* start tunnel reads */
        submit_client_recv(c, IO_BUF_SIZE, 0);
        submit_upstream_recv(c, IO_BUF_SIZE, 0);
        break;
    }
    default:
        break;
    }
}

static void handle_tunnel_data(connection_t *c, struct ev_io_op *op, int res) {
    if (!c || res <= 0) {
        close_connection(c);
        return;
    }
    int src_fd = op->fd;
    int dst_fd = (src_fd == c->client_fd) ? c->upstream_fd : c->client_fd;
    if (dst_fd < 0) {
        close_connection(c);
        return;
    }
    /* tag indicates direction: 0 client->upstream, 1 upstream->client */
    int tag = (src_fd == c->client_fd) ? 0 : 1;
    if (dst_fd == c->client_fd) {
        submit_client_send(c, op->buf, (size_t)res, MSG_NOSIGNAL, false, tag);
    } else {
        submit_upstream_send(c, op->buf, (size_t)res, MSG_NOSIGNAL, tag);
    }
}

/* Callbacks */
static void on_accept(struct ev_loop *loop, struct ev_io_op *op, int res) {
    proxy_ctx *ctx = (proxy_ctx *)op->owner;
    /* resubmit accept regardless */
    SOCKS_SUBMIT_ACCEPT(loop, ctx->listen_fd, ctx, on_accept);
    if (res < 0) {
        LOG_ERRORF("accept failed: %s", strerror(-res));
        return;
    }
    int client_fd = res;
    set_nonblock(client_fd);
    connection_t *conn = (connection_t *)SOCKS_CALLOC(1, sizeof(connection_t));
    if (!conn) {
        close(client_fd);
        return;
    }
    conn->ctx = ctx;
    conn->client_fd = client_fd;
    conn->upstream_fd = -1;
    fill_client_addr(conn, client_fd);
    LOG_INFOF("client connected %s fd=%d", conn->client_addr, client_fd);
    conn->cstate = CS_METHODS_COUNT;
    conn->ustate = US_BEGIN;
    conn->auth_required = ctx->auth_required;
    conn->refcnt = 1; /* base ref */
    conn->base_released = false;
    submit_client_recv(conn, 2, MSG_WAITALL);
}

static void on_client_read(struct ev_loop *loop, struct ev_io_op *op, int res) {
    (void)loop;
    connection_t *c = (connection_t *)op->owner;
    if (!c) return;
    if (c->closing || res <= 0) {
        close_connection(c);
        conn_release(c);
        return;
    }
    if (c->cstate == CS_TUNNEL) {
        handle_tunnel_data(c, op, res);
        conn_release(c);
        return;
    }
    handle_client_handshake(c, op->buf, res);
    conn_release(c);
}

static void on_upstream_read(struct ev_loop *loop, struct ev_io_op *op, int res) {
    (void)loop;
    connection_t *c = (connection_t *)op->owner;
    if (!c) return;
    if (c->closing || res <= 0) {
        close_connection(c);
        conn_release(c);
        return;
    }
    if (c->ustate == US_TUNNEL) {
        handle_tunnel_data(c, op, res);
        conn_release(c);
        return;
    }
    handle_upstream_handshake(c, op->buf, res);
    conn_release(c);
}

static void on_client_send(struct ev_loop *loop, struct ev_io_op *op, int res) {
    (void)loop;
    connection_t *c = (connection_t *)op->owner;
    if (!c) return;
    if (res < 0) {
        close_connection(c);
        conn_release(c);
        return;
    }
    if ((size_t)res < op->len) {
        size_t remain = op->len - (size_t)res;
                conn_hold(c);
                SOCKS_SUBMIT_SEND(c->ctx->loop, op->fd, op->buf + res, remain, op->flags,
                                                    c, on_client_send, op->user_tag);
                conn_release(c);
        return;
    }
    if (c->close_after_send) {
        close_connection(c);
        conn_release(c);
        return;
    }
    if (c->cstate == CS_TUNNEL) {
        /* resume reading from the same direction */
        if (op->user_tag == 1) {
            submit_upstream_recv(c, IO_BUF_SIZE, 0);
        } else {
            submit_client_recv(c, IO_BUF_SIZE, 0);
        }
    }
    conn_release(c);
}

static void on_upstream_send(struct ev_loop *loop, struct ev_io_op *op, int res) {
    (void)loop;
    connection_t *c = (connection_t *)op->owner;
    if (!c) return;
    if (res < 0) {
        close_connection(c);
        conn_release(c);
        return;
    }
    if ((size_t)res < op->len) {
        size_t remain = op->len - (size_t)res;
        conn_hold(c);
    SOCKS_SUBMIT_SEND(c->ctx->loop, op->fd, op->buf + res, remain, op->flags,
                      c, on_upstream_send, op->user_tag);
        conn_release(c);
        return;
    }
    if (c->ustate == US_TUNNEL) {
        if (op->user_tag == 1) {
            submit_upstream_recv(c, IO_BUF_SIZE, 0);
        } else {
            submit_client_recv(c, IO_BUF_SIZE, 0);
        }
    }
    conn_release(c);
}

static void on_upstream_connect(struct ev_loop *loop, struct ev_io_op *op, int res) {
    (void)loop;
    connection_t *c = (connection_t *)op->owner;
    if (!c) return;
    if (res < 0) {
        LOG_WARNF("upstream connect failed for %s: %s", c->client_addr, strerror(-res));
        send_failure_and_close(c, REP_GENERAL_FAILURE);
        conn_release(c);
        return;
    }
    LOG_INFOF("upstream connected for %s", c->client_addr);
    uint8_t methods[3];
    size_t mlen = 0;
    methods[mlen++] = SOCKS_VERSION;
    if (c->ctx->require_upstream_auth && c->ctx->up_user && c->ctx->up_pass) {
        methods[mlen++] = 1; /* one method */
        methods[mlen++] = SOCKS_USERPASS;
    } else {
        methods[mlen++] = 1;
        methods[mlen++] = SOCKS_NO_AUTH;
    }
    c->ustate = US_METHOD_REPLY;
    submit_upstream_send(c, methods, mlen, MSG_NOSIGNAL, 0);
    submit_upstream_recv(c, 2, MSG_WAITALL);
    conn_release(c);
}

static void proxy_ctx_init(proxy_ctx *ctx, struct ev_loop *loop, bool owns_loop) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->loop = loop;
    ctx->owns_loop = owns_loop;
    ctx->listen_fd = -1;
}

static void proxy_ctx_cleanup(proxy_ctx *ctx) {
    if (!ctx) return;
    if (ctx->listen_fd >= 0) close(ctx->listen_fd);
    if (ctx->up_user) SOCKS_FREE(ctx->up_user);
    if (ctx->up_pass) SOCKS_FREE(ctx->up_pass);
    if (ctx->auth_user) SOCKS_FREE(ctx->auth_user);
    if (ctx->auth_pass) SOCKS_FREE(ctx->auth_pass);
    if (ctx->owns_loop && ctx->loop) {
        ev_loop_close(ctx->loop);
        SOCKS_FREE(ctx->loop);
    }
}

static int proxy_prepare(proxy_ctx *ctx,
                         const char *listen_host, int listen_port,
                         const char *upstream_host, int upstream_port,
                         const char *auth_username, const char *auth_password,
                         const char *up_user, const char *up_pass,
                         bool require_auth, bool require_up_auth,
                         unsigned loop_entries, bool create_loop) {
    if (!ctx) return -1;
    if (create_loop) {
        ctx->loop = (struct ev_loop *)SOCKS_MALLOC(sizeof(struct ev_loop));
        if (!ctx->loop) return -1;
        if (ev_loop_init(ctx->loop, loop_entries) != 0) {
            SOCKS_FREE(ctx->loop);
            ctx->loop = NULL;
            return -3;
        }
        ctx->owns_loop = true;
    }

    ctx->listen_fd = create_listener(listen_host, listen_port);
    if (ctx->listen_fd < 0) {
        return -1;
    }
    LOG_INFOF("listening on %s:%d", listen_host ? listen_host : "0.0.0.0", listen_port);
    if (!resolve_upstream(upstream_host, upstream_port, &ctx->upstream_addr, &ctx->upstream_len)) {
        close(ctx->listen_fd);
        ctx->listen_fd = -1;
        return -2;
    }
    LOG_INFOF("resolved upstream %s:%d", upstream_host, upstream_port);
    if (auth_username) ctx->auth_user = SOCKS_STRDUP(auth_username);
    if (auth_password) ctx->auth_pass = SOCKS_STRDUP(auth_password);
    if (up_user) ctx->up_user = SOCKS_STRDUP(up_user);
    if (up_pass) ctx->up_pass = SOCKS_STRDUP(up_pass);
    ctx->auth_required = require_auth;
    ctx->require_upstream_auth = require_up_auth && ctx->up_user && ctx->up_pass;

    return 0;
}

int socks5_proxy_init_with_loop(socks5_proxy *p, struct ev_loop *loop,
                                const char *listen_host, int listen_port,
                                const char *upstream_host, int upstream_port,
                                const char *auth_username, const char *auth_password,
                                const char *up_user, const char *up_pass,
                                bool require_auth, bool require_up_auth) {
    if (!p || !loop) return -1;
    proxy_ctx *ctx = (proxy_ctx *)SOCKS_CALLOC(1, sizeof(proxy_ctx));
    if (!ctx) return -1;
    proxy_ctx_init(ctx, loop, false);
    int rc = proxy_prepare(ctx, listen_host, listen_port, upstream_host, upstream_port,
                           auth_username, auth_password, up_user, up_pass,
                           require_auth, require_up_auth, 0, false);
    if (rc != 0) {
        SOCKS_FREE(ctx);
        return rc;
    }
    p->loop = loop;
    p->listen_host = (listen_host ? SOCKS_STRDUP(listen_host) : NULL);
    p->listen_port = listen_port;
    p->upstream_host = (upstream_host ? SOCKS_STRDUP(upstream_host) : NULL);
    p->upstream_port = upstream_port;
    p->upstream_user = (up_user ? SOCKS_STRDUP(up_user) : NULL);
    p->upstream_pass = (up_pass ? SOCKS_STRDUP(up_pass) : NULL);
    p->auth_username = (auth_username ? SOCKS_STRDUP(auth_username) : NULL);
    p->auth_password = (auth_password ? SOCKS_STRDUP(auth_password) : NULL);
    p->require_upstream_auth = require_up_auth;
    p->require_auth = require_auth;
    p->listen_fd = ctx->listen_fd;
    p->upstream_addr = ctx->upstream_addr;
    p->upstream_len = ctx->upstream_len;
    p->owns_loop = false;
    p->ctx = ctx;
    return 0;
}

int socks5_proxy_init_own_loop(socks5_proxy *p, unsigned loop_entries,
                               const char *listen_host, int listen_port,
                               const char *upstream_host, int upstream_port,
                               const char *auth_username, const char *auth_password,
                               const char *up_user, const char *up_pass,
                               bool require_auth, bool require_up_auth) {
    if (!p) return -1;
    proxy_ctx *ctx = (proxy_ctx *)SOCKS_CALLOC(1, sizeof(proxy_ctx));
    if (!ctx) return -1;
    proxy_ctx_init(ctx, NULL, true);
    int rc = proxy_prepare(ctx, listen_host, listen_port, upstream_host, upstream_port,
                           auth_username, auth_password, up_user, up_pass,
                           require_auth, require_up_auth, loop_entries, true);
    if (rc != 0) {
        proxy_ctx_cleanup(ctx);
        SOCKS_FREE(ctx);
        return rc;
    }
    p->loop = ctx->loop;
    p->listen_host = (listen_host ? SOCKS_STRDUP(listen_host) : NULL);
    p->listen_port = listen_port;
    p->upstream_host = (upstream_host ? SOCKS_STRDUP(upstream_host) : NULL);
    p->upstream_port = upstream_port;
    p->upstream_user = (up_user ? SOCKS_STRDUP(up_user) : NULL);
    p->upstream_pass = (up_pass ? SOCKS_STRDUP(up_pass) : NULL);
    p->auth_username = (auth_username ? SOCKS_STRDUP(auth_username) : NULL);
    p->auth_password = (auth_password ? SOCKS_STRDUP(auth_password) : NULL);
    p->require_upstream_auth = require_up_auth;
    p->require_auth = require_auth;
    p->listen_fd = ctx->listen_fd;
    p->upstream_addr = ctx->upstream_addr;
    p->upstream_len = ctx->upstream_len;
    p->owns_loop = true;
    p->ctx = ctx;
    return 0;
}

static proxy_ctx *proxy_from_obj(socks5_proxy *p) { return (proxy_ctx *)p->ctx; }

int socks5_proxy_start(socks5_proxy *p) {
    if (!p || !p->loop) return -1;
    proxy_ctx *ctx = proxy_from_obj(p);
    if (!ctx) return -1;
    ctx->loop = p->loop;
    SOCKS_SUBMIT_ACCEPT(ctx->loop, ctx->listen_fd, ctx, on_accept);
    return 0;
}

void socks5_proxy_close(socks5_proxy *p) {
    if (!p) return;
    proxy_ctx *ctx = proxy_from_obj(p);
    if (ctx) {
        proxy_ctx_cleanup(ctx);
        SOCKS_FREE(ctx);
    }
    if (p->listen_host) SOCKS_FREE(p->listen_host);
    if (p->upstream_host) SOCKS_FREE(p->upstream_host);
    if (p->upstream_user) SOCKS_FREE(p->upstream_user);
    if (p->upstream_pass) SOCKS_FREE(p->upstream_pass);
    if (p->auth_username) SOCKS_FREE(p->auth_username);
    if (p->auth_password) SOCKS_FREE(p->auth_password);
    memset(p, 0, sizeof(*p));
}

int run_socks5_proxy(const char *listen_host, int listen_port,
                     const char *upstream_host, int upstream_port,
                     const char *auth_username, const char *auth_password,
                     const char *up_user, const char *up_pass,
                     bool require_auth, bool require_up_auth) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    socks5_proxy proxy;
    memset(&proxy, 0, sizeof(proxy));
    int rc = socks5_proxy_init_own_loop(&proxy, 256, listen_host, listen_port,
                                        upstream_host, upstream_port,
                                        auth_username, auth_password,
                                        up_user, up_pass,
                                        require_auth, require_up_auth);
    if (rc != 0) {
        socks5_proxy_close(&proxy);
        return rc;
    }

    rc = socks5_proxy_start(&proxy);
    if (rc != 0) {
        socks5_proxy_close(&proxy);
        return rc;
    }

    rc = ev_loop_run(proxy.loop);

    socks5_proxy_close(&proxy);
    return rc;
}
