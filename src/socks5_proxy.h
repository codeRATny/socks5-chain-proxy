#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "event_loop.h"

typedef struct socks5_proxy {
    struct ev_loop *loop;            /* external loop (not owned) */
    char *listen_host;
    int listen_port;
    char *upstream_host;
    int upstream_port;
    char *upstream_user;
    char *upstream_pass;
    char *auth_username;
    char *auth_password;
    bool require_upstream_auth;
    bool require_auth;
    int listen_fd;
    struct sockaddr_storage upstream_addr;
    socklen_t upstream_len;
    bool owns_loop;
    void *ctx;
} socks5_proxy;

/* Create a proxy with an existing loop (not owned). Caller keeps loop alive. */
int socks5_proxy_init_with_loop(socks5_proxy *p, struct ev_loop *loop,
                                const char *listen_host, int listen_port,
                                const char *upstream_host, int upstream_port,
                                const char *auth_username, const char *auth_password,
                                const char *up_user, const char *up_pass,
                                bool require_auth, bool require_up_auth);

/* Convenience: create proxy and its own loop (owned). */
int socks5_proxy_init_own_loop(socks5_proxy *p, unsigned loop_entries,
                               const char *listen_host, int listen_port,
                               const char *upstream_host, int upstream_port,
                               const char *auth_username, const char *auth_password,
                               const char *up_user, const char *up_pass,
                               bool require_auth, bool require_up_auth);

/* Start serving (submits accept); for owned loop you still call ev_loop_run externally. */
int socks5_proxy_start(socks5_proxy *p);

/* Shutdown and free resources; closes owned loop if any. */
void socks5_proxy_close(socks5_proxy *p);

/* Legacy helper: start proxy with internal loop, blocking run. */
int run_socks5_proxy(const char *listen_host, int listen_port,
                     const char *upstream_host, int upstream_port,
                     const char *auth_username, const char *auth_password,
                     const char *up_user, const char *up_pass,
                     bool require_auth, bool require_up_auth);
