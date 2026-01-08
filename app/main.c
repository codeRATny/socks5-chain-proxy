#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <fcntl.h>
#else
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#define write _write
#endif

#include "logger.h"
#include "socks5_proxy.h"
#include "config.h"

static int crash_fd = -1;

static void safe_write(int fd, const char *msg) {
    if (!msg || fd < 0) return;
    size_t len = strlen(msg);
    while (len > 0) {
        ssize_t w = write(fd, msg, len);
        if (w <= 0) break;
        msg += w;
        len -= (size_t)w;
    }
}

#ifndef _WIN32
static void crash_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)info;
    (void)ucontext;
    const int fd = (crash_fd >= 0) ? crash_fd : STDERR_FILENO;
    safe_write(fd, "\n*** crash detected ***\n");
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "signal %d (%s)\n", sig, strsignal(sig));
    if (n > 0) safe_write(fd, buf);

    void *bt[64];
    int frames = backtrace(bt, 64);
    backtrace_symbols_fd(bt, frames, fd);

    safe_write(fd, "\n*** end stacktrace ***\n");
    _exit(128 + sig);
}

static void setup_signal_handlers(void) {
    crash_fd = open("/var/log/proxy-chain-crash.log", O_CREAT | O_WRONLY | O_APPEND, 0644);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;

    int crash_sigs[] = {SIGSEGV, SIGABRT, SIGILL, SIGFPE, SIGBUS};
    for (size_t i = 0; i < sizeof(crash_sigs)/sizeof(crash_sigs[0]); ++i) {
        sigaction(crash_sigs[i], &sa, NULL);
    }
}
#else
static void setup_signal_handlers(void) { /* no-op on Windows */ }
#endif

static const char *default_config_path(void) {
    return "/etc/proxy-chain/proxy-chain.conf";
}

static int load_config_from_args(int argc, char **argv, proxy_config *cfg) {
    const char *cfg_path = NULL;
    if (argc > 2 && strcmp(argv[1], "--config") == 0) {
        cfg_path = argv[2];
    } else if (argc > 1 && strchr(argv[1], '.') != NULL) {
        cfg_path = argv[1];
    }
    if (!cfg_path) cfg_path = default_config_path();

    if (config_load(cfg_path, cfg) == 0) {
        return 0;
    }

    /* fallback to legacy args: <listen_port> [username password] */
    if (argc < 2) return -1;
    config_init_defaults(cfg);
    cfg->listen_port = atoi(argv[1]);
    if (argc > 3) {
        cfg->auth_user = strdup(argv[2]);
        cfg->auth_pass = strdup(argv[3]);
        cfg->require_auth = true;
    }
    /* defaults already set upstream/logging */
    return 0;
}

int main(int argc, char **argv) {
    setup_signal_handlers();

    proxy_config cfg;
    if (load_config_from_args(argc, argv, &cfg) != 0) {
        fprintf(stderr, "Usage: %s --config <path> | <listen_port> [username password]\n", argv[0]);
        return 1;
    }

    const char *log_path = (cfg.log_to_file ? cfg.log_file : NULL);
    if (logger_init(log_path, cfg.log_to_stdout) != 0) {
        fprintf(stderr, "Failed to init logger\n");
        return -1;
    }
    logger_set_level(cfg.log_level);

    LOG_INFOF("config listen=%s:%d upstream=%s:%d auth=%s up_auth=%s log_file=%s stdout=%s",
              cfg.listen_host, cfg.listen_port,
              cfg.upstream_host, cfg.upstream_port,
              cfg.require_auth ? "yes" : "no",
              cfg.require_upstream_auth ? "yes" : "no",
              cfg.log_file, cfg.log_to_stdout ? "yes" : "no");

    const char *user = (cfg.require_auth ? cfg.auth_user : NULL);
    const char *pass = (cfg.require_auth ? cfg.auth_pass : NULL);

    int rc = run_socks5_proxy(cfg.listen_host, cfg.listen_port,
                              cfg.upstream_host, cfg.upstream_port,
                              user, pass,
                              cfg.require_upstream_auth ? cfg.upstream_user : NULL,
                              cfg.require_upstream_auth ? cfg.upstream_pass : NULL,
                              cfg.require_auth,
                              cfg.require_upstream_auth);
    LOG_INFOF("proxy stopped with rc=%d", rc);
    logger_shutdown();
    config_free(&cfg);
    return rc;
}
