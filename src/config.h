#pragma once

#include <stdbool.h>
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct proxy_config {
    char *listen_host;
    int listen_port;
    char *upstream_host;
    int upstream_port;
    char *upstream_user;
    char *upstream_pass;
    bool require_upstream_auth;
    char *auth_user;
    char *auth_pass;
    bool require_auth;      /* if false, allow anonymous even if creds absent */
    bool log_to_stdout;     /* log to stdout */
    bool log_to_file;       /* if true and log_file set, log to file */
    char *log_file;         /* filepath, may be NULL */
    log_level log_level;    /* minimum log level */
} proxy_config;

void config_init_defaults(proxy_config *cfg);
int config_load(const char *path, proxy_config *cfg);
void config_free(proxy_config *cfg);

#ifdef __cplusplus
}
#endif
