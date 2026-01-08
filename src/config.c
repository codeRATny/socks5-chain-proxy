#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *cfg_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char *out = (char *)malloc(len + 1);
    if (out) memcpy(out, s, len + 1);
    return out;
}

static void trim(char *s) {
    if (!s) return;
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    if (start != s) memmove(s, start, (size_t)(end - start + 1));
}

static bool parse_bool(const char *v, bool *out) {
    if (!v || !out) return false;
    if (!strcasecmp(v, "1") || !strcasecmp(v, "true") || !strcasecmp(v, "yes") || !strcasecmp(v, "on")) {
        *out = true; return true;
    }
    if (!strcasecmp(v, "0") || !strcasecmp(v, "false") || !strcasecmp(v, "no") || !strcasecmp(v, "off")) {
        *out = false; return true;
    }
    return false;
}

void config_init_defaults(proxy_config *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->listen_host = cfg_strdup("0.0.0.0");
    cfg->listen_port = 1080;
    cfg->upstream_host = cfg_strdup("127.0.0.1");
    cfg->upstream_port = 2080;
    cfg->require_upstream_auth = false;
    cfg->require_auth = false;
    cfg->log_to_stdout = true;
    cfg->log_to_file = true;
    cfg->log_file = cfg_strdup("/var/log/proxy-chain.log");
    cfg->log_level = LOG_INFO;
}

static void set_str(char **dst, const char *val) {
    if (*dst) { free(*dst); *dst = NULL; }
    if (val && *val) *dst = cfg_strdup(val);
}

static bool parse_level(const char *v, log_level *out) {
    if (!v || !out) return false;
    if (!strcasecmp(v, "debug")) { *out = LOG_DEBUG; return true; }
    if (!strcasecmp(v, "info"))  { *out = LOG_INFO;  return true; }
    if (!strcasecmp(v, "warn") || !strcasecmp(v, "warning")) { *out = LOG_WARN; return true; }
    if (!strcasecmp(v, "error")) { *out = LOG_ERROR; return true; }
    return false;
}

int config_load(const char *path, proxy_config *cfg) {
    if (!path || !cfg) return -1;
    config_init_defaults(cfg);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    bool require_auth_set = false;
    bool require_up_auth_set = false;
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';' || line[0] == '[') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key); trim(val);
        if (!*key) continue;
        if (!strcasecmp(key, "listen_host")) {
            set_str(&cfg->listen_host, val);
        } else if (!strcasecmp(key, "listen_port")) {
            cfg->listen_port = atoi(val);
        } else if (!strcasecmp(key, "upstream_host")) {
            set_str(&cfg->upstream_host, val);
        } else if (!strcasecmp(key, "upstream_port")) {
            cfg->upstream_port = atoi(val);
        } else if (!strcasecmp(key, "upstream_user")) {
            set_str(&cfg->upstream_user, val);
            if (cfg->upstream_user) { cfg->require_upstream_auth = true; require_up_auth_set = true; }
        } else if (!strcasecmp(key, "upstream_pass")) {
            set_str(&cfg->upstream_pass, val);
            if (cfg->upstream_pass) { cfg->require_upstream_auth = true; require_up_auth_set = true; }
        } else if (!strcasecmp(key, "require_upstream_auth")) {
            bool b; if (parse_bool(val, &b)) { cfg->require_upstream_auth = b; require_up_auth_set = true; }
        } else if (!strcasecmp(key, "auth_user")) {
            set_str(&cfg->auth_user, val);
            if (cfg->auth_user) { require_auth_set = true; cfg->require_auth = true; }
        } else if (!strcasecmp(key, "auth_pass")) {
            set_str(&cfg->auth_pass, val);
            if (cfg->auth_pass) { require_auth_set = true; cfg->require_auth = true; }
        } else if (!strcasecmp(key, "require_auth")) {
            bool b; if (parse_bool(val, &b)) { cfg->require_auth = b; require_auth_set = true; }
        } else if (!strcasecmp(key, "log_to_stdout")) {
            parse_bool(val, &cfg->log_to_stdout);
        } else if (!strcasecmp(key, "log_to_file")) {
            parse_bool(val, &cfg->log_to_file);
        } else if (!strcasecmp(key, "log_file")) {
            set_str(&cfg->log_file, val);
        } else if (!strcasecmp(key, "log_level")) {
            parse_level(val, &cfg->log_level);
        }
    }
    fclose(f);

    if (!require_auth_set && (cfg->auth_user || cfg->auth_pass)) {
        cfg->require_auth = true;
    }
    if (!require_up_auth_set && (cfg->upstream_user || cfg->upstream_pass)) {
        cfg->require_upstream_auth = true;
    }
    return 0;
}

void config_free(proxy_config *cfg) {
    if (!cfg) return;
    free(cfg->listen_host);
    free(cfg->upstream_host);
    free(cfg->upstream_user);
    free(cfg->upstream_pass);
    free(cfg->auth_user);
    free(cfg->auth_pass);
    free(cfg->log_file);
    memset(cfg, 0, sizeof(*cfg));
}
