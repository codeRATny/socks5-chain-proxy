#pragma once

#include "event_loop_traits.h"
#include "queue_traits.h"
#include "vector_traits.h"
#include "logger_traits.h"

#ifndef SOCKS_MALLOC
#include <stdlib.h>
#define SOCKS_MALLOC  malloc
#define SOCKS_CALLOC  calloc
#define SOCKS_FREE    free
#endif

#ifndef SOCKS_STRDUP
#include <string.h>
#define SOCKS_STRDUP strdup
#endif

#ifndef SOCKS_SUBMIT_ACCEPT
#define SOCKS_SUBMIT_ACCEPT ev_submit_accept
#endif

#ifndef SOCKS_SUBMIT_RECV
#define SOCKS_SUBMIT_RECV ev_submit_recv
#endif

#ifndef SOCKS_SUBMIT_SEND
#define SOCKS_SUBMIT_SEND ev_submit_send
#endif

#ifndef SOCKS_SUBMIT_CONNECT
#define SOCKS_SUBMIT_CONNECT ev_submit_connect
#endif

#ifndef SOCKS_SUBMIT_TIMEOUT
#define SOCKS_SUBMIT_TIMEOUT ev_submit_timeout
#endif
