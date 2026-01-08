#pragma once

#ifndef EV_MALLOC
#include <stdlib.h>
#define EV_MALLOC malloc
#define EV_FREE free
#endif

#ifndef EV_MUTEX_T
#ifdef _WIN32
#include <windows.h>
#define EV_MUTEX_T CRITICAL_SECTION
#define EV_MUTEX_INIT(m) InitializeCriticalSection((m))
#define EV_MUTEX_LOCK(m) EnterCriticalSection((m))
#define EV_MUTEX_UNLOCK(m) LeaveCriticalSection((m))
#define EV_MUTEX_DESTROY(m) DeleteCriticalSection((m))
#else
#include <pthread.h>
#define EV_MUTEX_T pthread_mutex_t
#define EV_MUTEX_INIT(m) pthread_mutex_init((m), NULL)
#define EV_MUTEX_LOCK(m) pthread_mutex_lock((m))
#define EV_MUTEX_UNLOCK(m) pthread_mutex_unlock((m))
#define EV_MUTEX_DESTROY(m) pthread_mutex_destroy((m))
#endif
#endif

#ifndef EV_EVENTFD
#ifndef _WIN32
#include <sys/eventfd.h>
#define EV_EVENTFD(initval, flags) eventfd((initval), (flags))
#endif
#endif
