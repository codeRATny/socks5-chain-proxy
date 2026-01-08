#pragma once

#ifndef LOG_MALLOC
#include <stdlib.h>
#define LOG_MALLOC malloc
#define LOG_FREE free
#endif

#ifndef LOG_MUTEX_T
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <windows.h>
#include <synchapi.h>
#ifndef InitializeConditionVariable
WINBASEAPI VOID WINAPI InitializeConditionVariable(PCONDITION_VARIABLE ConditionVariable);
WINBASEAPI BOOL WINAPI SleepConditionVariableCS(PCONDITION_VARIABLE ConditionVariable, PCRITICAL_SECTION CriticalSection, DWORD dwMilliseconds);
WINBASEAPI VOID WINAPI WakeConditionVariable(PCONDITION_VARIABLE ConditionVariable);
WINBASEAPI VOID WINAPI WakeAllConditionVariable(PCONDITION_VARIABLE ConditionVariable);
#endif
#define LOG_MUTEX_T CRITICAL_SECTION
#define LOG_MUTEX_INIT(m) InitializeCriticalSection((m))
#define LOG_MUTEX_LOCK(m) EnterCriticalSection((m))
#define LOG_MUTEX_UNLOCK(m) LeaveCriticalSection((m))
#define LOG_MUTEX_DESTROY(m) DeleteCriticalSection((m))
#define LOG_COND_T CONDITION_VARIABLE
#define LOG_COND_INIT(c) InitializeConditionVariable((c))
#define LOG_COND_WAIT(c,m) SleepConditionVariableCS((c),(m),INFINITE)
#define LOG_COND_SIGNAL(c) WakeConditionVariable((c))
#define LOG_COND_BROADCAST(c) WakeAllConditionVariable((c))
#define LOG_COND_DESTROY(c) ((void)0)
#define LOG_THREAD_T HANDLE
#define LOG_THREAD_CREATE(t,fn,arg) (((*(t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(fn), (arg), 0, NULL))) ? 0 : -1)
#define LOG_THREAD_JOIN(t) do { if (t) { WaitForSingleObject((t), INFINITE); CloseHandle((t)); } } while (0)
#else
#include <pthread.h>
#define LOG_MUTEX_T pthread_mutex_t
#define LOG_MUTEX_INIT(m) pthread_mutex_init((m), NULL)
#define LOG_MUTEX_LOCK(m) pthread_mutex_lock((m))
#define LOG_MUTEX_UNLOCK(m) pthread_mutex_unlock((m))
#define LOG_MUTEX_DESTROY(m) pthread_mutex_destroy((m))
#define LOG_COND_T pthread_cond_t
#define LOG_COND_INIT(c) pthread_cond_init((c), NULL)
#define LOG_COND_WAIT(c,m) pthread_cond_wait((c),(m))
#define LOG_COND_SIGNAL(c) pthread_cond_signal((c))
#define LOG_COND_BROADCAST(c) pthread_cond_broadcast((c))
#define LOG_COND_DESTROY(c) pthread_cond_destroy((c))
#define LOG_THREAD_T pthread_t
#define LOG_THREAD_CREATE(t,fn,arg) pthread_create((t), NULL, (fn), (arg))
#define LOG_THREAD_JOIN(t) pthread_join((t), NULL)
#endif
#endif
