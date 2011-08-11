#ifndef DREW_INTERNAL_H
#define DREW_INTERNAL_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#define _BSD_SOURCE 1
#define DREW_IN_BUILD 1

#if defined(DREW_AS_PLUGIN)
#define DREW_PLUGIN_NAME(x) drew_plugin_info
#elif defined(DREW_AS_MODULE)
#define DREW_PLUGIN_NAME(x) drew_plugin_info_ ## x
#endif

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

#define RETFAIL(x) do { \
        int result_code; \
        if ((result_code = (x))) return result_code; } while (0)
#define URETFAIL(m, x) do { \
        int result_code; \
        if ((result_code = (x))) { UNLOCK(m); return result_code; } \
} while (0)

#ifdef __cplusplus
#define NTHROWFAIL(x) do { \
        int result_code; \
        if ((result_code = (x)) < 0) throw -result_code; } while (0)
#define START_FUNC() try {
#define END_FUNC() } \
	catch (int e) { return -abs(e); } \
	catch (std::bad_alloc) { return -ENOMEM; }
#endif

#ifdef DREW_THREAD_SAFE
#include <pthread.h>
#define DREW_MUTEX_DECL() pthread_mutex_t mutex;
#define DREW_MUTEX_INIT(x) pthread_mutex_init(&((x)->mutex), NULL);
#define DREW_MUTEX_FINI(x) pthread_mutex_destroy(&((x)->mutex));
#ifdef __cplusplus
#define LOCK(x)         MutexLock(&((x)->mutex));
#define UNLOCK(x)
#else
#define LOCK(x)         pthread_mutex_lock(&((x)->mutex));
#define UNLOCK(x)       pthread_mutex_unlock(&((x)->mutex));
#endif
#else
#define DREW_MUTEX_DECL()
#define DREW_MUTEX_INIT(x)
#define DREW_MUTEX_FINI(x)
#define LOCK(x)
#define UNLOCK(x)
#endif

#define STATIC_ASSERT(e) ((void)sizeof(char[1 - 2*!(e)]))

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

typedef int (*drew_plugin_api_t)(void *, int, int, void *);

#endif
