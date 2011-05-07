#ifndef DREW_TLS_H
#define DREW_TLS_H

#include <stdint.h>
#include <sys/types.h>

#ifdef DREW_TLS_THREAD_SAFE
#include <pthread.h>
#define DREW_TLS_MUTEX_DECL() pthread_mutex_t mutex;
#else
#define DREW_TLS_MUTEX_DECL()
#endif

typedef struct {
	uint8_t major, minor;
} drew_tls_protocol_version_t;

typedef void *drew_tls_data_ctxt_t;
typedef ssize_t (*drew_tls_data_in_func_t)(drew_tls_data_ctxt_t, void *,
		size_t);
typedef ssize_t (*drew_tls_data_out_func_t)(drew_tls_data_ctxt_t, const void *,
		size_t);
#endif
