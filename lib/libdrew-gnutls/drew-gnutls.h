#ifndef DREW_GNUTLS_INTERNAL_H
#define DREW_GNUTLS_INTERNAL_H

#include <pthread.h>

#include <gnutls/gnutls.h>

/* You don't want to use this.  It's for internal implementation use only.
 * Thanks.
 */

#define GLOBAL_MUTEX _drew_gnutls__global_mutex
#define GLOBAL_DATA _drew_gnutls__global_data
#define GLOBAL_PDATA _drew_gnutls__global_pdata

extern pthread_mutex_t _drew_gnutls__global_mutex;

// These items are always protected by GLOBAL_MUTEX.
struct impl_global_data {
	int log_level;
	gnutls_log_func log_func;
} _drew_gnutls__global_data = { 0 };

// These items are global, but since they are set by non-thread-safe functions
// before gnutls_global_init, they are not protected by any mutex.  Changing
// them after gnutls_global_init is forbidden.
struct impl_global_data_preinit {
	int allocs_inited;
	gnutls_alloc_function malloc;
	gnutls_alloc_function smalloc;
	gnutls_is_secure_function issmalloc;
	gnutls_free_function free;
	gnutls_realloc_function realloc;
} _drew_gnutls__global_pdata = { 0 };

int _drew_gnutls__map_error(int err);

#endif
