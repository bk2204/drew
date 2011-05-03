#ifndef DREW_GNUTLS_INTERNAL_H
#define DREW_GNUTLS_INTERNAL_H

#include <gnutls/gnutls.h>

/* You don't want to use this.  It's for internal implementation use only.
 * Thanks.
 */

#define GLOBAL_MUTEX drew_gnutls__global_mutex
#define GLOBAL_DATA drew_gnutls__global_data

extern pthread_mutex_t drew_gnutls__global_mutex;

struct impl_global_data {
	gnutls_log_func log_func;
	int log_level;
} drew_gnutls__global_data;

#endif
