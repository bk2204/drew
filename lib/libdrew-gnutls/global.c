#include <pthread.h>

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>

#include "drew-gnutls.h"

static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;
static int count = 0;

/* Yes, yes, I know that these aren't supposed to be thread-safe, but they are.
 * Deal with it.
 */
int gnutls_global_init(void)
{
	int retval = GNUTLS_E_SUCCESS;
	pthread_mutex_lock(&global_mutex);
	count++;
	if (count > 1)
		goto out;
	// FIXME: initialize here.
	// FIXME: handle locale issues.
out:
	pthread_mutex_unlock(&global_mutex);
	return retval;
}

void gnutls_global_deinit(void)
{
	pthread_mutex_lock(&global_mutex);
	/* The user has tried to deinit us more times than we've been inited. */
	if (count < 1)
		goto out;
	count--;
	if (count)
		goto out;
	// FIXME: deinitialize here.
out:
	pthread_mutex_unlock(&global_mutex);
	return;
}

const char *gnutls_check_version(const char *req_version)
{
	// FIXME: stub.
	return NULL;
}

void gnutls_global_set_log_function(gnutls_log_func log_func)
{
	pthread_mutex_lock(&GLOBAL_MUTEX);
	GLOBAL_DATA.log_func = log_func;
	pthread_mutex_unlock(&GLOBAL_MUTEX);
}

void gnutls_global_set_log_level(int level)
{
	pthread_mutex_lock(&GLOBAL_MUTEX);
	GLOBAL_DATA.log_level = level;
	pthread_mutex_unlock(&GLOBAL_MUTEX);
}

/* These are basically stubs that just call the appropriate main functions,
 * since the extra functionality is built-in.
 */

int gnutls_global_init_extra(void)
{
	// This is all taken care of in gnutls_global_init.
	return GNUTLS_E_SUCCESS;
}

const char *gnutls_extra_check_version(const char *req_version)
{
	return gnutls_check_version(req_version);
}
