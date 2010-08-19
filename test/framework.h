/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a generic test framework.  This implementation requires
 * ANSI C and POSIX 1003.1-2001.
 */

#ifndef FRAMEWORK_H
#define FRAMEWORK_H

#define _POSIX_C_SOURCE 200112L

#include <time.h>

#include <plugin.h>

#define MODE_SPEED			1
#define MODE_TEST			2
#define MODE_TEST_INTERNAL	3

#if defined(CLOCK_PROCESS_CPUTIME_ID)
#define USED_CLOCK CLOCK_PROCESS_CPUTIME_ID
#elif defined(CLOCK_MONOTONIC)
#define USED_CLOCK CLOCK_MONOTONIC
#else
#define USED_CLOCK CLOCK_REALTIME
#endif

#define CHUNK 8192
#define NCHUNKS 40960

int test_get_type(void);
int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *functbl, int chunk, int nchunks);
int test_internal(drew_loader_t *ldr, const char *name, const void *functbl);
void print_speed_info(int chunk, int nchunks, const struct timespec *cstart,
		const struct timespec *cend);

#endif
