/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
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
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <drew/param.h>
#include <drew/plugin.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

#define MODE_SPEED			1
#define MODE_TEST			2
#define MODE_TEST_INTERNAL	3
#define MODE_TEST_API		4

#if defined(CLOCK_PROCESS_CPUTIME_ID)
#define USED_CLOCK CLOCK_PROCESS_CPUTIME_ID
#elif defined(CLOCK_MONOTONIC)
#define USED_CLOCK CLOCK_MONOTONIC
#else
#define USED_CLOCK CLOCK_REALTIME
#endif

#define TEST_CODE(x)		(x & ~0xff)

#define TEST_OK				(0 << 8)
#define TEST_FAILURE		(1 << 8)
#define TEST_FAILED 		TEST_FAILURE
#define TEST_EXECUTE		(2 << 8)
#define TEST_CORRUPT		(3 << 8)
#define TEST_NOT_FOR_US		(4 << 8)
#define TEST_NOT_IMPL		(5 << 8)
#define TEST_INTERNAL_ERR	(6 << 8)

#define TEST_RESET_PARTIAL	1
#define TEST_RESET_FREE		2
#define TEST_RESET_ZERO		4
#define TEST_RESET_FULL		(~0)

#define FLAG_DECRYPT		1

/* When performing speed tests, try to operate on NCHUNKS chunks of size CHUNK
 * each, but not for longer than NSECONDS.
 */
#define CHUNK 8192
#define NCHUNKS 40960
#define NSECONDS 5

struct test_data {
	char **ids;
	const char *algodesc;
	size_t nimpls_tested;
	size_t cur_testno;
};

struct test_formatter {
	const char *format;
	void *data;
	void (*prealgo)(void *p, const char *algo);
	void (*test)(void *p, const char *algo, const char *name, int status);
	void (*postalgo)(void *p, const char *algo, int status);
	void (*post)(void *p);
};

struct test_external {
	char **ids;
	size_t nids;
	void **data;
	size_t ndata;
	int results;
	size_t ntests;
	size_t lineno;
	const char *name;
	const void *tbl;
	DrewLoader *ldr;
};


extern volatile sig_atomic_t framework_sigflag;

int test_get_type(void);
int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *functbl, int chunk, int nchunks, int flags);
int test_internal(drew_loader_t *ldr, const char *name, const void *functbl);
const char *test_get_default_algo(drew_loader_t *ldr, const char *name);
void print_speed_info(int chunk, int nchunks, const struct timespec *cstart,
		const struct timespec *cend);
int print_test_results(int result, char **ids);
void framework_teardown(void *data);
void *framework_setup(void);
void test_reset_data(void *p, int flags);
void *test_clone_data(void *p, int flags);
void *test_create_data();
const char *test_get_filename();
char *test_get_id(void *data);
int test_execute(void *data, const char *name, const void *tbl,
		struct test_external *);
int process_bytes(ssize_t len, uint8_t **buf, const char *data);
int test_process_testcase(void *data, int type, const char *item,
		struct test_external *tep);
bool is_forbidden_errno(int val);
int test_api(DrewLoader *ldr, const char *name, const char *algo,
		const void *tbl);
int test_external(DrewLoader *ldr, const char *name, const void *tbl,
		const char *filename, struct test_external *tes,
		struct test_formatter *fmt);
int test_external_parse(DrewLoader *ldr, const char *filename,
		struct test_external *tes);
int test_external_cleanup(struct test_external *tes);
int test_external_parse_param(drew_param_t **param, const char *item);
int test_external_free_params(drew_param_t **param);

#endif
