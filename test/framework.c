/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a generic test framework.  This implementation requires
 * ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <drew/mem.h>
#include <drew/plugin.h>

double cpuspeed = 0;

bool is_forbidden_errno(int val)
{
	if (val >= 0)
		return 0;
	if (-val >= 0x10000)
		return 0;
	if (-val == ENOMEM)
		return 0;
	return 1;
}

double sec_from_timespec(const struct timespec *ts)
{
	return ts->tv_sec + (ts->tv_nsec / 1000000000.0);
}

volatile sig_atomic_t framework_sigflag = 0;

void framework_sighandler(int signum)
{
	if (signum == SIGALRM)
		framework_sigflag = 1;
}

struct framework_data {
	timer_t timer;
};

void *framework_setup(void)
{
	struct itimerspec timerspec;
	struct framework_data *fwdata;
	struct sigaction act;

	fwdata = drew_mem_malloc(sizeof(*fwdata));
	if (!fwdata)
		return NULL;

	memset(&timerspec, 0, sizeof(timerspec));
	timerspec.it_value.tv_sec = NSECONDS;
	act.sa_flags = SA_RESETHAND;
	act.sa_handler = framework_sighandler;
	framework_sigflag = 0;

	sigaction(SIGALRM, &act, NULL);
	timer_create(USED_CLOCK, NULL, &fwdata->timer);
	timer_settime(fwdata->timer, 0, &timerspec, NULL);

	return fwdata;
}

void framework_teardown(void *data)
{
	struct framework_data *fwdata = data;
	struct itimerspec timerspec;

	memset(&timerspec, 0, sizeof(timerspec));
	timer_settime(fwdata->timer, 0, &timerspec, NULL);
}

int print_test_results_impl(int result, char **ids, const char *text)
{
	printf("%s ", text);
	if (!result) {
		printf("ok");
	}
	else if (result > 0) {
		printf("failed (test%s: ", (result & (result-1)) ? "s" : "");
		if (!ids) {
			/* Tests are numbered starting with 0. */
			int last = -1;
			for (int x = result; x; x &= ~(1 << (last))) {
				const char *s = (last >= 0) ? ", " : "";
				last = ffs(x) - 1;
				printf("%s%d", s, last);
			}
		}
		else {
			for (char **p = ids; p && *p; p++)
				printf("%s%s", (p != ids) ? ", " : "", *p);
		}
		printf(")");
	}
	else if (result == -DREW_ERR_NOT_IMPL) {
		printf("not implemented");
	}
	else {
		printf("exited with error");
	}
	printf(" (result code %d)\n", result);
	return result;
}

int print_test_results(int result, char **ids)
{
	return print_test_results_impl(result, ids, "self-test");
}

void print_speed_info(int chunk, int nchunks, const struct timespec *cstart,
		const struct timespec *cend)
{
	double start, end, rate, diff;

	start = sec_from_timespec(cstart);
	end = sec_from_timespec(cend);
	diff = end - start;
	rate = chunk * ((double)nchunks) / diff;
	rate /= 1048576;

	printf("%d bytes in %0.3fs (%0.3f MiB/s)", (nchunks*chunk), diff, rate);
	if (cpuspeed) {
		printf(" (%0.3f cycles/byte)", cpuspeed * diff / (nchunks*chunk));
	}
	putchar('\n');
}

// Some algorithms will need to handle the empty input.
int process_bytes(ssize_t len, uint8_t **buf, const char *data)
{
	uint8_t *p;
	drew_mem_free(*buf);
	*buf = 0;
	if (len < 0)
		return TEST_CORRUPT;
	if (strlen(data) != len * 2) {
		return TEST_CORRUPT;
	}
	// Make sure we don't get a NULL pointer if len is 0.
	*buf = p = drew_mem_malloc(len ? len : 1);
	for (size_t i = 0; i < len; i++) {
		if (sscanf(data+(i*2), "%02hhx", p+i) != 1) {
			drew_mem_free(p);
			return TEST_CORRUPT;
		}
	}
	return TEST_OK;
}

int usage(const char *argv0, int retval)
{
	FILE *fp = retval ? stderr : stdout;
	fprintf(fp, "usage:\n%s [-hspti] [options]\n", argv0);
	fprintf(fp,
			"\t-h\t: print this help message\n"
			"\t-s\t: perform a speed test (default)\n"
			"\t-p\t: perform a test for compliance to the API\n"
			"\t-t\t: perform a test using a test vector file\n"
			"\t-i\t: perform a test using code in the plugin\n\n");
	fprintf(fp,
			"\t-f\t: treat unimplemented tests as errors\n"
			"\t-a algo\t: specify a secondary algorithm\n"
			"\t-c size\t: process data in chunks of size bytes\n"
			"\t-n num\t: process num chunks\n"
			"\t-o algo\t: only use algorithm algo\n"
			"\t-u speed\t: specify cpu speed in GHz\n"
			"\t-r file\t: use file for test vectors\n");
	return retval;
}

int main(int argc, char **argv)
{
	int error = 0;
	int i;
	int mode = 0;
	int nplugins = 0;
	int opt = 0;
	int type = 0;
	int chunk = 0;
	int nchunks = 0;
	int retval = 0;
	int verbose = 0;
	int flags = 0;
	int success_only = 0;
	const char *optalgo = NULL;
	const char *only = NULL;
	const char *resource = NULL; // A filename of testcases.
	drew_loader_t *ldr = NULL;
	struct test_external tes;

	drew_loader_new(&ldr);
	drew_mem_pool_adjust(NULL, DREW_MEM_SECMEM, DREW_MEM_SECMEM_NO_LOCK, NULL);

	while ((opt = getopt(argc, argv, "hstipfda:c:n:o:r:u:v")) != -1) {
		switch (opt) {
			case '?':
			case ':':
				return usage(argv[0], 2);
			case 'h':
				return usage(argv[0], 0);
			case 's':
				mode = MODE_SPEED;
				break;
			case 't':
				mode = MODE_TEST;
				break;
			case 'p':
				mode = MODE_TEST_API;
				break;
			case 'i':
				mode = MODE_TEST_INTERNAL;
				break;
			case 'f':
				success_only = 1;
				break;
			case 'a':
				optalgo = optarg;
				break;
			case 'c':
				chunk = atoi(optarg);
				break;
			case 'n':
				nchunks = atoi(optarg);
				break;
			case 'o':
				only = optarg;
				break;
			case 'r':
				resource = optarg;
				break;
			case 'v':
				verbose++;
				break;
			case 'd':
				flags = FLAG_DECRYPT;
				break;
			case 'u':
				cpuspeed = atof(optarg) * 1000000000.0;
				break;
		}
	}

	if (!mode)
		mode = MODE_SPEED;
	if (chunk <= 0)
		chunk = CHUNK;
	if (nchunks <= 0)
		nchunks = NCHUNKS;

	if ((retval = drew_loader_load_plugin(ldr, NULL, NULL))) {
		printf("<internal>: failed to load (error %d (%s))\n", -retval,
				strerror(-retval));
		error++;
	}

	for (; optind < argc; optind++) {
		int id;

		id = drew_loader_load_plugin(ldr, argv[optind], "./plugins");
		if (id < 0) {
			printf("%s: failed to load (error %d (%s))\n", argv[optind], -id,
					strerror(-id));
			error++;
			continue;
		}
	}

	if (optalgo)
		printf("# Using algorithm %s for tests.\n", optalgo);

	nplugins = drew_loader_get_nplugins(ldr, -1);
	type = test_get_type();

	if (mode == MODE_TEST)
		test_external_parse(ldr, resource, &tes);

	for (i = 0; i < nplugins; i++) {
		const void *functbl;
		const char *name;
		const char *algo;
		const char *pluginname = NULL;
		drew_metadata_t md;
		char buf[32];
		int result = 0, nmetadata = 0;

		if (drew_loader_get_type(ldr, i) != type)
			continue;

		drew_loader_get_functbl(ldr, i, &functbl);
		drew_loader_get_algo_name(ldr, i, &name);
		nmetadata = drew_loader_get_metadata(ldr, i, -1, NULL);

		for (int j = 0; j < nmetadata; j++) {
			drew_loader_get_metadata(ldr, i, j, &md);
			if (!strcmp(md.predicate, "http://www.w3.org/2002/07/owl#sameAs")) {
				pluginname = strrchr(md.object, '/');
				if (pluginname)
					pluginname++;
			}
		}

		if (only && strcmp(only, name))
			continue;

		algo = optalgo;
		if (!algo && mode != MODE_TEST)
			algo = test_get_default_algo(ldr, name);
		if (algo)
			snprintf(buf, sizeof(buf)/2, "%s(%s)", name, algo);
		else
			snprintf(buf, sizeof(buf)/2, "%s", name);

		if (pluginname && verbose) {
			size_t off = strlen(buf);
			snprintf(buf+off, sizeof(buf)-off, " (%s) ", pluginname);
		}
		printf("%-32s: ", buf);
		fflush(stdout);

		switch (mode) {
			case MODE_SPEED:
				result = test_speed(ldr, name, algo, functbl, chunk, nchunks,
						flags);
				if (result && ((result != -DREW_ERR_NOT_IMPL) || success_only))
					error++;
				if (result == -DREW_ERR_NOT_IMPL)
					print_test_results_impl(result, NULL, "speed test");
				break;
			case MODE_TEST:
				result = test_external(ldr, name, functbl, resource, &tes);
				if (result && ((result != -DREW_ERR_NOT_IMPL) || success_only))
					error++;
				break;
			case MODE_TEST_INTERNAL:
				result = test_internal(ldr, name, functbl);
				if (result && ((result != -DREW_ERR_NOT_IMPL) || success_only))
					error++;
				break;
			case MODE_TEST_API:
				result = test_api(ldr, name, algo, functbl);
				if (result && ((result != -DREW_ERR_NOT_IMPL) || success_only))
					error++;
				print_test_results_impl(result, NULL, "API test");
				break;
			default:
				break;
		}
	}
	if (mode == MODE_TEST)
		test_external_cleanup(&tes);
	drew_loader_free(&ldr);

	if (error && !(error & 0xff))
		error++;
	return error;
}
