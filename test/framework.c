/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
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

#include <drew/plugin.h>

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

	fwdata = malloc(sizeof(*fwdata));
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

	printf("%d bytes in %0.3fs (%0.3f MiB/s)\n", (nchunks*chunk), diff, rate);
}

// Some algorithms will need to handle the empty input.
int process_bytes(ssize_t len, uint8_t **buf, const char *data)
{
	uint8_t *p;
	if (len < 0)
		return TEST_CORRUPT;
	if (strlen(data) != len * 2) {
		return TEST_CORRUPT;
	}
	free(*buf);
	// Make sure we don't get a NULL pointer if len is 0.
	*buf = p = malloc(len ? len : 1);
	for (size_t i = 0; i < len; i++) {
		if (sscanf(data+(i*2), "%02hhx", p+i) != 1) {
			free(p);
			return TEST_CORRUPT;
		}
	}
	return TEST_OK;
}

static void add_id(struct test_external *tep, char *p)
{
	tep->nids++;
	// FIXME: handle NULL.
	tep->ids = realloc(tep->ids, tep->nids*sizeof(*tep->ids));
	tep->ids[tep->nids-1] = p;
}

// Rotate the bits, except don't allow the result to become negative.
static int rol31(int x)
{
	int r = (x << 1) | (x >> (32-1));
	if (r & 0x80000000) {
		r |= 1;
		r &= ~0x80000000;
	}
	return r;
}

static int execute_test_external(int ret, struct test_external *tep, size_t i)
{
	ret = test_execute(tep->data[i], tep->name, tep->tbl, tep);
	switch (TEST_CODE(ret)) {
		case TEST_FAILED:
			add_id(tep, test_get_id(tep->data[i]));
			// fallthru
		case TEST_OK:
			tep->results = rol31(tep->results);
			tep->results |= ret;
			tep->ntests++;
			break;
	}
	return ret;
}

#define NDATA_CHUNK	512
int test_external(const drew_loader_t *ldr, const char *name, const void *tbl,
		const char *filename, struct test_external *tes)
{
	int ret = 0;

	if (tes->results < 0)
		goto out;

	for (size_t i = 0; i < tes->ndata; i++) {
		if (!tes->data[i])
			break;
		tes->name = name;
		tes->tbl = tbl;
		ret = execute_test_external(ret, tes, i);
		if (TEST_CODE(ret) == TEST_CORRUPT)
			break;
	}
out:
	if (!tes->ntests)
		tes->results = -DREW_ERR_NOT_IMPL;
	if (TEST_CODE(ret) == TEST_CORRUPT || tes->results == -DREW_ERR_INVALID) {
		printf("corrupt test (type %#02x) at line %zu\n", ret & 0xff, tes->lineno);
		tes->results = -DREW_ERR_INVALID;
	}
	else {
		if (tes->nids)
			add_id(tes, NULL);
		tes->results = print_test_results(tes->results, tes->ids);
	}
	for (size_t i = 0; i < tes->nids; i++)
		free(tes->ids[i]);
	free(tes->ids);
	tes->ids = NULL;
	return tes->results;
}

int test_external_parse(const drew_loader_t *ldr, const char *filename,
		struct test_external *tes)
{
	char buf[2048];
	char *saveptr;
	FILE *fp;
	int ret = 0;
	size_t chunkidx = 0;

	if (!filename)
		filename = test_get_filename();

	tes->results = 0;
	tes->ntests = 0;
	tes->name = NULL;
	tes->ldr = ldr;
	tes->tbl = NULL;
	tes->lineno = 0;
	tes->data = malloc(sizeof(*tes->data) * NDATA_CHUNK);
	tes->ndata = NDATA_CHUNK;
	tes->nids = 0;
	tes->ids = NULL;

	memset(tes->data, 0, sizeof(*tes->data) * NDATA_CHUNK);
	chunkidx = 0;
	tes->data[0] = test_create_data();

	if (!filename)
		return tes->results = -DREW_ERR_NOT_IMPL;

	if (!(fp = fopen(filename, "r")))
		return tes->results = -errno;

	while (fgets(buf, sizeof(buf), fp)) {
		char *p = buf, *tok;
		size_t off = strlen(buf);

		if (buf[off-1] != '\n')
			continue;
		tes->lineno++;
		buf[off-1] = 0;
		if (buf[0] == '#')
			continue;

		while ((tok = strtok_r(p, " ", &saveptr))) {
			p = NULL;
			ret = test_process_testcase(tes->data[chunkidx], tok[0], tok+1, tes);
			if (TEST_CODE(ret) == TEST_EXECUTE) {
				if ((chunkidx + 1) == tes->ndata) {
					size_t newsize = tes->ndata + NDATA_CHUNK;
					void **p = realloc(tes->data, sizeof(*p) * newsize);
					if (!p) {
						tes->results = -ENOMEM;
						goto out;
					}
					memset(p + tes->ndata, 0, NDATA_CHUNK * sizeof(*p));
					tes->data = p;
					tes->ndata = newsize;
				}
				tes->data[chunkidx+1] = test_clone_data(tes->data[chunkidx],
						TEST_RESET_PARTIAL);
				chunkidx++;
				ret = test_process_testcase(tes->data[chunkidx], tok[0], tok+1, tes);
			}
			if (TEST_CODE(ret) == TEST_CORRUPT)
				goto out;
		}
	}

	tes->data[chunkidx+1] = NULL;

out:
	fclose(fp);
	if (TEST_CODE(ret) == TEST_CORRUPT)
		tes->results = -DREW_ERR_INVALID;
	return tes->results;
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
	int success_only = 0;
	const char *optalgo = NULL;
	const char *only = NULL;
	const char *resource = NULL; // A filename of testcases.
	drew_loader_t *ldr = NULL;
	struct test_external tes;

	drew_loader_new(&ldr);

	while ((opt = getopt(argc, argv, "hstipfa:c:n:o:r:")) != -1) {
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

	if (mode == MODE_TEST &&
			(retval = test_external_parse(ldr, resource, &tes)))
		tes.results = -DREW_ERR_NOT_IMPL;

	for (i = 0; i < nplugins; i++) {
		const void *functbl;
		const char *name;
		const char *algo;
		int result = 0;

		if (drew_loader_get_type(ldr, i) != type)
			continue;

		drew_loader_get_functbl(ldr, i, &functbl);
		drew_loader_get_algo_name(ldr, i, &name);

		if (only && strcmp(only, name))
			continue;

		algo = optalgo;
		if (!algo && mode != MODE_TEST)
			algo = test_get_default_algo(ldr, name);
		if (algo) {
			char buf[16];
			snprintf(buf, sizeof(buf), "%s(%s)", name, algo);
			printf("%-15s: ", buf);
		}
		else
			printf("%-15s: ", name);

		switch (mode) {
			case MODE_SPEED:
				result = test_speed(ldr, name, algo, functbl, chunk, nchunks);
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
			default:
				break;
		}
	}
	drew_loader_free(&ldr);

	if (error && !(error & 0xff))
		error++;
	return error;
}
