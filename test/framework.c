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

int print_test_results(int result)
{
	printf("self-test ");
	if (!result) {
		printf("ok");
	}
	else if (result > 0) {
		/* Tests are numbered starting with 0. */
		int last = -1;
		printf("failed (test%s: ", (result & (result-1)) ? "s" : "");
		for (int x = result; x; x &= ~(1 << (last))) {
			const char *s = (last >= 0) ? ", " : "";
			last = ffs(x) - 1;
			printf("%s%d", s, last);
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

int process_bytes(ssize_t len, uint8_t **buf, const char *data)
{
	uint8_t *p;
	if (len < 0)
		return TEST_CORRUPT;
	if (strlen(data) != len * 2) {
		return TEST_CORRUPT;
	}
	*buf = p = malloc(len);
	for (size_t i = 0; i < len; i++) {
		if (sscanf(data+(i*2), "%02hhx", p+i) != 1) {
			free(p);
			return TEST_CORRUPT;
		}
	}
	return TEST_OK;
}

int test_external(const drew_loader_t *ldr, const char *name, const void *tbl)
{
	char buf[2048];
	char *saveptr;
	FILE *fp;
	int ret = 0, results = 0, ntests = 0;
	size_t lineno = 0;
	void *data = test_create_data();
	const char *filename = test_get_filename();

	if (!filename)
		return 0;

	if (!(fp = fopen(test_get_filename(), "r")))
		return errno;

	while (fgets(buf, sizeof(buf), fp)) {
		char *p = buf, *tok;
		size_t off = strlen(buf);

		if (buf[off-1] != '\n')
			continue;
		lineno++;
		buf[off-1] = 0;

		while ((tok = strtok_r(p, " ", &saveptr))) {
			p = NULL;
			ret = test_process_testcase(data, tok[0], tok+1);
			if (ret == TEST_EXECUTE) {
				ret = test_execute(data, name, tbl, ldr);
				switch (ret) {
					case TEST_OK:
					case TEST_FAILED:
						results <<= 1;
						results |= ret;
						ntests++;
						break;
					case TEST_CORRUPT:
						goto out;
				}
				test_reset_data(data, 1);
				ret = test_process_testcase(data, tok[0], tok+1);
			}
			if (ret == TEST_CORRUPT)
				goto out;
		}
	}

out:
	if (!ntests)
		results = -DREW_ERR_NOT_IMPL;
	test_reset_data(data, 1);
	free(data);
	fclose(fp);
	if (ret == TEST_CORRUPT) {
		printf("corrupt test at line %zu\n", lineno);
		return -DREW_ERR_INVALID;
	}
	else
		return print_test_results(results);
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
	drew_loader_t *ldr = NULL;

	drew_loader_new(&ldr);

	while ((opt = getopt(argc, argv, "stifa:c:n:o:")) != -1) {
		switch (opt) {
			case 's':
				mode = MODE_SPEED;
				break;
			case 't':
				mode = MODE_TEST;
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
		if (!algo)
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
				test_speed(ldr, name, algo, functbl, chunk, nchunks);
				break;
			case MODE_TEST:
				result = test_external(ldr, name, functbl);
				if (result && ((result != -DREW_ERR_NOT_IMPL) || success_only))
					error++;
				break;
			case MODE_TEST_INTERNAL:
				result = test_internal(ldr, name, functbl);
				if (result && ((result != -DREW_ERR_NOT_IMPL) || success_only))
					error++;
			default:
				break;
		}
	}
	drew_loader_free(&ldr);

	if (error && !(error & 0xff))
		error++;
	return error;
}
