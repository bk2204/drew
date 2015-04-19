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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <drew/drew.h>
#include <drew/mem.h>

static void add_id(struct test_external *tep, char *p)
{
	tep->nids++;
	// FIXME: handle NULL.
	tep->ids = drew_mem_realloc(tep->ids, tep->nids*sizeof(*tep->ids));
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
int test_external(DrewLoader *ldr, const char *name, const void *tbl,
		const char *filename, struct test_external *tes)
{
	int ret = 0;

	if (tes->results == -DREW_ERR_NOT_IMPL)
		tes->results = 0;
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
	if (!tes->ntests)
		tes->results = -DREW_ERR_NOT_IMPL;
out:
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
		drew_mem_free(tes->ids[i]);
	drew_mem_free(tes->ids);
	tes->ids = NULL;
	return tes->results;
}

int test_external_cleanup(struct test_external *tes)
{
	for (size_t i = 0; i < tes->ndata; i++)
		if (tes->data[i]) {
			test_reset_data(tes->data[i], TEST_RESET_FREE);
			drew_mem_free(tes->data[i]);
		}
	drew_mem_free(tes->data);
	return 0;
}

int test_external_parse(DrewLoader *ldr, const char *filename,
		struct test_external *tes)
{
	char *buf = NULL;
	char *saveptr;
	FILE *fp;
	int ret = 0;
	size_t chunkidx = 0;
	const size_t bufsz = 1024 * 1024;

	if (!filename)
		filename = test_get_filename();

	tes->results = 0;
	tes->ntests = 0;
	tes->name = NULL;
	tes->ldr = ldr;
	tes->tbl = NULL;
	tes->lineno = 0;
	tes->data = drew_mem_malloc(sizeof(*tes->data) * NDATA_CHUNK);
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

	buf = drew_mem_malloc(bufsz);
	while (fgets(buf, bufsz, fp)) {
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
					void **p = drew_mem_realloc(tes->data,
							sizeof(*p) * newsize);
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
	free(buf);
	fclose(fp);
	if (TEST_CODE(ret) == TEST_CORRUPT)
		tes->results = -DREW_ERR_INVALID;
	return tes->results;
}
