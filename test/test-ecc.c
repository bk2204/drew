/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different elliptic curves.
 * This implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <drew/drew.h>
#include <drew/bignum.h>
#include <drew/ecc.h>
#include <drew/plugin.h>

#define FILENAME "test/vectors-ecc"

int test_get_type(void)
{
	return DREW_TYPE_ECC;
}

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return NULL;
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_ecc_functbl_t *functbl = tbl;
	
	return print_test_results(functbl->test(NULL, ldr), NULL);
}

#define STUBS_EXTERNAL 1
#define STUBS_API 1
#include "stubs.c"

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks)
{
	return -DREW_ERR_NOT_IMPL;
}
