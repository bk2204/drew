/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements a test driver for several different BIGNUMs.  This
 * implementation requires ANSI C and POSIX 1003.1-2001.
 */

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <drew/plugin.h>
#include <drew/bignum.h>

int test_get_type(void)
{
	return DREW_TYPE_BIGNUM;
}

const char *test_get_default_algo(drew_loader_t *ldr, const char *name)
{
	return NULL;
}

int test_internal(drew_loader_t *ldr, const char *name, const void *tbl)
{
	const drew_bignum_functbl_t *functbl = tbl;

	return print_test_results(functbl->test(NULL, ldr), NULL);
}

static inline int test_speed_loop(drew_bignum_t *ctx, uint8_t *buf,
		uint8_t *mod, int chunk, int nchunks)
{
	int i;
	drew_bignum_t bn, *ctp = &bn, kbn, *kbp = &kbn;

	ctx->functbl->init(kbp, 0, NULL, NULL);
	ctx->functbl->init(ctx, 0, NULL, NULL);
	ctx->functbl->init(ctp, 0, NULL, NULL);
	kbp->functbl->setsmall(kbp, 65537);
	ctx->functbl->setbytes(ctx, buf, chunk);
	ctp->functbl->setbytes(ctp, mod, chunk+1);
	for (i = 0; !framework_sigflag && i < nchunks; i++)
		ctx->functbl->expmod(ctx, ctx, kbp, ctp);
	kbp->functbl->fini(kbp, 0);
	ctx->functbl->fini(ctx, 0);
	ctp->functbl->fini(ctp, 0);

	return i;
}

#define STUBS_EXTERNAL 1
#define STUBS_API 1
#include "stubs.c"

int test_speed(drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl, int chunk, int nchunks, int flags)
{
	int i;
	uint8_t *buf, *mod;
	struct timespec cstart, cend;
	drew_bignum_t ctx;
	void *fwdata;

	ctx.functbl = tbl;

	// We take the chunk size as bits here.
	if (chunk > 4096)
		chunk = 2048;
	chunk /= 8;

	buf = malloc(chunk);
	if (!buf)
		return ENOMEM;

	mod = malloc(chunk+1);
	if (!mod)
		return ENOMEM;

	// Make sure the top and bottom bits are one and that there's at least some
	// ones elsewhere in there.
	buf[0] = mod[0] = 0x80;
	buf[chunk-1] = mod[chunk] = 0xff;

	fwdata = framework_setup();

	clock_gettime(USED_CLOCK, &cstart);
	i = test_speed_loop(&ctx, buf, mod, chunk, nchunks);
	clock_gettime(USED_CLOCK, &cend);

	framework_teardown(fwdata);

	free(buf);
	free(mod);

	print_speed_info(chunk, i, &cstart, &cend);

	return 0;
}
