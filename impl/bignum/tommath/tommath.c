/*-
 * Copyright © 2011 brian m. carlson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "internal.h"
#include "util.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <tommath.h>

#include <drew/bignum.h>
#include <drew/plugin.h>

// "Bare" MP and MPConstant, "Bare" DIGit and DIGitConstant.
#define BMP(x) (&(((struct bignum *)(x))->mp))
#define BMPC(x) ((mp_int *)(&(((const struct bignum *)(x))->mp)))
#define BDIG(x) (&(((struct bignum *)(x))->dig))
#define BDIGC(x) ((mp_digit *)(&(((const struct bignum *)(x))->dig)))
// Context to MP and MPConstant or DIGit and DIGitConstant.
#define MP(x) BMP((x)->ctx)
#define MPC(x) BMPC((x)->ctx)
#define DIG(x) BDIG((x)->ctx)
#define DIGC(x) BDIGC((x)->ctx)
#undef RETFAIL
#define RETFAIL(x) do { int failret = (x); \
	if (failret != MP_OKAY) return fixup_return(failret); } while (0)
#define COPY(to, from) do { \
	if (to != from) RETFAIL(mp_copy(MPC(from), MP(to))); } while (0)

HIDE()
struct bignum {
	mp_int mp;
	mp_digit dig;
};

static inline int fixup_return(int val)
{
	switch (val) {
		case MP_VAL:
			return -DREW_ERR_INVALID;
		case MP_MEM:
			return -ENOMEM;
		case MP_OKAY:
			return 0;
		default:
			return -DREW_ERR_BUG;
	}
}

static int bn_info(int op, void *p);
static int bn_info2(const drew_bignum_t *, int, drew_param_t *,
		const drew_param_t *);
static int bn_init(drew_bignum_t *, int, const drew_loader_t *,
		const drew_param_t *);
static int bn_clone(drew_bignum_t *, const drew_bignum_t *, int);
static int bn_fini(drew_bignum_t *, int);
static int bn_nbits(const drew_bignum_t *);
static int bn_nbytes(const drew_bignum_t *);
static int bn_bytes(const drew_bignum_t *, uint8_t *, size_t);
static int bn_setbytes(drew_bignum_t *, const uint8_t *, size_t);
static int bn_setzero(drew_bignum_t *);
static int bn_setsmall(drew_bignum_t *, long);
static int bn_negate(drew_bignum_t *, const drew_bignum_t *);
static int bn_abs(drew_bignum_t *, const drew_bignum_t *);
static int bn_compare(const drew_bignum_t *, const drew_bignum_t *, int);
static int bn_comparesmall(const drew_bignum_t *, long);
static int bn_bitwiseor(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_bitwiseand(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_bitwisexor(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_bitwisenot(drew_bignum_t *, const drew_bignum_t *);
static int bn_getbit(const drew_bignum_t *, size_t);
static int bn_setbit(drew_bignum_t *, size_t, bool);
static int bn_add(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_sub(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_mul(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_div(drew_bignum_t *, drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_mulpow2(drew_bignum_t *, const drew_bignum_t *, size_t);
static int bn_divpow2(drew_bignum_t *, drew_bignum_t *, const drew_bignum_t *,
		size_t);
static int bn_shiftleft(drew_bignum_t *, const drew_bignum_t *, size_t);
static int bn_shiftright(drew_bignum_t *, const drew_bignum_t *, size_t);
static int bn_square(drew_bignum_t *, const drew_bignum_t *);
static int bn_mod(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
static int bn_expsmall(drew_bignum_t *, const drew_bignum_t *, unsigned long);
static int bn_expmod(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *, const drew_bignum_t *);
static int bn_squaremod(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_addmod(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *, const drew_bignum_t *);
static int bn_mulmod(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *, const drew_bignum_t *);
static int bn_invmod(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_gcd(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_test(void *, const drew_loader_t *);


static const drew_bignum_functbl_t bn_functbl = {
	.info = bn_info,
	.info2 = bn_info2,
	.init = bn_init,
	.clone = bn_clone,
	.fini = bn_fini,
	.nbits = bn_nbits,
	.nbytes = bn_nbytes,
	.bytes = bn_bytes,
	.setbytes = bn_setbytes,
	.setzero = bn_setzero,
	.setsmall = bn_setsmall,
	.negate = bn_negate,
	.abs = bn_abs,
	.compare = bn_compare,
	.comparesmall = bn_comparesmall,
	.bitwiseor = bn_bitwiseor,
	.bitwiseand = bn_bitwiseand,
	.bitwisexor = bn_bitwisexor,
	.bitwisenot = bn_bitwisenot,
	.getbit = bn_getbit,
	.setbit = bn_setbit,
	.add = bn_add,
	.sub = bn_sub,
	.mul = bn_mul,
	.div = bn_div,
	.mulpow2 = bn_mulpow2,
	.divpow2 = bn_divpow2,
	.shiftleft = bn_shiftleft,
	.shiftright = bn_shiftright,
	.square = bn_square,
	.mod = bn_mod,
	.expsmall = bn_expsmall,
	.squaremod = bn_squaremod,
	.addmod = bn_addmod,
	.mulmod = bn_mulmod,
	.expmod = bn_expmod,
	.invmod = bn_invmod,
	.gcd = bn_gcd,
	.test = bn_test
};

static int bn_info(int op, void *p)
{
	switch (op) {
		case DREW_BIGNUM_VERSION:
			return CURRENT_ABI;
		case DREW_BIGNUM_INTSIZE:
			return sizeof(struct bignum);
		default:
			return -DREW_ERR_INVALID;
	}
}

static int bn_info2(const drew_bignum_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return bn_info(op, NULL);
}

static int bn_init(drew_bignum_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct bignum *newctx = ctx->ctx;

	if (!(flags & DREW_BIGNUM_FIXED))
		newctx = malloc(sizeof(*newctx));
	mp_init(BMP(newctx));
	
	ctx->ctx = newctx;
	ctx->functbl = &bn_functbl;

	return 0;
}

static int bn_test(void *p, const drew_loader_t *ldr)
{
	return -DREW_ERR_NOT_IMPL;
}

static int bn_nbits(const drew_bignum_t *ctx)
{
	int nbytes;
	drew_bignum_t t1, *t = &t1;
	RETFAIL(bn_clone(t, ctx, 0));
	nbytes = bn_nbytes(t);
	for (int i = 0; i < 8; i++) {
		RETFAIL(bn_shiftright(t, t, 1));
		if (nbytes != bn_nbytes(t)) {
			bn_fini(t, 0);
			return (nbytes * 8) - i - 1;
		}
	}
	return -DREW_ERR_BUG;
}

static int bn_nbytes(const drew_bignum_t *ctx)
{
	return mp_unsigned_bin_size(MPC(ctx));
}

static int bn_bytes(const drew_bignum_t *ctx, uint8_t *data, size_t len)
{
	RETFAIL(mp_to_unsigned_bin(MPC(ctx), data));
	if (MPC(ctx)->sign)
		return 1;
	return 0;
}

static int bn_setbytes(drew_bignum_t *ctx, const uint8_t *data,
		size_t len)
{
	RETFAIL(mp_read_unsigned_bin(MP(ctx), data, len));
	return 0;
}

static int bn_setzero(drew_bignum_t *ctx)
{
	mp_set(MP(ctx), 0);
	return 0;
}

static int bn_setsmall(drew_bignum_t *ctx, long v)
{
	unsigned long a = labs(v);
	mp_set(MP(ctx), a);
	if (v < 0)
		return bn_negate(ctx, ctx);
	return 0;
}

static int bn_negate(drew_bignum_t *res, const drew_bignum_t *in)
{
	RETFAIL(mp_neg(MPC(in), MP(res)));
	return 0;
}

static int bn_abs(drew_bignum_t *res, const drew_bignum_t *in)
{
	RETFAIL(mp_abs(MPC(in), MP(res)));
	return 0;
}

static int bn_compare(const drew_bignum_t *a, const drew_bignum_t *b, int flag)
{
	int res = (flag & DREW_BIGNUM_ABS) ? mp_cmp_mag(MP(a), MP(b)) :
		mp_cmp(MP(a), MP(b));
	return (res == MP_GT) ? 1 : ((res == MP_EQ) ? 0 : -1);
}

static int bn_comparesmall(const drew_bignum_t *ctx, long x)
{
	int res = mp_cmp_d(MPC(ctx), x);
	return (res == MP_GT) ? 1 : ((res == MP_EQ) ? 0 : -1);
}

static int bn_bitwiseor(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	RETFAIL(mp_or(MPC(a), MPC(b), MP(c)));
	return 0;
}

static int bn_bitwiseand(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	RETFAIL(mp_and(MPC(a), MPC(b), MP(c)));
	return 0;
}

static int bn_bitwisexor(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	RETFAIL(mp_xor(MPC(a), MPC(b), MP(c)));
	return 0;
}

static int bn_bitwisenot(drew_bignum_t *res, const drew_bignum_t *in)
{
	int nbytes = bn_nbytes(in);
	if (nbytes < 0)
		return nbytes;
	uint8_t *buf = malloc(nbytes);
	if (!buf)
		return -ENOMEM;
	mp_to_unsigned_bin(MP(in), buf);
	for (int i = 0; i < nbytes; i++)
		buf[i] = ~buf[i];
	mp_read_unsigned_bin(MP(res), buf, nbytes);
	memset(buf, 0, nbytes);
	free(buf);
	return 0;
}

static int bn_getbit(const drew_bignum_t *ctx, size_t bitno)
{
	bool bitval;
	drew_bignum_t t1, *t = &t1;
	RETFAIL(bn_clone(t, ctx, 0));
	RETFAIL(bn_setsmall(t, 1));
	RETFAIL(bn_shiftleft(t, t, bitno));
	RETFAIL(bn_bitwiseand(t, t, ctx));
	bitval = bn_comparesmall(t, 0);
	RETFAIL(bn_fini(t, 0));
	return bitval;
}

static int bn_setbit(drew_bignum_t *ctx, size_t bitno, bool val)
{
	drew_bignum_t t1, *t = &t1;
	RETFAIL(bn_clone(t, ctx, 0));
	RETFAIL(bn_setsmall(t, 1));
	RETFAIL(bn_shiftleft(t, t, bitno));
	if (val)
		RETFAIL(bn_bitwiseor(ctx, t, ctx));
	else {
		RETFAIL(bn_bitwisenot(t, t));
		RETFAIL(bn_bitwiseand(ctx, t, ctx));
	}
	RETFAIL(bn_fini(t, 0));
	return 0;
}

static int bn_add(drew_bignum_t *res, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	RETFAIL(mp_add(MPC(a), MPC(b), MP(res)));
	return 0;
}

static int bn_sub(drew_bignum_t *res, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	RETFAIL(mp_sub(MPC(a), MPC(b), MP(res)));
	return 0;
}

static int bn_mul(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	RETFAIL(mp_mul(MPC(a), MPC(b), MP(c)));
	return 0;
}

static int bn_div(drew_bignum_t *quot, drew_bignum_t *rem,
		const drew_bignum_t *dividend, const drew_bignum_t *divisor)
{
	RETFAIL(mp_div(MPC(dividend), MPC(divisor), MP(quot), MP(rem)));
	return 0;
}

static int bn_mulpow2(drew_bignum_t *c, const drew_bignum_t *a, size_t b)
{
	RETFAIL(mp_mul_2d(MPC(a), b, MP(c)));
	return 0;
}

static int bn_divpow2(drew_bignum_t *quot, drew_bignum_t *rem,
		const drew_bignum_t *a, size_t b)
{
	RETFAIL(mp_div_2d(MPC(a), b, MP(quot), MP(rem)));
	return 0;
}

static int bn_shiftleft(drew_bignum_t *res, const drew_bignum_t *in, size_t n)
{
	return bn_mulpow2(res, in, n);
}

static int bn_shiftright(drew_bignum_t *res, const drew_bignum_t *in, size_t n)
{
	RETFAIL(mp_div_2d(MPC(in), n, MP(res), NULL));
	return 0;
}

static int bn_square(drew_bignum_t *res, const drew_bignum_t *in)
{
	RETFAIL(mp_sqr(MPC(in), MP(res)));
	return 0;
}

static int bn_mod(drew_bignum_t *res, const drew_bignum_t *a,
		const drew_bignum_t *mod)
{
	RETFAIL(mp_mod(MPC(a), MPC(mod), MP(res)));
	return 0;
}

static int bn_expsmall(drew_bignum_t *res, const drew_bignum_t *a,
		unsigned long exp)
{
	RETFAIL(mp_expt_d(MPC(a), exp, MP(res)));
	return 0;
}

static int bn_squaremod(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *n)
{
	RETFAIL(bn_square(c, a));
	RETFAIL(bn_mod(c, c, n));
	return 0;
}

static int bn_addmod(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *b, const drew_bignum_t *n)
{
	RETFAIL(bn_add(c, a, b));
	RETFAIL(bn_mod(c, c, n));
	return 0;
}

static int bn_mulmod(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *b, const drew_bignum_t *n)
{
	RETFAIL(bn_mul(c, a, b));
	RETFAIL(bn_mod(c, c, n));
	return 0;
}

static int bn_expmod(drew_bignum_t *res, const drew_bignum_t *g,
		const drew_bignum_t *x, const drew_bignum_t *mod)
{
	RETFAIL(mp_exptmod(MPC(g), MPC(x), MPC(mod), MP(res)));
	return 0;
}

static int bn_invmod(drew_bignum_t *res, const drew_bignum_t *a,
		const drew_bignum_t *mod)
{
	RETFAIL(mp_invmod(MPC(a), MPC(mod), MP(res)));
	return 0;
}

static int bn_gcd(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	RETFAIL(mp_gcd(MPC(a), MPC(b), MP(c)));
	return 0;
}

static int bn_fini(drew_bignum_t *ctx, int flags)
{
	struct bignum *c = ctx->ctx;

	mp_clear(BMP(c));
	memset(c, 0, sizeof(*c));
	if (!(flags & DREW_BIGNUM_FIXED))
		free(c);

	ctx->ctx = NULL;
	return 0;
}

static int bn_clone(drew_bignum_t *newctx, const drew_bignum_t *oldctx, int flags)
{
	if (!(flags & DREW_BIGNUM_FIXED))
		newctx->ctx = malloc(sizeof(struct bignum));

	memset(newctx->ctx, 0, sizeof(struct bignum));

	struct bignum *new = newctx->ctx, *old = oldctx->ctx;
	new->dig = old->dig;
	COPY(newctx, oldctx);
	newctx->functbl = oldctx->functbl;
	return 0;
}

struct plugin {
	const char *name;
	const drew_bignum_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "Bignum", &bn_functbl },
	{ "BignumTomMath", &bn_functbl }
};

EXPORT()
int DREW_PLUGIN_NAME(tommath)(void *ldr, int op, int id, void *p)
{
	int nplugins = sizeof(plugin_data)/sizeof(plugin_data[0]);

	if (id < 0 || id >= nplugins)
		return -DREW_ERR_INVALID;

	switch (op) {
		case DREW_LOADER_LOOKUP_NAME:
			return 0;
		case DREW_LOADER_GET_NPLUGINS:
			return nplugins;
		case DREW_LOADER_GET_TYPE:
			return DREW_TYPE_BIGNUM;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return sizeof(drew_bignum_functbl_t);
		case DREW_LOADER_GET_FUNCTBL:
			memcpy(p, plugin_data[id].functbl, sizeof(drew_bignum_functbl_t));
			return 0;
		case DREW_LOADER_GET_NAME_SIZE:
			return strlen(plugin_data[id].name) + 1;
		case DREW_LOADER_GET_NAME:
			memcpy(p, plugin_data[id].name, strlen(plugin_data[id].name)+1);
			return 0;
		default:
			return -DREW_ERR_INVALID;
	}
}
UNEXPORT()
UNHIDE()
