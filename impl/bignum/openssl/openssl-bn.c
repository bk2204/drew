#include "internal.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include <drew/bignum.h>
#include <drew/plugin.h>

struct bignum {
	BIGNUM *bn;
};

#define NEW_CTX(x) \
	do { \
		if (!(x = BN_CTX_new())) \
			return -ENOMEM; \
	} while (0)
#define DEL_CTX(x) BN_CTX_free(x)
#define MP(x) (((struct bignum *)((x)->ctx))->bn)
#undef RETFAIL
#define RETFAIL(x) \
	do { \
		if (!(x)) \
			return -ENOMEM; \
	} while (0)

static int bn_info(int op, void *p);
static int bn_init(drew_bignum_t *, int, const drew_loader_t *,
		const drew_param_t *);
static int bn_clone(drew_bignum_t *, const drew_bignum_t *, int);
static int bn_fini(drew_bignum_t *, int);
static int bn_nbytes(const drew_bignum_t *);
static int bn_bytes(const drew_bignum_t *, uint8_t *, size_t);
static int bn_setbytes(drew_bignum_t *, const uint8_t *, size_t);
static int bn_setzero(drew_bignum_t *);
static int bn_setsmall(drew_bignum_t *, long);
static int bn_negate(drew_bignum_t *, const drew_bignum_t *);
static int bn_abs(drew_bignum_t *, const drew_bignum_t *);
static int bn_compare(const drew_bignum_t *, const drew_bignum_t *, int);
static int bn_bitwiseor(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_bitwiseand(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_bitwisexor(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_bitwisenot(drew_bignum_t *, const drew_bignum_t *);
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
static int bn_invmod(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *);
static int bn_test(void *, const drew_loader_t *);


static const drew_bignum_functbl_t bn_functbl = {
	.info = bn_info,
	.init = bn_init,
	.clone = bn_clone,
	.fini = bn_fini,
	.nbytes = bn_nbytes,
	.bytes = bn_bytes,
	.setbytes = bn_setbytes,
	.setzero = bn_setzero,
	.setsmall = bn_setsmall,
	.negate = bn_negate,
	.abs = bn_abs,
	.compare = bn_compare,
	.bitwiseor = bn_bitwiseor,
	.bitwiseand = bn_bitwiseand,
	.bitwisexor = bn_bitwisexor,
	.bitwisenot = bn_bitwisenot,
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
	.expmod = bn_expmod,
	.invmod = bn_invmod,
	.test = bn_test
};

static int bn_info(int op, void *p)
{
	switch (op) {
		case DREW_BIGNUM_VERSION:
			return 2;
		case DREW_BIGNUM_INTSIZE:
			return sizeof(struct bignum);
		default:
			return -DREW_ERR_INVALID;
	}
}

static int bn_init(drew_bignum_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct bignum *newctx = ctx->ctx;

	if (!(flags & DREW_BIGNUM_FIXED))
		newctx = malloc(sizeof(*newctx));
	if (!(newctx->bn = BN_new())) {
		free(newctx);
		return -ENOMEM;
	}
	
	ctx->ctx = newctx;
	ctx->functbl = &bn_functbl;

	return 0;
}

static int bn_test(void *p, const drew_loader_t *ldr)
{
	return -DREW_ERR_NOT_IMPL;
}

static int bn_nbytes(const drew_bignum_t *ctx)
{
	return BN_num_bytes(MP(ctx));
}

static int bn_bytes(const drew_bignum_t *ctx, uint8_t *data, size_t len)
{
	if (data && len)
		BN_bn2bin(MP(ctx), data);
	return !!BN_is_negative(MP(ctx));
}

static int bn_setbytes(drew_bignum_t *ctx, const uint8_t *data,
		size_t len)
{
	return !BN_bin2bn(data, len, MP(ctx));
}

static int bn_setzero(drew_bignum_t *ctx)
{
	return !BN_zero(MP(ctx));
}

static int bn_setsmall(drew_bignum_t *ctx, long v)
{
	unsigned long a = labs(v);
	if (!BN_set_word(MP(ctx), a))
		return -ENOMEM;
	if (v < 0)
		return bn_negate(ctx, ctx);
	return 0;
}

static int bn_negate(drew_bignum_t *res, const drew_bignum_t *in)
{
	BN_set_negative(MP(res), !BN_is_negative(MP(in)));
	return 0;
}

static int bn_abs(drew_bignum_t *res, const drew_bignum_t *in)
{
	if (BN_is_negative(MP(res)))
		bn_negate(res, in);
	else if (!BN_copy(MP(res), MP(in)))
		return -ENOMEM;
	return 0;
}

static int bn_compare(const drew_bignum_t *a, const drew_bignum_t *b, int flag)
{
	if (flag & DREW_BIGNUM_ABS)
		return BN_ucmp(MP(a), MP(b));
	return BN_cmp(MP(a), MP(b));
}

/* The bitwise operations are not very efficient in OpenSSL.  Oh, well. */
static int bn_bitwiseor(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	int bbits = BN_num_bits(MP(b));
	BN_copy(MP(c), MP(a));
	for (int i = 0; i < bbits; i++) {
		if (BN_is_bit_set(MP(b), i))
			BN_set_bit(MP(c), i);
	}
	return 0;
}

static int bn_bitwiseand(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	int bbits = BN_num_bits(MP(b));
	BN_copy(MP(c), MP(a));
	for (int i = 0; i < bbits; i++) {
		if (!BN_is_bit_set(MP(b), i))
			BN_clear_bit(MP(c), i);
	}
	return 0;
}

static int bn_bitwisexor(drew_bignum_t *c, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	int bbits = BN_num_bits(MP(b));
	BN_copy(MP(c), MP(a));
	for (int i = 0; i < bbits; i++) {
		if (BN_is_bit_set(MP(b), i))
			BN_clear_bit(MP(c), i);
		else
			BN_set_bit(MP(c), i);
	}
	return 0;
}

static int bn_bitwisenot(drew_bignum_t *res, const drew_bignum_t *in)
{
	int bits = BN_num_bits(MP(in));
	BN_copy(MP(res), MP(in));
	for (int i = 0; i < bits; i++) {
		if (BN_is_bit_set(MP(in), i))
			BN_clear_bit(MP(res), i);
		else
			BN_set_bit(MP(res), i);
	}
	return 0;
}

static int bn_add(drew_bignum_t *res, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	return !BN_add(MP(res), MP(a), MP(b));
}

static int bn_sub(drew_bignum_t *res, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	return !BN_sub(MP(res), MP(a), MP(b));
}

static int bn_mul(drew_bignum_t *r, const drew_bignum_t *a,
		const drew_bignum_t *b)
{
	int res = 0;
	BN_CTX *ctx;
	NEW_CTX(ctx);
	res = !BN_mul(MP(r), MP(a), MP(b), ctx);
	DEL_CTX(ctx);
	return res;
}

static int bn_div(drew_bignum_t *quot, drew_bignum_t *rem,
		const drew_bignum_t *dividend, const drew_bignum_t *divisor)
{
	int res = 0;
	BN_CTX *ctx;
	NEW_CTX(ctx);
	res = !BN_div(MP(quot), MP(rem), MP(dividend), MP(divisor), ctx);
	DEL_CTX(ctx);
	return res;
}

static int bn_mulpow2(drew_bignum_t *c, const drew_bignum_t *a, size_t b)
{
	return !BN_lshift(MP(c), MP(a), b);
}

static int bn_divpow2(drew_bignum_t *quot, drew_bignum_t *rem,
		const drew_bignum_t *a, size_t b)
{
	if (rem) {
		BN_copy(MP(rem), MP(a));
		BN_mask_bits(MP(rem), b);
	}
	return !BN_rshift(MP(quot), MP(a), b);
}

static int bn_shiftleft(drew_bignum_t *res, const drew_bignum_t *in, size_t n)
{
	return bn_mulpow2(res, in, n);
}

static int bn_shiftright(drew_bignum_t *res, const drew_bignum_t *in, size_t n)
{
	return !BN_rshift(MP(res), MP(in), n);
}

static int bn_square(drew_bignum_t *r, const drew_bignum_t *in)
{
	int res = 0;
	BN_CTX *ctx;
	NEW_CTX(ctx);
	res = !BN_sqr(MP(r), MP(in), ctx);
	DEL_CTX(ctx);
	return res;
}

static int bn_mod(drew_bignum_t *r, const drew_bignum_t *a,
		const drew_bignum_t *mod)
{
	int res = 0;
	BN_CTX *ctx;
	NEW_CTX(ctx);
	res = !BN_mod(MP(r), MP(a), MP(mod), ctx);
	DEL_CTX(ctx);
	return res;
}

static int bn_expsmall(drew_bignum_t *r, const drew_bignum_t *a,
		unsigned long exp)
{
	int res = 0;
	BN_CTX *ctx;
	BIGNUM *bn = BN_new();
	if (!bn)
		return -ENOMEM;
	if (!BN_set_word(bn, exp))
		return -ENOMEM;
	NEW_CTX(ctx);
	res = !BN_exp(MP(r), MP(a), bn, ctx);
	DEL_CTX(ctx);
	BN_free(bn);
	return res;
}

static int bn_expmod(drew_bignum_t *r, const drew_bignum_t *g,
		const drew_bignum_t *x, const drew_bignum_t *mod)
{
	int res = 0;
	BN_CTX *ctx;
	NEW_CTX(ctx);
	res = !BN_mod_exp(MP(r), MP(g), MP(x), MP(mod), ctx);
	DEL_CTX(ctx);
	return res;
}

static int bn_invmod(drew_bignum_t *r, const drew_bignum_t *a,
		const drew_bignum_t *mod)
{
	int res = 0;
	BN_CTX *ctx;
	NEW_CTX(ctx);
	res = !BN_mod_inverse(MP(r), MP(a), MP(mod), ctx);
	DEL_CTX(ctx);
	return res;
}

static int bn_fini(drew_bignum_t *ctx, int flags)
{
	struct bignum *c = ctx->ctx;

	BN_free(c->bn);
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
	if (!BN_copy(new->bn, old->bn))
		return -ENOMEM;
	newctx->functbl = oldctx->functbl;
	return 0;
}

struct plugin {
	const char *name;
	const drew_bignum_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "Bignum", &bn_functbl },
	{ "BignumOpenSSL", &bn_functbl }
};

int DREW_PLUGIN_NAME(tommath)(void *ldr, int op, int id, void *p)
{
	int nplugins = sizeof(plugin_data)/sizeof(plugin_data[0]);

	if (id < 0 || id >= nplugins)
		return -EINVAL;

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
			return -EINVAL;
	}
}
