#include "internal.h"

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
static int bn_breduceinit(drew_bignum_t *, const drew_bignum_t *);
static int bn_breduce(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *, const drew_bignum_t *);
static int bn_mreduceinit(drew_bignum_t *, const drew_bignum_t *);
static int bn_mreduce(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *, const drew_bignum_t *);
static int bn_mreduceconst(drew_bignum_t *, const drew_bignum_t *);
static int bn_drreduceinit(drew_bignum_t *, const drew_bignum_t *);
static int bn_drreduce(drew_bignum_t *, const drew_bignum_t *,
		const drew_bignum_t *, const drew_bignum_t *);
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
	.breduceinit = bn_breduceinit,
	.breduce = bn_breduce,
	.mreduceinit = bn_mreduceinit,
	.mreduce = bn_mreduce,
	.mreduceconst = bn_mreduceconst,
	.drreduceinit = bn_drreduceinit,
	.drreduce = bn_drreduce,
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
	mp_init(BMP(newctx));
	
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
	COPY(res, in);
	RETFAIL(mp_lshd(MP(res), n));
	return 0;
}

static int bn_shiftright(drew_bignum_t *res, const drew_bignum_t *in, size_t n)
{
	COPY(res, in);
	mp_rshd(MP(res), n);
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

static int bn_expmod(drew_bignum_t *res, const drew_bignum_t *g,
		const drew_bignum_t *x, const drew_bignum_t *mod)
{
	RETFAIL(mp_exptmod(MPC(g), MPC(x), MPC(mod), MP(res)));
	return 0;
}

static int bn_invmod(drew_bignum_t *res, const drew_bignum_t *a,
		const drew_bignum_t *mod)
{
	RETFAIL(mp_invmod(MPC(a), MPC(mod), MP(mod)));
	return 0;
}

static int bn_breduceinit(drew_bignum_t *mu, const drew_bignum_t *mod)
{
	RETFAIL(mp_reduce_setup(MP(mu), MPC(mod)));
	return 0;
}

static int bn_breduce(drew_bignum_t *res, const drew_bignum_t *a,
		const drew_bignum_t *mod, const drew_bignum_t *mu)
{
	COPY(res, a);
	RETFAIL(mp_reduce(MP(res), MPC(mod), MPC(mu)));
	return 0;
}

static int bn_mreduceinit(drew_bignum_t *mp, const drew_bignum_t *a)
{
	RETFAIL(mp_montgomery_setup(MPC(a), DIG(mp)));
	return 0;
}

static int bn_mreduce(drew_bignum_t *res, const drew_bignum_t *a,
		const drew_bignum_t *mod, const drew_bignum_t *mp)
{
	COPY(res, a);
	RETFAIL(mp_montgomery_reduce(MP(res), MPC(mod), *DIG(mp)));
	return 0;
}

static int bn_mreduceconst(drew_bignum_t *k, const drew_bignum_t *mod)
{
	RETFAIL(mp_montgomery_calc_normalization(MP(k), MPC(mod)));
	return 0;
}

static int bn_drreduceinit(drew_bignum_t *mp, const drew_bignum_t *mod)
{
	RETFAIL(mp_reduce_2k_setup(MPC(mod), DIG(mp)));
	return 0;
}

static int bn_drreduce(drew_bignum_t *res, const drew_bignum_t *a,
		const drew_bignum_t *mod, const drew_bignum_t *mp)
{
	COPY(res, a);
	RETFAIL(mp_reduce_2k(MP(res), MPC(mod), *DIG(mp)));
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
