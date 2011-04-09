#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/bignum.h>
#include <drew/pksig.h>
#include <drew/plugin.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

struct rsa {
	drew_bignum_t *p;
	drew_bignum_t *q;
	drew_bignum_t *u;
	drew_bignum_t *e;
	drew_bignum_t *d;
	drew_bignum_t *n;
};

static int rsa_info(int op, void *p);
static int rsa_init(drew_pksig_t *, int,
		const drew_loader_t *, const drew_param_t *);
static int rsa_clone(drew_pksig_t *, const drew_pksig_t *, int);
static int rsa_fini(drew_pksig_t *, int);
static int rsa_generate(drew_pksig_t *, const drew_param_t *);
static int rsa_setmode(drew_pksig_t *, int);
static int rsa_setval(drew_pksig_t *, const char *, const uint8_t *, size_t);
static int rsa_val(const drew_pksig_t *, const char *, uint8_t *, size_t);
static int rsa_valsize(const drew_pksig_t *, const char *);
static int rsa_sign(const drew_pksig_t *, drew_bignum_t *,
		const drew_bignum_t *);
static int rsa_verify(const drew_pksig_t *, drew_bignum_t *,
		const drew_bignum_t *);
static int rsa_test(void *, const drew_loader_t *);


static const drew_pksig_functbl_t rsa_functbl = {
	.info = rsa_info,
	.init = rsa_init,
	.clone = rsa_clone,
	.fini = rsa_fini,
	.generate = rsa_generate,
	.setmode = rsa_setmode,
	.setval = rsa_setval,
	.val = rsa_val,
	.valsize = rsa_valsize,
	.sign = rsa_sign,
	.verify = rsa_verify,
	.test = rsa_test
};

static int rsa_info(int op, void *p)
{
	switch (op) {
		case DREW_PKSIG_VERSION:
			return 2;
		case DREW_PKSIG_INTSIZE:
			return sizeof(struct rsa);
		case DREW_PKSIG_PLAIN_BIGNUMS:
			return 1;
		case DREW_PKSIG_CIPHER_BIGNUMS:
			return 1;
		default:
			return -DREW_ERR_INVALID;
	}
}

#include "../../multi/rsa/rsa.c"

static int rsa_test(void *ptr, const drew_loader_t *ldr)
{
	uint8_t p[] = {0x3d}, q[] = {0x35}, n[] = {0x0c, 0xa1}, e[] = {0x11},
			d[] = {0x0a, 0xc1}, m[] = {0x41}, c[] = {0x0a, 0xe6};
	uint8_t buf[2];
	const void *functbl;
	drew_pksig_t ctx;
	int res = 0, id;
	drew_param_t param;
	const char *bignum = "Bignum";
	drew_bignum_t bns[1];

	param.next = NULL;
	param.name = "bignum";
	param.param.string = bignum;

	id = drew_loader_lookup_by_name(ldr, bignum, 0, -1);
	if (id < 0)
		return id;
	if (drew_loader_get_type(ldr, id) != DREW_TYPE_BIGNUM)
		return -DREW_ERR_INVALID;
	if ((res = drew_loader_get_functbl(ldr, id, &functbl)) < 0)
		return res;
	bns[0].functbl = functbl;

	res = 0;

	bns[0].functbl->init(&bns[0], 0, ldr, NULL);

	ctx.functbl = &rsa_functbl;
	if (ctx.functbl->init(&ctx, 0, ldr, &param) != 0)
		return 3;
	ctx.functbl->setval(&ctx, "p", p, DIM(p));
	ctx.functbl->setval(&ctx, "q", q, DIM(q));
	ctx.functbl->setval(&ctx, "n", n, DIM(n));
	ctx.functbl->setval(&ctx, "e", e, DIM(e));
	ctx.functbl->setval(&ctx, "d", d, DIM(d));
	bns[0].functbl->setbytes(&bns[0], c, sizeof(c));
	ctx.functbl->sign(&ctx, bns, bns);
	bns[0].functbl->bytes(&bns[0], buf, sizeof(buf));
	res |= !!memcmp(buf, m, sizeof(m));
	bns[0].functbl->setbytes(&bns[0], m, sizeof(m));
	ctx.functbl->verify(&ctx, bns, bns);
	bns[0].functbl->bytes(&bns[0], buf, sizeof(buf));
	res <<= 1;
	res |= !!memcmp(buf, c, sizeof(c));
	ctx.functbl->fini(&ctx, 0);
	bns[0].functbl->fini(&bns[0], 0);

	return res;
}

static int rsa_init(drew_pksig_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct rsa *newctx = ctx->ctx;
	int res = 0;

	if (!(flags & DREW_PKSIG_FIXED))
		newctx = malloc(sizeof(*newctx));

	if ((res = init(newctx, flags, ldr, param)))
		return res;
	
	ctx->ctx = newctx;
	ctx->functbl = &rsa_functbl;

	return 0;
}

static int rsa_fini(drew_pksig_t *ctx, int flags)
{
	struct rsa *c = ctx->ctx;

	fini(c, flags);
	if (!(flags & DREW_PKSIG_FIXED))
		free(c);

	ctx->ctx = NULL;
	return 0;
}

#define CLONE(new, old, x) do { if (!(old)->x) new->x = NULL; \
	else old->x->functbl->clone(new->x, old->x, 0); } while (0)

static int rsa_clone(drew_pksig_t *newctx, const drew_pksig_t *oldctx,
		int flags)
{
	if (!(flags & DREW_PKSIG_FIXED))
		newctx->ctx = malloc(sizeof(struct rsa));

	memset(newctx->ctx, 0, sizeof(struct rsa));

	struct rsa *new = newctx->ctx, *old = oldctx->ctx;
	CLONE(new, old, p);
	CLONE(new, old, q);
	CLONE(new, old, u);
	CLONE(new, old, e);
	CLONE(new, old, d);
	CLONE(new, old, n);
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int rsa_generate(drew_pksig_t *ctx, const drew_param_t *param)
{
	return -DREW_ERR_NOT_IMPL;
}

static int rsa_setmode(drew_pksig_t *ctx, int flags)
{
	return 0;
}

static int rsa_setval(drew_pksig_t *ctx, const char *name, const uint8_t *buf,
		size_t len)
{
	struct rsa *c = ctx->ctx;
	return setval(c, name, buf, len);
}

static int rsa_val(const drew_pksig_t *ctx, const char *name, uint8_t *data,
		size_t len)
{
	struct rsa *c = ctx->ctx;
	return val(c, name, data, len);
}

static int rsa_valsize(const drew_pksig_t *ctx, const char *name)
{
	struct rsa *c = ctx->ctx;
	return valsize(c, name);
}

static int rsa_sign(const drew_pksig_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct rsa *c = ctx->ctx;
	return decrypt(c, out, in);
}

static int rsa_verify(const drew_pksig_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct rsa *c = ctx->ctx;
	return encrypt(c, out, in);
}

struct plugin {
	const char *name;
	const drew_pksig_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "RSASignature", &rsa_functbl },
};

int drew_plugin_info(void *ldr, int op, int id, void *p)
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
			return DREW_TYPE_PKSIG;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return sizeof(drew_pksig_functbl_t);
		case DREW_LOADER_GET_FUNCTBL:
			memcpy(p, plugin_data[id].functbl, sizeof(drew_pksig_functbl_t));
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
