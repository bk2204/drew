#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/bignum.h>
#include <drew/pkenc.h>
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
static int rsa_init(drew_pkenc_t *, int,
		const drew_loader_t *, const drew_param_t *);
static int rsa_clone(drew_pkenc_t *, const drew_pkenc_t *, int);
static int rsa_fini(drew_pkenc_t *, int);
static int rsa_generate(drew_pkenc_t *, const drew_param_t *);
static int rsa_setmode(drew_pkenc_t *, int);
static int rsa_setval(drew_pkenc_t *, const char *, const uint8_t *, size_t);
static int rsa_val(const drew_pkenc_t *, const char *, uint8_t *, size_t);
static int rsa_valsize(const drew_pkenc_t *, const char *);
static int rsa_encrypt(const drew_pkenc_t *, drew_bignum_t *,
		const drew_bignum_t *);
static int rsa_decrypt(const drew_pkenc_t *, drew_bignum_t *,
		const drew_bignum_t *);
static int rsa_test(void *, const drew_loader_t *);


static const drew_pkenc_functbl_t rsa_functbl = {
	.info = rsa_info,
	.init = rsa_init,
	.clone = rsa_clone,
	.fini = rsa_fini,
	.generate = rsa_generate,
	.setmode = rsa_setmode,
	.setval = rsa_setval,
	.val = rsa_val,
	.valsize = rsa_valsize,
	.encrypt = rsa_encrypt,
	.decrypt = rsa_decrypt,
	.test = rsa_test
};

static int rsa_info(int op, void *p)
{
	switch (op) {
		case DREW_PKENC_VERSION:
			return 2;
		case DREW_PKENC_INTSIZE:
			return sizeof(struct rsa);
		case DREW_PKENC_PLAIN_BIGNUMS:
			return 1;
		case DREW_PKENC_CIPHER_BIGNUMS:
			return 1;
		default:
			return -DREW_ERR_INVALID;
	}
}

#include "../../multi/rsa/rsa.c"

static int rsa_init(drew_pkenc_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct rsa *newctx = ctx->ctx;
	int res = 0;

	if (!(flags & DREW_PKENC_FIXED))
		newctx = malloc(sizeof(*newctx));

	if ((res = init(newctx, flags, ldr, param)))
		return res;
	
	ctx->ctx = newctx;
	ctx->functbl = &rsa_functbl;

	return 0;
}

static int rsa_fini(drew_pkenc_t *ctx, int flags)
{
	struct rsa *c = ctx->ctx;

	fini(c, flags);

	ctx->ctx = NULL;
	return 0;
}

#define CLONE(new, old, x) do { if (!(old)->x) new->x = NULL; \
	else old->x->functbl->clone(new->x, old->x, 0); } while (0)

static int rsa_clone(drew_pkenc_t *newctx, const drew_pkenc_t *oldctx,
		int flags)
{
	if (!(flags & DREW_PKENC_FIXED))
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

static int rsa_generate(drew_pkenc_t *ctx, const drew_param_t *param)
{
	return -DREW_ERR_NOT_IMPL;
}

static int rsa_setmode(drew_pkenc_t *ctx, int flags)
{
	return 0;
}

static int rsa_setval(drew_pkenc_t *ctx, const char *name, const uint8_t *buf,
		size_t len)
{
	struct rsa *c = ctx->ctx;
	return setval(c, name, buf, len);
}

static int rsa_val(const drew_pkenc_t *ctx, const char *name, uint8_t *data,
		size_t len)
{
	struct rsa *c = ctx->ctx;
	return val(c, name, data, len);
}

static int rsa_valsize(const drew_pkenc_t *ctx, const char *name)
{
	struct rsa *c = ctx->ctx;
	return valsize(c, name);
}

static int rsa_encrypt(const drew_pkenc_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct rsa *c = ctx->ctx;
	return encrypt(c, out, in);
}

static int rsa_decrypt(const drew_pkenc_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct rsa *c = ctx->ctx;
	return decrypt(c, out, in);
}

struct plugin {
	const char *name;
	const drew_pkenc_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "RSAEncryption", &rsa_functbl },
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
			return DREW_TYPE_PKENC;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return sizeof(drew_pkenc_functbl_t);
		case DREW_LOADER_GET_FUNCTBL:
			memcpy(p, plugin_data[id].functbl, sizeof(drew_pkenc_functbl_t));
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
