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

static drew_bignum_t *init_bignum(const drew_loader_t *ldr,
		const drew_param_t *param, const void *functbl)
{
	drew_bignum_t *ctx = malloc(sizeof(*ctx));

	ctx->functbl = functbl;
	ctx->functbl->init(ctx, 0, ldr, param);

	return ctx;
}

static int rsa_init(drew_pkenc_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct rsa *newctx = ctx->ctx;
	const void *functbl;
	int id = -1, res = 0;
	const char *bignum = NULL;

	for (const drew_param_t *p = param; p; p = p->next) {
		if (!strcmp(p->name, "bignum")) {
			bignum = p->param.string;
			break;
		}
	}

	if (!bignum)
		return -DREW_ERR_MORE_INFO;

	id = drew_loader_lookup_by_name(ldr, bignum, 0, -1);
	if (id < 0)
		return id;
	if (drew_loader_get_type(ldr, id) != DREW_TYPE_BIGNUM)
		return -DREW_ERR_INVALID;
	if ((res = drew_loader_get_functbl(ldr, id, &functbl)) < 0)
		return res;

	if (!(flags & DREW_PKENC_FIXED))
		newctx = malloc(sizeof(*newctx));

	memset(newctx, 0, sizeof(*newctx));

	// This is a way to avoid having to keep the loader around until later.
	if (!(newctx->n = malloc(sizeof(*newctx->n))))
		return -ENOMEM;
	newctx->p = init_bignum(ldr, param, functbl);
	newctx->q = init_bignum(ldr, param, functbl);
	newctx->e = init_bignum(ldr, param, functbl);
	newctx->d = init_bignum(ldr, param, functbl);
	newctx->n = init_bignum(ldr, param, functbl);
	newctx->u = init_bignum(ldr, param, functbl);
	
	ctx->ctx = newctx;
	ctx->functbl = &rsa_functbl;

	return 0;
}

static int rsa_test(void *ptr, const drew_loader_t *ldr)
{
	uint8_t p[] = {0x3d}, q[] = {0x35}, n[] = {0x0c, 0xa1}, e[] = {0x11},
			d[] = {0x0a, 0xc1}, m[] = {0x41}, c[] = {0x0a, 0xe6};
	uint8_t buf[2];
	const void *functbl;
	drew_pkenc_t ctx;
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
	bns[0].functbl->setbytes(&bns[0], m, sizeof(m));
	ctx.functbl->encrypt(&ctx, bns, bns);
	bns[0].functbl->bytes(&bns[0], buf, sizeof(buf));
	res |= !!memcmp(buf, c, sizeof(c));
	bns[0].functbl->setbytes(&bns[0], c, sizeof(c));
	ctx.functbl->decrypt(&ctx, bns, bns);
	bns[0].functbl->bytes(&bns[0], buf, sizeof(buf));
	res <<= 1;
	res |= !!memcmp(buf, m, sizeof(m));
	ctx.functbl->fini(&ctx, 0);
	bns[0].functbl->fini(&bns[0], 0);

	return res;
}

static void free_bignum(drew_bignum_t *ctx)
{
	ctx->functbl->fini(ctx, 0);
	free(ctx);
}

static int rsa_fini(drew_pkenc_t *ctx, int flags)
{
	struct rsa *c = ctx->ctx;

	// FIXME: free MPIs.
	free_bignum(c->p);
	free_bignum(c->q);
	free_bignum(c->e);
	free_bignum(c->d);
	free_bignum(c->n);
	free_bignum(c->u);
	memset(c, 0, sizeof(*c));
	if (!(flags & DREW_PKENC_FIXED))
		free(c);

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

static inline drew_bignum_t **get_named_mpi(struct rsa *c, const char *name)
{
	if (strlen(name) != 1)
		return NULL;

	switch (name[0]) {
		case 'p':
			return &c->p;
		case 'q':
			return &c->q;
		case 'n':
			return &c->n;
		case 'u':
			return &c->u;
		case 'e':
			return &c->e;
		case 'd':
			return &c->d;
		default:
			return NULL;
	}
}

static int rsa_setval(drew_pkenc_t *ctx, const char *name, const uint8_t *buf,
		size_t len)
{
	struct rsa *c = ctx->ctx;
	drew_bignum_t **p = get_named_mpi(c, name);

	if (!p)
		return -DREW_ERR_INVALID;

	drew_bignum_t *bn = *p;
	bn->functbl->setbytes(bn, buf, len);
	return 0;
}

static int rsa_val(const drew_pkenc_t *ctx, const char *name, uint8_t *data,
		size_t len)
{
	drew_bignum_t **p = get_named_mpi((struct rsa *)ctx->ctx, name);

	if (!p)
		return -DREW_ERR_INVALID;
	return (*p)->functbl->bytes(*p, data, len);
}

static int rsa_valsize(const drew_pkenc_t *ctx, const char *name)
{
	drew_bignum_t **p = get_named_mpi((struct rsa *)ctx->ctx, name);

	if (!p)
		return -DREW_ERR_INVALID;
	return (*p)->functbl->nbytes(*p);
}

static int rsa_encrypt(const drew_pkenc_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct rsa *c = ctx->ctx;
	drew_bignum_t *n = c->n;
	size_t outlen = n->functbl->nbytes(n);

	if (!out)
		return outlen;

	out[0].functbl->expmod(&out[0], &in[0], c->e, n);
	outlen = out[0].functbl->nbytes(&out[0]);
	return outlen;
}

static int rsa_decrypt(const drew_pkenc_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	// FIXME: use chinese remainder theorem where possible.
	struct rsa *c = ctx->ctx;
	drew_bignum_t *n = c->n;
	size_t outlen = n->functbl->nbytes(n);

	if (!out)
		return outlen;

	out[0].functbl->expmod(&out[0], &in[0], c->d, n);
	outlen = out[0].functbl->nbytes(&out[0]);
	return outlen;
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
