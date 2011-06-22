#include "internal.h"

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

struct dsa {
	drew_bignum_t *p;
	drew_bignum_t *q;
	drew_bignum_t *g;
	drew_bignum_t *y;
	drew_bignum_t *x;
};

static int dsa_info(int op, void *p);
static int dsa_init(drew_pksig_t *, int,
		const drew_loader_t *, const drew_param_t *);
static int dsa_clone(drew_pksig_t *, const drew_pksig_t *, int);
static int dsa_fini(drew_pksig_t *, int);
static int dsa_generate(drew_pksig_t *, const drew_param_t *);
static int dsa_setmode(drew_pksig_t *, int);
static int dsa_setval(drew_pksig_t *, const char *, const uint8_t *, size_t);
static int dsa_val(const drew_pksig_t *, const char *, uint8_t *, size_t);
static int dsa_valsize(const drew_pksig_t *, const char *);
static int dsa_sign(const drew_pksig_t *, drew_bignum_t *,
		const drew_bignum_t *);
static int dsa_verify(const drew_pksig_t *, drew_bignum_t *,
		const drew_bignum_t *);
static int dsa_test(void *, const drew_loader_t *);


static const drew_pksig_functbl_t dsa_functbl = {
	.info = dsa_info,
	.init = dsa_init,
	.clone = dsa_clone,
	.fini = dsa_fini,
	.generate = dsa_generate,
	.setmode = dsa_setmode,
	.setval = dsa_setval,
	.val = dsa_val,
	.valsize = dsa_valsize,
	.sign = dsa_sign,
	.verify = dsa_verify,
	.test = dsa_test
};

struct mapping {
	const char *name;
	size_t index;
};

static int name_to_index(drew_param_t *p, size_t nentries,
		const struct mapping *map)
{
	const char *name = p->param.string;
	for (size_t i = 0; i < nentries; i++)
		if (!strcmp(name, map[i].name)) {
			p->param.number = map[i].index;
			return 0;
		}
	return -DREW_ERR_INVALID;
}

static int index_to_name(drew_param_t *p, size_t nentries,
		const struct mapping *map)
{
	size_t index = p->param.number;
	if (index >= nentries)
		return -DREW_ERR_INVALID;
	p->param.string = map[index].name;
	return 0;
}

static int dsa_info(int op, void *p)
{
	drew_param_t *param = p;
	struct mapping sign_in[] = {
		{"h", 0},
		{"k", 1}
	},
	sign_out[] = {
		{"r", 0},
		{"s", 1}
	},
	verify_in[] = {
		{"r", 0},
		{"s", 1},
		{"h", 2}
	},
	verify_out[] = {
		{"v", 0}
	};
	switch (op) {
		case DREW_PKSIG_VERSION:
			return 2;
		case DREW_PKSIG_INTSIZE:
			return sizeof(struct dsa);
		case DREW_PKSIG_SIGN_IN:
			return DIM(sign_in);
		case DREW_PKSIG_SIGN_OUT:
			return DIM(sign_out);
		case DREW_PKSIG_VERIFY_IN:
			return DIM(verify_in);
		case DREW_PKSIG_VERIFY_OUT:
			return DIM(verify_out);
		case DREW_PKSIG_SIGN_IN_NAME_TO_INDEX:
			return name_to_index(param, DIM(sign_in), sign_in);
		case DREW_PKSIG_SIGN_IN_INDEX_TO_NAME:
			return index_to_name(param, DIM(sign_in), sign_in);
		case DREW_PKSIG_SIGN_OUT_NAME_TO_INDEX:
			return name_to_index(param, DIM(sign_out), sign_out);
		case DREW_PKSIG_SIGN_OUT_INDEX_TO_NAME:
			return index_to_name(param, DIM(sign_out), sign_out);
		case DREW_PKSIG_VERIFY_IN_NAME_TO_INDEX:
			return name_to_index(param, DIM(verify_in), verify_in);
		case DREW_PKSIG_VERIFY_IN_INDEX_TO_NAME:
			return index_to_name(param, DIM(verify_in), verify_in);
		case DREW_PKSIG_VERIFY_OUT_NAME_TO_INDEX:
			return name_to_index(param, DIM(verify_out), verify_out);
		case DREW_PKSIG_VERIFY_OUT_INDEX_TO_NAME:
			return index_to_name(param, DIM(verify_out), verify_out);
		default:
			return -DREW_ERR_INVALID;
	}
}

static int dsa_test(void *ptr, const drew_loader_t *ldr)
{
	return -DREW_ERR_NOT_IMPL;
}

static drew_bignum_t *init_bignum(const drew_loader_t *ldr,
		const drew_param_t *param, const void *functbl)
{
	drew_bignum_t *ctx = malloc(sizeof(*ctx));

	ctx->functbl = functbl;
	ctx->functbl->init(ctx, 0, ldr, param);

	return ctx;
}

static void free_bignum(drew_bignum_t *ctx)
{
	ctx->functbl->fini(ctx, 0);
	free(ctx);
}

static int fini(struct dsa *c, int flags)
{
	free_bignum(c->p);
	free_bignum(c->q);
	free_bignum(c->g);
	free_bignum(c->x);
	free_bignum(c->y);
	memset(c, 0, sizeof(*c));

	return 0;
}

static inline drew_bignum_t **get_named_mpi(struct dsa *c, const char *name)
{
	if (strlen(name) != 1)
		return NULL;

	switch (name[0]) {
		case 'p':
			return &c->p;
		case 'q':
			return &c->q;
		case 'g':
			return &c->g;
		case 'x':
			return &c->x;
		case 'y':
			return &c->y;
		default:
			return NULL;
	}
}

static int dsa_init(drew_pksig_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct dsa *newctx = ctx->ctx;

	if (!(flags & DREW_PKSIG_FIXED))
		newctx = malloc(sizeof(*newctx));

	const void *functbl;
	int res = 0;
	drew_bignum_t *bignum = NULL;

	for (const drew_param_t *p = param; p; p = p->next) {
		if (!strcmp(p->name, "bignum")) {
			bignum = p->param.value;
			break;
		}
	}

	if (!bignum)
		return -DREW_ERR_MORE_INFO;

	functbl = bignum->functbl;

	memset(newctx, 0, sizeof(*newctx));

	newctx->p = init_bignum(ldr, param, functbl);
	newctx->q = init_bignum(ldr, param, functbl);
	newctx->g = init_bignum(ldr, param, functbl);
	newctx->x = init_bignum(ldr, param, functbl);
	newctx->y = init_bignum(ldr, param, functbl);
	
	ctx->ctx = newctx;
	ctx->functbl = &dsa_functbl;

	return res;
}

static int dsa_fini(drew_pksig_t *ctx, int flags)
{
	struct dsa *c = ctx->ctx;

	fini(c, flags);
	if (!(flags & DREW_PKSIG_FIXED))
		free(c);

	ctx->ctx = NULL;
	return 0;
}

#define CLONE(new, old, x) do { if (!(old)->x) new->x = NULL; \
	else old->x->functbl->clone(new->x, old->x, 0); } while (0)

static int dsa_clone(drew_pksig_t *newctx, const drew_pksig_t *oldctx,
		int flags)
{
	if (!(flags & DREW_PKSIG_FIXED))
		newctx->ctx = malloc(sizeof(struct dsa));

	memset(newctx->ctx, 0, sizeof(struct dsa));

	struct dsa *new = newctx->ctx, *old = oldctx->ctx;
	CLONE(new, old, p);
	CLONE(new, old, q);
	CLONE(new, old, g);
	CLONE(new, old, x);
	CLONE(new, old, y);
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int dsa_generate(drew_pksig_t *ctx, const drew_param_t *param)
{
	return -DREW_ERR_NOT_IMPL;
}

static int dsa_setmode(drew_pksig_t *ctx, int flags)
{
	return 0;
}

static int dsa_setval(drew_pksig_t *ctx, const char *name, const uint8_t *buf,
		size_t len)
{
	struct dsa *c = ctx->ctx;
	drew_bignum_t **p = get_named_mpi(c, name);

	if (!p)
		return -DREW_ERR_INVALID;

	drew_bignum_t *bn = *p;
	bn->functbl->setbytes(bn, buf, len);
	return 0;
}

static int dsa_val(const drew_pksig_t *ctx, const char *name, uint8_t *data,
		size_t len)
{
	struct dsa *c = ctx->ctx;
	drew_bignum_t **p = get_named_mpi(c, name);

	if (!p)
		return -DREW_ERR_INVALID;
	return (*p)->functbl->bytes(*p, data, len);
}

static int dsa_valsize(const drew_pksig_t *ctx, const char *name)
{
	struct dsa *c = ctx->ctx;
	drew_bignum_t **p = get_named_mpi(c, name);

	if (!p)
		return -DREW_ERR_INVALID;
	return (*p)->functbl->nbytes(*p);
}

static int dsa_sign(const drew_pksig_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct dsa *c = ctx->ctx;
	drew_bignum_t t, kinv, z, *p = c->p, *q = c->q, *r = out, *s = out+1;
	const drew_bignum_t *h = in, *k = in+1;
	int res = 0;

	r->functbl->init(&z, 0, NULL, NULL);
	r->functbl->init(&t, 0, NULL, NULL);
	r->functbl->init(&kinv, 0, NULL, NULL);
	z.functbl->setzero(&z);
	kinv.functbl->invmod(&kinv, k, q);
	r->functbl->expmod(r, c->g, k, p);
	r->functbl->mod(r, r, q);
	t.functbl->mul(&t, c->x, r);
	t.functbl->mod(&t, &t, c->q);
	t.functbl->add(&t, &t, h);
	s->functbl->mul(s, &kinv, &t);
	s->functbl->mod(s, s, c->q);
	// Check whether either r or s is zero.
	if (!r->functbl->compare(r, &z, 0) || !s->functbl->compare(s, &z, 0))
		res = -DREW_ERR_INVALID;
	t.functbl->fini(&t, 0);
	kinv.functbl->fini(&kinv, 0);
	return res;
}

static int dsa_verify(const drew_pksig_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct dsa *c = ctx->ctx;
	const drew_bignum_t *r = in, *s = in+1, *h = in+2;
	drew_bignum_t *v = out;
	drew_bignum_t wbuf, *w = &wbuf, u1buf, *u1 = &u1buf, u2buf, *u2 = &u2buf;
	drew_bignum_t zbuf, *z = &zbuf, tbuf, *t = &tbuf;
	int res = 0;

	r->functbl->init(w, 0, NULL, NULL);
	r->functbl->init(u1, 0, NULL, NULL);
	r->functbl->init(u2, 0, NULL, NULL);
	r->functbl->init(z, 0, NULL, NULL);
	r->functbl->init(t, 0, NULL, NULL);
	z->functbl->setzero(z);
	// Check whether either r or s is zero.
	if (!r->functbl->compare(r, z, 0) || !s->functbl->compare(s, z, 0))
		res = -DREW_ERR_INVALID;
	w->functbl->invmod(w, s, c->q);
	u1->functbl->mul(u1, h, w);
	u1->functbl->mod(u1, u1, c->q);
	u2->functbl->mul(u2, r, w);
	u2->functbl->mod(u2, u2, c->q);
	v->functbl->expmod(v, c->g, u1, c->p);
	t->functbl->expmod(t, c->y, u2, c->p);
	v->functbl->mul(v, v, t);
	v->functbl->mod(v, v, c->p);
	v->functbl->mod(v, v, c->q);
	w->functbl->fini(w, 0);
	u1->functbl->fini(u1, 0);
	u2->functbl->fini(u2, 0);
	z->functbl->fini(z, 0);
	t->functbl->fini(t, 0);
	return res;
}

struct plugin {
	const char *name;
	const drew_pksig_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "DSA", &dsa_functbl },
};

int DREW_PLUGIN_NAME(dsa)(void *ldr, int op, int id, void *p)
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
