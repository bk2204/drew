#include "internal.h"
#include "util.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/bignum.h>
#include <drew/mem.h>
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

/* Tests from sigver.rsp from NIST's 186-2dsatestvectors.zip.  k values are
 * computed using a perl script.
 */
static int dsa_test(void *ptr, const drew_loader_t *ldr)
{
	uint8_t p[] = {
		0xaa, 0x9a, 0x0d, 0x61, 0x16, 0x80, 0x7c, 0xf7,
		0x4e, 0x0e, 0xe6, 0x3c, 0xdc, 0x6f, 0x38, 0x11,
		0x0f, 0x87, 0x3a, 0xff, 0xc6, 0xdb, 0x2d, 0x9a,
		0xd8, 0x54, 0xae, 0x27, 0xa3, 0x84, 0x23, 0x0d,
		0xd9, 0x04, 0xf8, 0xa6, 0xce, 0xb1, 0x1b, 0xb2,
		0x98, 0x39, 0x73, 0xc0, 0xd8, 0x19, 0xcc, 0xf0,
		0x2d, 0xf0, 0x4d, 0x82, 0xcc, 0x79, 0x26, 0xd6,
		0x1b, 0xe7, 0x8f, 0x5a, 0xd9, 0x2a, 0x05, 0xb9,
		0x30, 0x8a, 0xca, 0x5a, 0x9e, 0xcd, 0x74, 0x61,
		0xfc, 0x1b, 0x51, 0xda, 0x3e, 0x9d, 0x84, 0x9f,
		0xce, 0x50, 0x75, 0xd9, 0xc0, 0x27, 0xf1, 0xaf,
		0xeb, 0x0a, 0xb7, 0x91, 0x6d, 0xf4, 0xa7, 0xb7,
		0x2b, 0x3b, 0xb0, 0x04, 0x61, 0xf4, 0x35, 0x42,
		0x31, 0x3c, 0x8b, 0x82, 0x35, 0x4f, 0x88, 0xc5,
		0x42, 0xa4, 0x8b, 0xfa, 0x73, 0xbc, 0xc1, 0xdb,
		0x4f, 0xfe, 0xd3, 0x29, 0xb2, 0xcc, 0x5c, 0xff
	},
	q[] = {
		0xf7, 0x80, 0xe7, 0x06, 0xdb, 0x7e, 0x46, 0x5d,
		0xd0, 0xee, 0xec, 0x3f, 0x1b, 0x92, 0x92, 0x40,
		0x15, 0x7f, 0x47, 0x6f
	},
	g[] = {
		0x3b, 0x80, 0x10, 0x31, 0x91, 0xe0, 0xb2, 0xd6,
		0xb9, 0x49, 0xe1, 0xdb, 0xfb, 0x62, 0x1c, 0x5c,
		0x8f, 0xb4, 0x5b, 0xb9, 0xf9, 0xdb, 0x5a, 0x52,
		0x37, 0x27, 0x28, 0x04, 0x50, 0x15, 0xb5, 0x69,
		0x75, 0xb5, 0x6b, 0x3f, 0x8b, 0x97, 0x65, 0x96,
		0x00, 0x19, 0x44, 0x42, 0xd0, 0x75, 0xa8, 0xc5,
		0xc8, 0xc1, 0x58, 0x8e, 0xe0, 0x1d, 0x84, 0x8e,
		0x7b, 0x42, 0x90, 0x5e, 0xdd, 0xa8, 0x07, 0x20,
		0x9e, 0x13, 0x95, 0xa1, 0x30, 0xcf, 0x7f, 0xb2,
		0x63, 0x0c, 0x2b, 0xfc, 0xf4, 0x6c, 0xc2, 0xf8,
		0xcd, 0xc2, 0xe0, 0xa1, 0x1e, 0xed, 0x91, 0x89,
		0xb3, 0x5d, 0x92, 0xb2, 0x61, 0x9d, 0xaf, 0xf9,
		0x5a, 0xc1, 0x8b, 0x0c, 0x0e, 0x2f, 0xd1, 0xc8,
		0xe4, 0x49, 0xe2, 0x25, 0xf8, 0x12, 0xb2, 0x98,
		0x15, 0xef, 0xd1, 0xd0, 0x5d, 0x7b, 0xc1, 0xbf,
		0x6e, 0xfa, 0xa1, 0x76, 0x6e, 0xc2, 0xa3, 0x22
	};
	struct test {
		uint8_t x[20];
		uint8_t y[1024/8];
		uint8_t h[20];
		uint8_t r[20];
		uint8_t s[20];
		uint8_t k[20];
		bool success;
	} tests[] = {
		{
			{
				0x30, 0x7f, 0xcd, 0x3b, 0xcf, 0xf6, 0x3a, 0xf1,
				0xcc, 0xd3, 0x66, 0x10, 0xc4, 0x41, 0xfa, 0xc0,
				0x90, 0x22, 0x29, 0xb5,
			},
			{
				0x6e, 0x02, 0x12, 0x71, 0xdd, 0xfb, 0xd3, 0x51,
				0xc2, 0x61, 0x9d, 0xf1, 0xe2, 0x4a, 0xfc, 0x19,
				0x9b, 0x1d, 0xa2, 0x1d, 0x65, 0xf6, 0xa4, 0xf9,
				0x7e, 0x26, 0xdc, 0xf1, 0x38, 0x37, 0x5c, 0xa4,
				0xf4, 0x74, 0x9b, 0x5a, 0x5f, 0xfa, 0xcc, 0x26,
				0x10, 0xf1, 0xa3, 0x08, 0xd6, 0x04, 0xeb, 0x3a,
				0x14, 0x39, 0x01, 0x04, 0xb7, 0xd4, 0x3b, 0x05,
				0x6a, 0x40, 0xd9, 0x23, 0x3d, 0x13, 0xfe, 0x3c,
				0x79, 0xab, 0xf6, 0xec, 0xaa, 0x17, 0xce, 0xf2,
				0x16, 0xd9, 0x9c, 0xec, 0x34, 0x98, 0xe6, 0xec,
				0x8c, 0xff, 0x21, 0x4e, 0xcc, 0x5e, 0x85, 0x0b,
				0x90, 0x15, 0x2f, 0x15, 0x80, 0x68, 0x7b, 0x5e,
				0x87, 0x14, 0xe4, 0x76, 0xe1, 0xee, 0x56, 0x80,
				0x24, 0x86, 0xd3, 0xec, 0xa8, 0xef, 0x68, 0xc6,
				0x2e, 0x47, 0x64, 0xa5, 0x6d, 0xa3, 0x16, 0x6d,
				0x2d, 0x66, 0x7b, 0xbb, 0x22, 0x77, 0x67, 0x55
			},
			{
				0xca, 0x03, 0xee, 0x15, 0x4f, 0x09, 0x90, 0x99,
				0xc2, 0x3f, 0x7c, 0x58, 0xa3, 0x3a, 0x82, 0xed,
				0x60, 0xc6, 0xb6, 0xb7,
			},
			{
				0xa5, 0xd2, 0xc4, 0xd7, 0xcc, 0x75, 0x37, 0xa4,
				0xe3, 0x87, 0x35, 0xf7, 0xe8, 0x33, 0xd1, 0x1d,
				0x57, 0x15, 0x89, 0x6e
			},
			{
				0x87, 0xbc, 0x06, 0x60, 0x96, 0x18, 0x50, 0x96,
				0xa6, 0xa7, 0x6b, 0x1c, 0xc0, 0x8b, 0xd6, 0x81,
				0xe5, 0x04, 0x0d, 0x8a
			},
			{
				// not provided since test will fail.
			},
			false
		},
		{
			// x
			{
				0x0e, 0xf5, 0x8b, 0x26, 0xa8, 0x00, 0xa7, 0xbf,
				0x0a, 0xab, 0xe5, 0xd7, 0x95, 0xac, 0xaf, 0xf5,
				0xa8, 0xc8, 0x8b, 0xe5
			},
			// y
			{
				0x40, 0x29, 0xa1, 0x21, 0xf6, 0x62, 0x71, 0x27,
				0xbc, 0x8a, 0xeb, 0x97, 0xbf, 0xee, 0xc2, 0xa8,
				0x0b, 0x08, 0x00, 0xed, 0x01, 0x5a, 0x91, 0xbc,
				0xf3, 0x98, 0x69, 0x18, 0x75, 0x35, 0xe9, 0x1b,
				0x5d, 0xb5, 0x3e, 0xe8, 0x40, 0x05, 0x65, 0x29,
				0xc1, 0xe4, 0xcc, 0xdb, 0xc2, 0x1e, 0x64, 0xb8,
				0x13, 0xcc, 0x3d, 0x2c, 0x17, 0x0c, 0x60, 0x30,
				0xa0, 0xd1, 0x95, 0x64, 0x5b, 0xd3, 0x65, 0x72,
				0x56, 0x64, 0x7b, 0xaf, 0xc0, 0x62, 0x39, 0x44,
				0xe4, 0x4f, 0x1c, 0x5f, 0x7c, 0x50, 0x31, 0x81,
				0x82, 0xe6, 0x89, 0x66, 0xb9, 0xa1, 0x6f, 0x46,
				0xda, 0x9e, 0x34, 0x33, 0x01, 0xdb, 0x69, 0x4d,
				0x8f, 0x3b, 0x62, 0x05, 0x2b, 0x66, 0xda, 0xe2,
				0x52, 0x22, 0xc5, 0x31, 0x25, 0xa7, 0x89, 0x34,
				0x16, 0x99, 0x40, 0x55, 0xa0, 0x28, 0x43, 0x93,
				0xf6, 0x7c, 0x6b, 0x2e, 0x3b, 0xbf, 0x0c, 0xd4
			},
			{
				0x8d, 0x8a, 0xa0, 0xd5, 0x9f, 0xc2, 0x7e, 0xc8,
				0x45, 0x81, 0xf2, 0x9f, 0x53, 0x74, 0xcc, 0x26,
				0x62, 0x0f, 0xc3, 0xa2
			},
			{
				0x68, 0x34, 0xf4, 0x9e, 0xa0, 0x79, 0xdd, 0x8b,
				0xb8, 0x9c, 0xe0, 0xf9, 0x69, 0x80, 0x39, 0xa7,
				0x34, 0xce, 0x28, 0x6f
			},
			{
				0x14, 0x6e, 0xee, 0x21, 0xb3, 0x75, 0xdf, 0x38,
				0x12, 0xdd, 0xc7, 0xf7, 0xce, 0x81, 0x90, 0x8e,
				0x57, 0x1c, 0xbf, 0x8a
			},
			{
				0xdb, 0x5a, 0xad, 0x14, 0x89, 0xbd, 0x8d, 0x87,
				0x18, 0xe8, 0xa4, 0x90, 0x24, 0x90, 0xfd, 0x8f,
				0xd7, 0xcc, 0x04, 0xe6
			},
			true
		}
	};
	const void *functbl;
	drew_pksig_t ctx;
	int res = 0, id;
	drew_param_t param;
	const char *bignum = "Bignum";
	drew_bignum_t bns[7]; // v, r, s, h, k, computed r, computed s.

	id = drew_loader_lookup_by_name(ldr, bignum, 0, -1);
	if (id < 0)
		return id;
	if (drew_loader_get_type(ldr, id) != DREW_TYPE_BIGNUM)
		return -DREW_ERR_INVALID;
	if ((res = drew_loader_get_functbl(ldr, id, &functbl)) < 0)
		return res;

	param.next = NULL;
	param.name = "bignum";
	param.param.value = bns;

	for (size_t i = 0; i < DIM(bns); i++) {
		bns[i].functbl = functbl;
		bns[i].functbl->init(&bns[i], 0, ldr, NULL);
	}

	res = 0;

	ctx.functbl = &dsa_functbl;
	if (ctx.functbl->init(&ctx, 0, ldr, &param) != 0)
		return 3;
	ctx.functbl->setval(&ctx, "p", p, DIM(p));
	ctx.functbl->setval(&ctx, "q", q, DIM(q));
	ctx.functbl->setval(&ctx, "g", g, DIM(g));
	for (size_t i = 0; i < DIM(tests); i++) {
		ctx.functbl->setval(&ctx, "x", tests[i].x, DIM(tests[i].x));
		ctx.functbl->setval(&ctx, "y", tests[i].y, DIM(tests[i].y));
		bns[1].functbl->setbytes(&bns[1], tests[i].r, DIM(tests[i].r));
		bns[2].functbl->setbytes(&bns[2], tests[i].s, DIM(tests[i].s));
		bns[3].functbl->setbytes(&bns[3], tests[i].h, DIM(tests[i].h));
		ctx.functbl->verify(&ctx, bns, bns+1);
		res <<= 1;
		res |= (tests[i].success == !!bns[1].functbl->compare(&bns[1], &bns[0], 0));
		if (tests[i].success) {
			bns[4].functbl->setbytes(&bns[4], tests[i].k, DIM(tests[i].k));
			ctx.functbl->sign(&ctx, bns+5, bns+3);
			res <<= 1;
			res |= !!bns[1].functbl->compare(&bns[1], &bns[5], 0);
			res |= !!bns[2].functbl->compare(&bns[2], &bns[6], 0);
		}
	}

	for (size_t i = 0; i < 4; i++)
		bns[i].functbl->fini(&bns[i], 0);
	ctx.functbl->fini(&ctx, 0);

	return res;
}

static drew_bignum_t *init_bignum(const drew_loader_t *ldr,
		const drew_param_t *param, const void *functbl)
{
	drew_bignum_t *ctx = drew_mem_malloc(sizeof(*ctx));

	ctx->functbl = functbl;
	ctx->functbl->init(ctx, 0, ldr, param);

	return ctx;
}

static void free_bignum(drew_bignum_t *ctx)
{
	ctx->functbl->fini(ctx, 0);
	drew_mem_free(ctx);
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
		newctx = drew_mem_malloc(sizeof(*newctx));

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
		drew_mem_free(c);

	ctx->ctx = NULL;
	return 0;
}

#define CLONE(new, old, x) do { if (!(old)->x) new->x = NULL; \
	else old->x->functbl->clone(new->x, old->x, 0); } while (0)

static int dsa_clone(drew_pksig_t *newctx, const drew_pksig_t *oldctx,
		int flags)
{
	if (!(flags & DREW_PKSIG_FIXED))
		newctx->ctx = drew_mem_malloc(sizeof(struct dsa));

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

EXPORT()
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
UNEXPORT()
