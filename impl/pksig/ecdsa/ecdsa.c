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
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/drew.h>
#include <drew/bignum.h>
#include <drew/ecc.h>
#include <drew/mem.h>
#include <drew/pksig.h>
#include <drew/plugin.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

struct ecdsa {
	drew_bignum_t *d;
	drew_ecc_t *curve;
	drew_ecc_point_t *q;
};

static int ecdsa_info(int op, void *p);
static int ecdsa_info2(const drew_pksig_t *, int, drew_param_t *,
		const drew_param_t *);
static int ecdsa_init(drew_pksig_t *, int,
		const drew_loader_t *, const drew_param_t *);
static int ecdsa_clone(drew_pksig_t *, const drew_pksig_t *, int);
static int ecdsa_fini(drew_pksig_t *, int);
static int ecdsa_generate(drew_pksig_t *, const drew_param_t *);
static int ecdsa_setmode(drew_pksig_t *, int);
static int ecdsa_setval(drew_pksig_t *, const char *, const uint8_t *, size_t);
static int ecdsa_val(const drew_pksig_t *, const char *, uint8_t *, size_t);
static int ecdsa_valsize(const drew_pksig_t *, const char *);
static int ecdsa_sign(const drew_pksig_t *, drew_bignum_t *,
		const drew_bignum_t *);
static int ecdsa_verify(const drew_pksig_t *, drew_bignum_t *,
		const drew_bignum_t *);
static int ecdsa_test(void *, const drew_loader_t *);


static const drew_pksig_functbl_t ecdsa_functbl = {
	.info = ecdsa_info,
	.info2 = ecdsa_info2,
	.init = ecdsa_init,
	.clone = ecdsa_clone,
	.fini = ecdsa_fini,
	.generate = ecdsa_generate,
	.setmode = ecdsa_setmode,
	.setval = ecdsa_setval,
	.val = ecdsa_val,
	.valsize = ecdsa_valsize,
	.sign = ecdsa_sign,
	.verify = ecdsa_verify,
	.test = ecdsa_test
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

static int ecdsa_info(int op, void *p)
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
			return CURRENT_ABI;
		case DREW_PKSIG_INTSIZE:
			return sizeof(struct ecdsa);
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

static int ecdsa_info2(const drew_pksig_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	switch (op) {
		case DREW_PKSIG_VERSION:
			return CURRENT_ABI;
		case DREW_PKSIG_INTSIZE:
			return sizeof(struct ecdsa);
		default:
			return -DREW_ERR_INVALID;
	}
}

static int ecdsa_test(void *p, const drew_loader_t *ldr)
{
	const uint8_t hbytes[] = {
		0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
		0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
		0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
		0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
		0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
		0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
		0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
		0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
	};
	const uint8_t dbytes[] = {
		0x00, 0x65, 0xfd, 0xa3, 0x40, 0x94, 0x51, 0xdc,
		0xab, 0x0a, 0x0e, 0xad, 0x45, 0x49, 0x51, 0x12,
		0xa3, 0xd8, 0x13, 0xc1, 0x7b, 0xfd, 0x34, 0xbd,
		0xf8, 0xc1, 0x20, 0x9d, 0x7d, 0xf5, 0x84, 0x91,
		0x20, 0x59, 0x77, 0x79, 0x06, 0x0a, 0x7f, 0xf9,
		0xd7, 0x04, 0xad, 0xf7, 0x8b, 0x57, 0x0f, 0xfa,
		0xd6, 0xf0, 0x62, 0xe9, 0x5c, 0x7e, 0x0c, 0x5d,
		0x54, 0x81, 0xc5, 0xb1, 0x53, 0xb4, 0x8b, 0x37,
		0x5f, 0xa1
	};
	/* Uncompressed SEC format */
	const uint8_t qbytes[] = {
		0x04, 0x01, 0x51, 0x51, 0x8f, 0x1a, 0xf0, 0xf5,
		0x63, 0x51, 0x7e, 0xdd, 0x54, 0x85, 0x19, 0x0d,
		0xf9, 0x5a, 0x4b, 0xf5, 0x7b, 0x5c, 0xba, 0x4c,
		0xf2, 0xa9, 0xa3, 0xf6, 0x47, 0x47, 0x25, 0xa3,
		0x5f, 0x7a, 0xfe, 0x0a, 0x6d, 0xde, 0xb8, 0xbe,
		0xdb, 0xcd, 0x6a, 0x19, 0x7e, 0x59, 0x2d, 0x40,
		0x18, 0x89, 0x01, 0xce, 0xcd, 0x65, 0x06, 0x99,
		0xc9, 0xb5, 0xe4, 0x56, 0xae, 0xa5, 0xad, 0xd1,
		0x90, 0x52, 0xa8, 0x00, 0x6f, 0x3b, 0x14, 0x2e,
		0xa1, 0xbf, 0xff, 0x7e, 0x28, 0x37, 0xad, 0x44,
		0xc9, 0xe4, 0xff, 0x6d, 0x2d, 0x34, 0xc7, 0x31,
		0x84, 0xbb, 0xad, 0x90, 0x02, 0x6d, 0xd5, 0xe6,
		0xe8, 0x53, 0x17, 0xd9, 0xdf, 0x45, 0xca, 0xd7,
		0x80, 0x3c, 0x6c, 0x20, 0x03, 0x5b, 0x2f, 0x3f,
		0xf6, 0x3a, 0xff, 0x4e, 0x1b, 0xa6, 0x4d, 0x1c,
		0x07, 0x75, 0x77, 0xda, 0x3f, 0x42, 0x86, 0xc5,
		0x8f, 0x0a, 0xea, 0xe6, 0x43
	};
	const uint8_t kbytes[] = {
		0x00, 0xc1, 0xc2, 0xb3, 0x05, 0x41, 0x9f, 0x5a,
		0x41, 0x34, 0x4d, 0x7e, 0x43, 0x59, 0x93, 0x3d,
		0x73, 0x40, 0x96, 0xf5, 0x56, 0x19, 0x7a, 0x9b,
		0x24, 0x43, 0x42, 0xb8, 0xb6, 0x2f, 0x46, 0xf9,
		0x37, 0x37, 0x78, 0xf9, 0xde, 0x6b, 0x64, 0x97,
		0xb1, 0xef, 0x82, 0x5f, 0xf2, 0x4f, 0x42, 0xf9,
		0xb4, 0xa4, 0xbd, 0x73, 0x82, 0xcf, 0xc3, 0x37,
		0x8a, 0x54, 0x0b, 0x1b, 0x7f, 0x0c, 0x1b, 0x95,
		0x6c, 0x2f
	};
	const uint8_t rbytes[] = {
		0x01, 0x54, 0xfd, 0x38, 0x36, 0xaf, 0x92, 0xd0,
		0xdc, 0xa5, 0x7d, 0xd5, 0x34, 0x1d, 0x30, 0x53,
		0x98, 0x85, 0x34, 0xfd, 0xe8, 0x31, 0x8f, 0xc6,
		0xaa, 0xaa, 0xb6, 0x8e, 0x2e, 0x6f, 0x43, 0x39,
		0xb1, 0x9f, 0x2f, 0x28, 0x1a, 0x7e, 0x0b, 0x22,
		0xc2, 0x69, 0xd9, 0x3c, 0xf8, 0x79, 0x4a, 0x92,
		0x78, 0x88, 0x0e, 0xd7, 0xdb, 0xb8, 0xd9, 0x36,
		0x2c, 0xae, 0xac, 0xee, 0x54, 0x43, 0x20, 0x55,
		0x22, 0x51
	};
	const uint8_t sbytes[] = {
		0x01, 0x77, 0x05, 0xa7, 0x03, 0x02, 0x90, 0xd1,
		0xce, 0xb6, 0x05, 0xa9, 0xa1, 0xbb, 0x03, 0xff,
		0x9c, 0xdd, 0x52, 0x1e, 0x87, 0xa6, 0x96, 0xec,
		0x92, 0x6c, 0x8c, 0x10, 0xc8, 0x36, 0x2d, 0xf4,
		0x97, 0x53, 0x67, 0x10, 0x1f, 0x67, 0xd1, 0xcf,
		0x9b, 0xcc, 0xbf, 0x2f, 0x3d, 0x23, 0x95, 0x34,
		0xfa, 0x50, 0x9e, 0x70, 0xaa, 0xc8, 0x51, 0xae,
		0x01, 0xaa, 0xc6, 0x8d, 0x62, 0xf8, 0x66, 0x47,
		0x26, 0x60
	};
	const void *bnfunctbl, *eccfunctbl;
	drew_ecc_t curve;
	drew_pksig_t ecdsa;
	drew_param_t pa, pb;
	drew_bignum_t bn[7], *r = bn, *s = bn+1, *h = bn+2, *k = bn+3, *v = bn+4;
	drew_bignum_t *rorig = bn+5, *sorig = bn+6;
	int id = 0, res = 0;

	if ((id = drew_loader_lookup_by_name(ldr, "EllipticCurvePrime", 0, -1)) < 0)
		return id;
	drew_loader_get_functbl(ldr, id, &eccfunctbl);
	if ((id = drew_loader_lookup_by_name(ldr, "Bignum", 0, -1)) < 0)
		return id;
	drew_loader_get_functbl(ldr, id, &bnfunctbl);

	curve.functbl = eccfunctbl;

	for (size_t i = 0; i < DIM(bn); i++) {
		bn[i].functbl = bnfunctbl;
		bn[i].functbl->init(bn+i, 0, ldr, NULL);
	}

	h->functbl->setbytes(h, hbytes, sizeof(hbytes));
	k->functbl->setbytes(k, kbytes, sizeof(kbytes));
	rorig->functbl->setbytes(rorig, rbytes, sizeof(rbytes));
	sorig->functbl->setbytes(sorig, sbytes, sizeof(sbytes));

	pa.name = "bignum";
	pa.param.value = bn;
	pa.next = NULL;
	
	pb.name = "curve";
	pb.param.value = &curve;
	pb.next = NULL;

	curve.functbl->init(&curve, 0, ldr, &pa);
	curve.functbl->setcurvename(&curve, "secp521r1");
	pa.next = &pb;

	ecdsa.functbl = &ecdsa_functbl;
	ecdsa.functbl->init(&ecdsa, 0, ldr, &pa);
	ecdsa.functbl->setval(&ecdsa, "d", dbytes, sizeof(dbytes));
	ecdsa.functbl->setval(&ecdsa, "q", qbytes, sizeof(qbytes));

	if (ecdsa.functbl->sign(&ecdsa, r, h))
		res |= 1;
	if (r->functbl->compare(r, rorig, 0))
		res |= 2;
	if (s->functbl->compare(s, sorig, 0))
		res |= 4;
	if (ecdsa.functbl->verify(&ecdsa, v, r))
		res |= 8;
	if (r->functbl->compare(r, v, 0))
		res |= 16;

	ecdsa.functbl->fini(&ecdsa, 0);
	curve.functbl->fini(&curve, 0);
	for (size_t i = 0; i < DIM(bn); i++)
		bn[i].functbl->fini(bn+i, 0);

	return res;
}

static int ecdsa_init(drew_pksig_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct ecdsa *newctx = ctx->ctx;

	if (!(flags & DREW_PKSIG_FIXED))
		newctx = drew_mem_malloc(sizeof(*newctx));

	int res = 0;
	drew_bignum_t *bignum = NULL;
	drew_ecc_t *curve = NULL;

	for (const drew_param_t *p = param; p; p = p->next) {
		if (!strcmp(p->name, "bignum"))
			bignum = p->param.value;
		if (!strcmp(p->name, "curve"))
			curve = p->param.value;
	}

	if (!bignum || !curve)
		return -DREW_ERR_MORE_INFO;

	memset(newctx, 0, sizeof(*newctx));

	newctx->d = drew_mem_malloc(sizeof(*newctx->d));
	newctx->q = drew_mem_malloc(sizeof(*newctx->q));
	newctx->curve = drew_mem_malloc(sizeof(*newctx->curve));

	newctx->d->functbl = bignum->functbl;
	newctx->curve->functbl = curve->functbl;

	newctx->d->functbl->init(newctx->d, 0, ldr, NULL);
	newctx->curve->functbl->clone(newctx->curve, curve, 0);
	newctx->curve->functbl->point(newctx->curve, newctx->q);
	
	ctx->ctx = newctx;
	ctx->functbl = &ecdsa_functbl;

	return res;
}

static int ecdsa_fini(drew_pksig_t *ctx, int flags)
{
	struct ecdsa *c = ctx->ctx;

	c->d->functbl->fini(c->d, 0);
	c->q->functbl->fini(c->q, 0);
	c->curve->functbl->fini(c->curve, 0);

	drew_mem_free(c->d);
	drew_mem_free(c->q);
	drew_mem_free(c->curve);

	if (!(flags & DREW_PKSIG_FIXED))
		drew_mem_free(c);

	ctx->ctx = NULL;
	return 0;
}

#define CLONE(new, old, x) do { if (!(old)->x) new->x = NULL; \
	else old->x->functbl->clone(new->x, old->x, 0); } while (0)

static int ecdsa_clone(drew_pksig_t *newctx, const drew_pksig_t *oldctx,
		int flags)
{
	if (!(flags & DREW_PKSIG_FIXED))
		newctx->ctx = drew_mem_malloc(sizeof(struct ecdsa));

	memset(newctx->ctx, 0, sizeof(struct ecdsa));

	struct ecdsa *new = newctx->ctx, *old = oldctx->ctx;
	CLONE(new, old, d);
	CLONE(new, old, q);
	CLONE(new, old, curve);
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int ecdsa_generate(drew_pksig_t *ctx, const drew_param_t *param)
{
	return -DREW_ERR_NOT_IMPL;
}

static int ecdsa_setmode(drew_pksig_t *ctx, int flags)
{
	return 0;
}

static int ecdsa_setval(drew_pksig_t *ctx, const char *name, const uint8_t *buf,
		size_t len)
{
	struct ecdsa *c = ctx->ctx;

	if (!strcmp("d", name))
		c->d->functbl->setbytes(c->d, buf, len);
	else if (!strcmp("q", name))
		c->q->functbl->setcoordbytes(c->q, buf, len, DREW_ECC_POINT_SEC);
	else
		return -DREW_ERR_INVALID;

	return 0;
}

static int ecdsa_val(const drew_pksig_t *ctx, const char *name, uint8_t *data,
		size_t len)
{
	struct ecdsa *c = ctx->ctx;

	if (!strcmp("d", name))
		c->d->functbl->bytes(c->d, data, len);
	else if (!strcmp("q", name))
		c->q->functbl->coordbytes(c->q, data, len, DREW_ECC_POINT_SEC);
	else
		return -DREW_ERR_INVALID;
	return 0;
}

static int ecdsa_valsize(const drew_pksig_t *ctx, const char *name)
{
	struct ecdsa *c = ctx->ctx;

	if (!strcmp("d", name))
		return c->d->functbl->nbytes(c->d);
	else if (!strcmp("q", name))
		return c->q->functbl->ncoordbytes(c->q, DREW_ECC_POINT_SEC);
	else
		return -DREW_ERR_INVALID;
}

static int ecdsa_sign(const drew_pksig_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct ecdsa *c = ctx->ctx;
	drew_bignum_t t, kinv, z, p, *r = out, *s = out+1;
	const drew_bignum_t *h = in, *k = in+1;
	drew_ecc_point_t kpt, *K = &kpt;
	int res = 0;

	c->curve->functbl->point(c->curve, K);
	r->functbl->init(&z, 0, NULL, NULL);
	r->functbl->init(&p, 0, NULL, NULL);
	r->functbl->init(&t, 0, NULL, NULL);
	r->functbl->init(&kinv, 0, NULL, NULL);
	z.functbl->setzero(&z);

	// Compute the point corresponding to k (kG == K).
	c->curve->functbl->valpoint(c->curve, "g", K);
	c->curve->functbl->valbignum(c->curve, "p", &p, 0);
	K->functbl->mul(K, K, k);
	K->functbl->coordbignum(K, r, DREW_ECC_POINT_X);
	kinv.functbl->invmod(&kinv, k, &p);
	r->functbl->mod(r, r, &p);
	t.functbl->mulmod(&t, c->d, r, &p);
	t.functbl->add(&t, &t, h);
	s->functbl->mulmod(s, &kinv, &t, &p);
	// Check whether either r or s is zero.
	if (!r->functbl->compare(r, &z, 0) || !s->functbl->compare(s, &z, 0))
		res = -DREW_ERR_INVALID;
	t.functbl->fini(&t, 0);
	p.functbl->fini(&p, 0);
	kinv.functbl->fini(&kinv, 0);
	K->functbl->fini(K, 0);
	return res;
}

static int ecdsa_verify(const drew_pksig_t *ctx, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	struct ecdsa *c = ctx->ctx;
	const drew_bignum_t *r = in, *s = in+1, *h = in+2;
	drew_bignum_t *v = out, pbuf, *p = &pbuf;
	drew_bignum_t wbuf, *w = &wbuf, u1buf, *u1 = &u1buf, u2buf, *u2 = &u2buf;
	drew_bignum_t zbuf, *z = &zbuf;
	const drew_ecc_point_t *Q = c->q;
	drew_ecc_point_t Gpt, *G = &Gpt, Rpt, *R = &Rpt, Tpt, *T = &Tpt;
	int res = 0;

	r->functbl->init(w, 0, NULL, NULL);
	r->functbl->init(u1, 0, NULL, NULL);
	r->functbl->init(u2, 0, NULL, NULL);
	r->functbl->init(z, 0, NULL, NULL);
	r->functbl->init(p, 0, NULL, NULL);
	z->functbl->setzero(z);
	c->curve->functbl->point(c->curve, R);
	c->curve->functbl->point(c->curve, T);
	c->curve->functbl->valpoint(c->curve, "g", G);
	c->curve->functbl->valbignum(c->curve, "p", p, 0);
	// Check whether either r or s is zero.
	if (!r->functbl->compare(r, z, 0) || !s->functbl->compare(s, z, 0))
		res = -DREW_ERR_INVALID;
	w->functbl->invmod(w, s, p);
	u1->functbl->mulmod(u1, h, w, p);
	u2->functbl->mulmod(u2, r, w, p);
	T->functbl->mul(T, Q, u2);
	R->functbl->mul(R, G, u1);
	R->functbl->add(R, R, T);
	if (R->functbl->isinf(R))
		res = -DREW_ERR_INVALID;
	R->functbl->coordbignum(R, v, DREW_ECC_POINT_X);
	v->functbl->mod(v, v, p);
	w->functbl->fini(w, 0);
	u1->functbl->fini(u1, 0);
	u2->functbl->fini(u2, 0);
	z->functbl->fini(z, 0);
	p->functbl->fini(p, 0);
	R->functbl->fini(R, 0);
	T->functbl->fini(T, 0);
	return res;
}

struct plugin {
	const char *name;
	const drew_pksig_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "ECDSA", &ecdsa_functbl },
};

EXPORT()
int DREW_PLUGIN_NAME(ecdsa)(void *ldr, int op, int id, void *p)
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
			return -DREW_ERR_INVALID;
	}
}
UNEXPORT()
