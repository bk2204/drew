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
		0x65, 0xf8, 0x34, 0x08, 0x09, 0x22, 0x61, 0xbd,
		0xa5, 0x99, 0x38, 0x9d, 0xf0, 0x33, 0x82, 0xc5,
		0xbe, 0x01, 0xa8, 0x1f, 0xe0, 0x0a, 0x36, 0xf3,
		0xf4, 0xbb, 0x65, 0x41, 0x26, 0x3f, 0x80, 0x16,
		0x27, 0xc4, 0x40, 0xe5, 0x08, 0x09, 0x71, 0x2b,
		0x0c, 0xac, 0xe7, 0xc2, 0x17, 0xe6, 0xe5, 0x05,
		0x1a, 0xf8, 0x1d, 0xe9, 0xbf, 0xec, 0x32, 0x04,
		0xdc, 0xd6, 0x3c, 0x4f, 0x9a, 0x74, 0x10, 0x47
	};
	const uint8_t dbytes[] = {
		0xf7, 0x49, 0xd3, 0x27, 0x04, 0xbc, 0x53, 0x3c,
		0xa8, 0x2c, 0xef, 0x0a, 0xcf, 0x10, 0x3d, 0x8f,
		0x4f, 0xba, 0x67, 0xf0, 0x8d, 0x26, 0x78, 0xe5,
		0x15, 0xed, 0x7d, 0xb8, 0x86, 0x26, 0x7f, 0xfa,
		0xf0, 0x2f, 0xab, 0x00, 0x80, 0xdc, 0xa2, 0x35,
		0x9b, 0x72, 0xf5, 0x74, 0xcc, 0xc2, 0x9a, 0x0f,
		0x21, 0x8c, 0x86, 0x55, 0xc0, 0xcc, 0xcf, 0x9f,
		0xee, 0x6c, 0x5e, 0x56, 0x7a, 0xa1, 0x4c, 0xb9,
		0x26
	};
	const uint8_t qbytes[] = {
		0x04, 0x00,
		0x61, 0x38, 0x7f, 0xd6, 0xb9, 0x59, 0x14, 0xe8,
		0x85, 0xf9, 0x12, 0xed, 0xfb, 0xb5, 0xfb, 0x27,
		0x46, 0x55, 0x02, 0x7f, 0x21, 0x6c, 0x40, 0x91,
		0xca, 0x83, 0xe1, 0x93, 0x36, 0x74, 0x0f, 0xd8,
		0x1a, 0xed, 0xfe, 0x04, 0x7f, 0x51, 0xb4, 0x2b,
		0xdf, 0x68, 0x16, 0x11, 0x21, 0x01, 0x3e, 0x0d,
		0x55, 0xb1, 0x17, 0xa1, 0x4e, 0x43, 0x03, 0xf9,
		0x26, 0xc8, 0xde, 0xbb, 0x77, 0xa7, 0xfd, 0xaa,
		0xd1, 0x00,
		0xe7, 0xd0, 0xc7, 0x5c, 0x38, 0x62, 0x6e, 0x89,
		0x5c, 0xa2, 0x15, 0x26, 0xb9, 0xf9, 0xfd, 0xf8,
		0x4d, 0xce, 0xcb, 0x93, 0xf2, 0xb2, 0x33, 0x39,
		0x05, 0x50, 0xd2, 0xb1, 0x46, 0x3b, 0x7e, 0xe3,
		0xf5, 0x8d, 0xf7, 0x34, 0x64, 0x35, 0xff, 0x04,
		0x34, 0x19, 0x95, 0x83, 0xc9, 0x7c, 0x66, 0x5a,
		0x97, 0xf1, 0x2f, 0x70, 0x6f, 0x23, 0x57, 0xda,
		0x4b, 0x40, 0x28, 0x8d, 0xef, 0x88, 0x8e, 0x59,
		0xe6
	};
	const uint8_t kbytes[] = {
		0x3a, 0xf5, 0xab, 0x6c, 0xaa, 0x29, 0xa6, 0xde,
		0x86, 0xa5, 0xba, 0xb9, 0xaa, 0x83, 0xc3, 0xb1,
		0x6a, 0x17, 0xff, 0xcd, 0x52, 0xb5, 0xc6, 0x0c,
		0x76, 0x9b, 0xe3, 0x05, 0x3c, 0xdd, 0xde, 0xac,
		0x60, 0x81, 0x2d, 0x12, 0xfe, 0xcf, 0x46, 0xcf,
		0xe1, 0xf3, 0xdb, 0x9a, 0xc9, 0xdc, 0xf8, 0x81,
		0xfc, 0xec, 0x3f, 0x0a, 0xa7, 0x33, 0xd4, 0xec,
		0xbb, 0x83, 0xc7, 0x59, 0x3e, 0x86, 0x4c, 0x6d,
		0xf1
	};
	const uint8_t rbytes[] = {
		0x4d, 0xe8, 0x26, 0xea, 0x70, 0x4a, 0xd1, 0x0b,
		0xc0, 0xf7, 0x53, 0x8a, 0xf8, 0xa3, 0x84, 0x3f,
		0x28, 0x4f, 0x55, 0xc8, 0xb9, 0x46, 0xaf, 0x92,
		0x35, 0xaf, 0x5a, 0xf7, 0x4f, 0x2b, 0x76, 0xe0,
		0x99, 0xe4, 0xbc, 0x72, 0xfd, 0x79, 0xd2, 0x8a,
		0x38, 0x0f, 0x8d, 0x4b, 0x4c, 0x91, 0x9a, 0xc2,
		0x90, 0xd2, 0x48, 0xc3, 0x79, 0x83, 0xba, 0x05,
		0xae, 0xa4, 0x2e, 0x2d, 0xd7, 0x9f, 0xdd, 0x33,
		0xe8
	};
	const uint8_t sbytes[] = {
		0x87, 0x48, 0x8c, 0x85, 0x9a, 0x96, 0xfe, 0xa2,
		0x66, 0xea, 0x13, 0xbf, 0x6d, 0x11, 0x4c, 0x42,
		0x9b, 0x16, 0x3b, 0xe9, 0x7a, 0x57, 0x55, 0x90,
		0x86, 0xed, 0xb6, 0x4a, 0xed, 0x4a, 0x18, 0x59,
		0x4b, 0x46, 0xfb, 0x9e, 0xfc, 0x7f, 0xd2, 0x5d,
		0x8b, 0x2d, 0xe8, 0xf0, 0x9c, 0xa0, 0x58, 0x7f,
		0x54, 0xbd, 0x28, 0x72, 0x99, 0xf4, 0x7b, 0x2f,
		0xf1, 0x24, 0xaa, 0xc5, 0x66, 0xe8, 0xee, 0x3b,
		0x43
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
