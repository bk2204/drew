static drew_bignum_t *init_bignum(const drew_loader_t *ldr,
		const drew_param_t *param, const void *functbl)
{
	drew_bignum_t *ctx = malloc(sizeof(*ctx));

	ctx->functbl = functbl;
	ctx->functbl->init(ctx, 0, ldr, param);

	return ctx;
}

static int init(struct rsa *newctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
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

static int fini(struct rsa *c, int flags)
{
	free_bignum(c->p);
	free_bignum(c->q);
	free_bignum(c->e);
	free_bignum(c->d);
	free_bignum(c->n);
	free_bignum(c->u);
	memset(c, 0, sizeof(*c));
	if (!(flags & DREW_PKENC_FIXED))
		free(c);

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

static int setval(struct rsa *c, const char *name, const uint8_t *buf,
		size_t len)
{
	drew_bignum_t **p = get_named_mpi(c, name);

	if (!p)
		return -DREW_ERR_INVALID;

	drew_bignum_t *bn = *p;
	bn->functbl->setbytes(bn, buf, len);
	return 0;
}

static int val(const struct rsa *c, const char *name, uint8_t *data,
		size_t len)
{
	drew_bignum_t **p = get_named_mpi((struct rsa *)c, name);

	if (!p)
		return -DREW_ERR_INVALID;
	return (*p)->functbl->bytes(*p, data, len);
}

static int valsize(const struct rsa *c, const char *name)
{
	drew_bignum_t **p = get_named_mpi((struct rsa *)c, name);

	if (!p)
		return -DREW_ERR_INVALID;
	return (*p)->functbl->nbytes(*p);
}

static int encrypt(const struct rsa *c, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	drew_bignum_t *n = c->n;
	size_t outlen = n->functbl->nbytes(n);

	if (!out)
		return outlen;

	out[0].functbl->expmod(&out[0], &in[0], c->e, n);
	outlen = out[0].functbl->nbytes(&out[0]);
	return outlen;
}

static int decrypt(const struct rsa *c, drew_bignum_t *out,
		const drew_bignum_t *in)
{
	// FIXME: use chinese remainder theorem where possible.
	drew_bignum_t *n = c->n;
	size_t outlen = n->functbl->nbytes(n);

	if (!out)
		return outlen;

	out[0].functbl->expmod(&out[0], &in[0], c->d, n);
	outlen = out[0].functbl->nbytes(&out[0]);
	return outlen;
}
