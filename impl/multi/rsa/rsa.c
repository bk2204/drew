struct mapping {
	const char *name;
	size_t index;
};

static const struct mapping enc_in[] = {
	{"m", 0},
},
enc_out[] = {
	{"c", 0},
},
dec_in[] = {
	{"c", 0},
},
dec_out[] = {
	{"m", 0}
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
	const drew_bignum_t *bignum = NULL;

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
