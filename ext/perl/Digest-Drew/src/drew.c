#include <drew/drew.h>
#include <drew/plugin.h>
#include <drew/hash.h>

drew_hash_t *ctx_new(const char *algoname)
{
	int id = 0;
	drew_loader_t *ldr;
	drew_hash_t *ctx = NULL;
	const void *functbl;

	if (!algoname)
		return NULL;

	if (drew_loader_new(&ldr))
		return NULL;

	if (!(ctx = malloc(sizeof(*ctx))))
		goto err;

	ctx->priv = ldr;

	drew_loader_load_plugin(ldr, NULL, NULL);

	for (;;) {
		if ((id = drew_loader_lookup_by_name(ldr, algoname, id, -1)) < 0)
			goto err;
		if (drew_loader_get_type(ldr, id) == DREW_TYPE_HASH)
			break;
	}

	drew_loader_get_functbl(ldr, id, &functbl);
	ctx->functbl = functbl;
	
	if (ctx->functbl->init(ctx, 0, NULL, NULL))
		goto err;
	return ctx;
err:
	drew_loader_free(&ldr);
	free(ctx);
	return NULL;
}

void ctx_destroy(drew_hash_t *ctx)
{
	drew_loader_t *ldr;

	if (!ctx || !ctx->functbl)
		return;

	ldr = ctx->priv;

	ctx->functbl->fini(ctx, 0);
	if (ldr)
		drew_loader_free(&ldr);
	free(ctx);
}

drew_hash_t *ctx_clone(drew_hash_t *ctx)
{
	drew_hash_t *newctx = NULL;

	if (!ctx || !ctx->functbl)
		return NULL;

	if (!(newctx = malloc(sizeof(*newctx))))
		return NULL;

	newctx->priv = NULL;
	ctx->functbl->clone(newctx, ctx, 0);
	return newctx;
}
