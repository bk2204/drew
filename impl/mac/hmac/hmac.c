#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/mac.h>
#include <drew/hash.h>
#include <drew/plugin.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

struct hmac {
	const drew_loader_t *ldr;
	drew_hash_t outside;
	drew_hash_t inside;
	uint8_t *keybuf;
	size_t keybufsz;
	size_t blksz;
	size_t digestsz;
	const drew_param_t *param;
};

static int hmac_info(int op, void *p)
{
	return -EINVAL;
}

static int hmac_init(drew_mac_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	const char *algo = NULL;
	const drew_param_t *oparam = param;

	for (; param; param = param->next)
		if (!strcmp(param->name, "digest")) {
			algo = param->param.string;
		}

	if (!algo)
		return -EINVAL;

	int id = drew_loader_lookup_by_name(ldr, algo, 0, -1);
	if (id < 0)
		return -ENOENT;
	if (drew_loader_get_type(ldr, id) != DREW_TYPE_HASH)
		return -EINVAL;
	const void *tbl = NULL;
	if (drew_loader_get_functbl(ldr, id, &tbl) < 0)
		return -EINVAL;

	struct hmac *p = malloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	p->ldr = ldr;
	p->outside.functbl = p->inside.functbl = tbl;
	p->blksz = p->outside.functbl->info(DREW_HASH_BLKSIZE, NULL);
	p->digestsz = p->outside.functbl->info(DREW_HASH_SIZE, NULL);
	p->keybuf = malloc(p->digestsz);
	p->param = oparam;

	if (flags & DREW_MAC_FIXED) {
		memcpy(ctx->ctx, p, sizeof(*p));
		free(p);
	}
	else
		ctx->ctx = p;
	return 0;
}

static int hmac_clone(drew_mac_t *newctx, const drew_mac_t *oldctx, int flags)
{
	struct hmac *h;
	if (flags & DREW_MAC_FIXED) {
		memcpy(newctx->ctx, oldctx->ctx, sizeof(*h));
	}
	else {
		h = malloc(sizeof(*h));
		newctx->ctx = h;
	}

	return 0;
}

static int hmac_fini(drew_mac_t *ctx, int flags)
{
	struct hmac *h = ctx->ctx;
	h->outside.functbl->fini(&h->outside, 0);
	h->inside.functbl->fini(&h->inside, 0);
	memset(h, 0, sizeof(*h));

	if (!(flags & DREW_MAC_FIXED))
		ctx->ctx = NULL;
	return 0;
}

static int hmac_setkey(drew_mac_t *ctxt, const uint8_t *data, size_t len)
{
	struct hmac *ctx = ctxt->ctx;
	uint8_t *outpad;
	uint8_t *inpad;
	size_t i;
	const uint8_t *k = data;
	drew_hash_t keyhash;

	if (len > ctx->blksz) {
		keyhash.functbl->init(&keyhash, 0, ctx->ldr, ctx->param);
		keyhash.functbl->update(&keyhash, data, len);
		keyhash.functbl->final(&keyhash, ctx->keybuf, 0);
		k = ctx->keybuf;
		len = ctx->digestsz;
	}
	if (data != ctx->keybuf) {
		memcpy(ctx->keybuf, data, len);
		ctx->keybufsz = len;
	}

	size_t min = len < ctx->blksz ? len : ctx->blksz;
	outpad = calloc(ctx->blksz, 1);
	inpad = calloc(ctx->blksz, 1);
	for (i = 0; i < min; i++) {
		outpad[i] = 0x5c ^ k[i];
		inpad[i] = 0x36 ^ k[i];
	}
	memset(outpad+i, 0x5c, ctx->blksz - i);
	memset(inpad+i, 0x36, ctx->blksz - i);
	ctx->outside.functbl->init(&ctx->outside, 0, ctx->ldr, ctx->param);
	ctx->inside.functbl->init(&ctx->inside, 0, ctx->ldr, ctx->param);
	ctx->outside.functbl->update(&ctx->outside, outpad, ctx->blksz);
	ctx->inside.functbl->update(&ctx->inside, inpad, ctx->blksz);

	free(outpad);
	free(inpad);

	return 0;
}

static int hmac_reset(drew_mac_t *ctx)
{
	struct hmac *c = ctx->ctx;
	c->outside.functbl->reset(&c->outside); 
	c->inside.functbl->reset(&c->inside);
	return hmac_setkey(ctx, c->keybuf, c->keybufsz);
}

static int hmac_update(drew_mac_t *ctx, const uint8_t *data, size_t len)
{
	struct hmac *c = ctx->ctx;
	c->inside.functbl->update(&c->inside, data, len);

	return 0;
}

static int hmac_final(drew_mac_t *ctx, uint8_t *digest, int flags)
{
	struct hmac *c = ctx->ctx;
	uint8_t *buf = malloc(c->digestsz);

	c->inside.functbl->final(&c->inside, buf, 0);
	c->outside.functbl->update(&c->outside, buf, c->digestsz);
	c->outside.functbl->final(&c->outside, digest, 0);
	c->inside.functbl->reset(&c->inside);
	c->outside.functbl->reset(&c->outside);

	free(buf);

	return 0;
}

struct test {
	const uint8_t *key;
	size_t keysz;
	const uint8_t *data;
	size_t datasz;
	size_t datarep;
	const uint8_t *output;
};

static int hmac_test_generic(const drew_loader_t *ldr, const char *name,
		const struct test *testdata, size_t ntests, size_t outputsz)
{
	int result = 0;
	drew_mac_t c;
	uint8_t buf[128];

	for (size_t i = 0; i < ntests; i++) {
		const struct test *t = testdata + i;
		drew_param_t param;
		int retval;

		memset(buf, 0, sizeof(buf));
		result <<= 1;

		param.name = "digest";
		param.next = NULL;
		param.param.string = name;
		if ((retval = hmac_init(&c, 0, ldr, &param)))
			return retval;			
		hmac_setkey(&c, t->key, t->keysz);
		for (size_t j = 0; j < t->datarep; j++)
			hmac_update(&c, t->data, t->datasz);
		hmac_final(&c, buf, 0);

		result |= !!memcmp(buf, t->output, outputsz);
		hmac_fini(&c, 0);
	}
	
	return result;
}

#define U8P (const uint8_t *)
static int hmac_test_md5(const drew_loader_t *ldr, size_t *ntests)
{
	const uint8_t *eighty_aa = U8P "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
	struct test testdata[] = {
		{
			U8P "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
				"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
			16,
			U8P "Hi There",
			8,
			1,
			U8P "\x92\x94\x72\x7a\x36\x38\xbb\x1c"
				"\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d",
		},
		{
			U8P "Jefe",
			4,
			U8P "what do ya want for nothing?",
			28,
			1,
			U8P "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03"
				"\xea\xa8\x6e\x31\x0a\x5d\xb7\x38",
		},
		{
			U8P	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
				"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
			16,
			U8P "\xdd",
			1,
			50,
			U8P "\x56\xbe\x34\x52\x1d\x14\x4c\x88"
				"\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6",
		},
		{
			U8P "\x01\x02\x03\x04\x05\x06\x07\x08"
				"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
				"\x11\x12\x13\x14\x15\x16\x17\x18"
				"\x19",
			25,
			U8P "\xcd",
			1,
			50,
			U8P	"\x69\x7e\xaf\x0a\xca\x3a\x3a\xea"
				"\x3a\x75\x16\x47\x46\xff\xaa\x79",
 
		},
		{
			U8P "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
				"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
			16,
			U8P "Test With Truncation",
			20,
			1,
			U8P	"\x56\x46\x1e\xf2\x34\x2e\xdc\x00"
				"\xf9\xba\xb9\x95\x69\x0e\xfd\x4c",
 
		},
		{
			eighty_aa,
			80,
			U8P "Test Using Larger Than Block-Size Key - Hash Key First",
			54,
			1,
			U8P "\x6b\x1a\xb7\xfe\x4b\xd7\xbf\x8f"
				"\x0b\x62\xe6\xce\x61\xb9\xd0\xcd",
 
		},
		{
			eighty_aa,
			80,
			U8P "Test Using Larger Than Block-Size Key and Larger "
				"Than One Block-Size Data",
			73,
			1,
			U8P "\x6f\x63\x0f\xad\x67\xcd\xa0\xee"
				"\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e"
 
		}
	};

	*ntests = DIM(testdata);

	return hmac_test_generic(ldr, "MD5", testdata, DIM(testdata), 16);
}

static int hmac_test(void *p, const drew_loader_t *ldr)
{
	int result = 0, tres;
	size_t ntests = 0;
	if (!ldr)
		return -EINVAL;

	if ((tres = hmac_test_md5(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}

	return result;
}

static drew_mac_functbl_t hmac_functbl = {
	hmac_info, hmac_init, hmac_clone, hmac_reset, hmac_fini, hmac_setkey,
	hmac_update, hmac_update, hmac_final, hmac_test
};

struct plugin {
	const char *name;
	drew_mac_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "HMAC", &hmac_functbl }
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
			return DREW_TYPE_MAC;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return sizeof(drew_mac_functbl_t);
		case DREW_LOADER_GET_FUNCTBL:
			memcpy(p, plugin_data[id].functbl, sizeof(drew_mac_functbl_t));
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
