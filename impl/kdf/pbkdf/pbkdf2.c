#include "internal.h"
#include "util.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/kdf.h>
#include <drew/mem.h>
#include <drew/plugin.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

/* This needs to be large enough to handle the output size of the underlying
 * PRF (usually that of the hash algorithm used in the HMAC instance).
 */
#define BUFFER_SIZE		256

HIDE()
struct pbkdf {
	const drew_loader_t *ldr;
	drew_kdf_t prf;
	uint8_t *salt;
	uint8_t saltsz;
	size_t count;
	size_t prfsz;
};

static int pbkdf_info(int op, void *p)
{
	drew_kdf_t *kdf = p;
	struct pbkdf *ctx;
	switch (op) {
		case DREW_KDF_VERSION:
			return 2;
		case DREW_KDF_SIZE:
			return 0;
		case DREW_KDF_BLKSIZE:
			if (!p)
				return -DREW_ERR_MORE_INFO;
			ctx = kdf->ctx;
			return ctx->prf.functbl->info(op, &ctx->prf);
		case DREW_KDF_ENDIAN:
			return 0;
		case DREW_KDF_INTSIZE:
			return sizeof(struct pbkdf);
	}
	return -DREW_ERR_INVALID;
}

static int pbkdf_init(drew_kdf_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	int res = 0;
	drew_kdf_t *algo = NULL;
	const drew_param_t *oparam = param;

	for (; param; param = param->next)
		if (!strcmp(param->name, "prf")) {
			algo = param->param.value;
		}

	if (!algo)
		return -DREW_ERR_INVALID;

	struct pbkdf *p = drew_mem_scalloc(1, sizeof(*p));
	if (!p)
		return -ENOMEM;
	p->ldr = ldr;
	p->prf.functbl = algo->functbl;
	p->prf.functbl->clone(&p->prf, algo, 0);
	p->prf.functbl->reset(&p->prf);
	if ((res = p->prf.functbl->info(DREW_KDF_SIZE, &p->prf)) < 0)
		return res;
	p->prfsz = res;

	if (p->prfsz > BUFFER_SIZE) {
		drew_mem_sfree(p);
		return -DREW_ERR_NOT_IMPL;
	}

	if (flags & DREW_KDF_FIXED) {
		memcpy(ctx->ctx, p, sizeof(*p));
		drew_mem_sfree(p);
	}
	else
		ctx->ctx = p;
	return 0;
}

static int pbkdf_clone(drew_kdf_t *newctx, const drew_kdf_t *oldctx, int flags)
{
	struct pbkdf *h, *old = oldctx->ctx;
	if (flags & DREW_KDF_FIXED) {
		memcpy(newctx->ctx, oldctx->ctx, sizeof(*h));
	}
	else {
		if (!(h = drew_mem_smalloc(sizeof(*h))))
			return -ENOMEM;
		newctx->ctx = h;
	}
	h = newctx->ctx;
	h->salt = drew_mem_smemdup(old->salt, h->saltsz);

	return 0;
}

static int pbkdf_fini(drew_kdf_t *ctx, int flags)
{
	struct pbkdf *h = ctx->ctx;
	drew_mem_sfree(h->salt);
	h->prf.functbl->fini(&h->prf, 0);

	if (!(flags & DREW_KDF_FIXED)) {
		drew_mem_sfree(ctx->ctx);
		ctx->ctx = NULL;
	}
	else
		memset(ctx->ctx, 0, sizeof(*ctx->ctx));
	return 0;
}

static int pbkdf_reset(drew_kdf_t *ctx)
{
	struct pbkdf *c = ctx->ctx;
	return c->prf.functbl->reset(&c->prf); 
}

int pbkdf_setkey(drew_kdf_t *ctx, const uint8_t *key, size_t len)
{
	return -DREW_ERR_NOT_ALLOWED;
}

int pbkdf_setsalt(drew_kdf_t *ctx, const uint8_t *salt, size_t len)
{
	struct pbkdf *c = ctx->ctx;
	c->salt = drew_mem_smemdup(salt, len);
	c->saltsz = len;
	return 0;
}

int pbkdf_setcount(drew_kdf_t *ctx, size_t count)
{
	struct pbkdf *c = ctx->ctx;
	c->count = count;
	return 0;
}

static inline void store_uint32(uint8_t *p, uint32_t x)
{
	p[0] = x >> 24;
	p[1] = x >> 16;
	p[2] = x >> 8;
	p[3] = x;
}

int pbkdf_generate(drew_kdf_t *ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	struct pbkdf *h = ctx->ctx;
	uint8_t buf[BUFFER_SIZE], extra[BUFFER_SIZE], *tmp;
	uint8_t *outp = out;
	drew_kdf_t *prf = &h->prf;

	// This prevents some integer underflows later.
	if (!outlen || !h->count)
		return -DREW_ERR_INVALID;

	size_t L = (outlen + (h->prfsz - 1)) / h->prfsz;
	size_t r = outlen - ((L - 1) * h->prfsz);

	tmp = drew_mem_smalloc(h->saltsz + 4);
	memcpy(tmp, h->salt, h->saltsz);

	prf->functbl->reset(prf);
	prf->functbl->setkey(prf, in, inlen);
	uint8_t *storep = outp;
	for (size_t i = 0; i < L; i++, outp += h->prfsz) {
		storep = (i == L-1 && r != h->prfsz) ? extra : outp;
		prf->functbl->reset(prf);
		store_uint32(tmp+h->saltsz, i+1);
		prf->functbl->generate(prf, storep, h->prfsz, tmp, h->saltsz+4);
		memcpy(buf, storep, h->prfsz);
		for (size_t j = 1; j < h->count; j++) {
			prf->functbl->reset(prf);
			prf->functbl->generate(prf, buf, h->prfsz, buf, h->prfsz);
			xor_buffers2(storep, buf, h->prfsz);
		}
	}
	if (storep == extra)
		memcpy(outp-h->prfsz, extra, r);

	memset(buf, 0, sizeof(buf));
	memset(extra, 0, sizeof(extra));
	drew_mem_sfree(tmp);

	return 0;
}

#if 0
struct test {
	const uint8_t *key;
	size_t keysz;
	const uint8_t *data;
	size_t datasz;
	size_t datarep;
	const uint8_t *output;
};

static int pbkdf_test_generic(const drew_loader_t *ldr, const char *name,
		const struct test *testdata, size_t ntests, size_t outputsz)
{
	int result = 0;
	drew_kdf_t c;
	uint8_t buf[BUFFER_SIZE];
	drew_param_t param;
	drew_hash_t hash;
	int id;

	if ((id = drew_loader_lookup_by_name(ldr, name, 0, -1)) < 0)
		return id;
	drew_loader_get_functbl(ldr, id, (const void **)&hash.functbl);

	hash.functbl->init(&hash, 0, ldr, NULL);

	param.name = "digest";
	param.next = NULL;
	param.param.value = &hash;

	for (size_t i = 0; i < ntests; i++) {
		const struct test *t = testdata + i;
		int retval;

		memset(buf, 0, sizeof(buf));
		result <<= 1;

		hash.functbl->reset(&hash);
		if ((retval = pbkdf_init(&c, 0, ldr, &param)))
			return retval;			
		pbkdf_setkey(&c, t->key, t->keysz);
		for (size_t j = 0; j < t->datarep; j++)
			pbkdf_update(&c, t->data, t->datasz);
		pbkdf_final(&c, buf, 0);

		result |= !!memcmp(buf, t->output, outputsz);
		pbkdf_fini(&c, 0);
	}
	hash.functbl->fini(&hash, 0);
	
	return result;
}

#define U8P (const uint8_t *)
#define EIGHTY_AA U8P "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
static const struct test testdata_md5[] = {
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
		EIGHTY_AA,
		80,
		U8P "Test Using Larger Than Block-Size Key - Hash Key First",
		54,
		1,
		U8P "\x6b\x1a\xb7\xfe\x4b\xd7\xbf\x8f"
			"\x0b\x62\xe6\xce\x61\xb9\xd0\xcd",

	},
	{
		EIGHTY_AA,
		80,
		U8P "Test Using Larger Than Block-Size Key and Larger "
			"Than One Block-Size Data",
		73,
		1,
		U8P "\x6f\x63\x0f\xad\x67\xcd\xa0\xee"
			"\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e"

	}
};

static int pbkdf_test_md5(const drew_loader_t *ldr, size_t *ntests)
{
	*ntests = DIM(testdata_md5);

	return pbkdf_test_generic(ldr, "MD5", testdata_md5, DIM(testdata_md5), 16);
}
#endif

static int pbkdf_test(void *p, const drew_loader_t *ldr)
{
	int result = 0, tres;
	size_t ntests = 0;
	if (!ldr)
		return -DREW_ERR_INVALID;

#if 0
	if ((tres = pbkdf_test_md5(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}
	return result;
#else
	return -DREW_ERR_NOT_IMPL;
#endif
}

static drew_kdf_functbl_t pbkdf_functbl = {
	pbkdf_info, pbkdf_init, pbkdf_clone, pbkdf_reset, pbkdf_fini, pbkdf_setkey,
	pbkdf_setsalt, pbkdf_setcount, pbkdf_generate, pbkdf_test
};

struct plugin {
	const char *name;
	const void *functbl;
};

static struct plugin plugin_data[] = {
	{ "PBKDF2", &pbkdf_functbl }
};

EXPORT()
int DREW_PLUGIN_NAME(pbkdf2)(void *ldr, int op, int id, void *p)
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
			return DREW_TYPE_KDF;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return sizeof(drew_kdf_functbl_t);
		case DREW_LOADER_GET_FUNCTBL:
			memcpy(p, plugin_data[id].functbl, sizeof(drew_kdf_functbl_t));
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
UNHIDE()
