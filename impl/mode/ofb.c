#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mode.h>
#include <block.h>
#include <plugin.h>
#include <util.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

struct ofb {
	const drew_loader_t *ldr;
	const drew_block_t *algo;
	uint8_t buf[32] ALIGNED_T;
	size_t blksize;
	size_t boff;
	size_t chunks;
};

static int ofb_info(int op, void *p);
static int ofb_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param);
static int ofb_setpad(drew_mode_t *ctx, const drew_pad_t *pad);
static int ofb_setblock(drew_mode_t *ctx, const drew_block_t *algoctx);
static int ofb_setiv(drew_mode_t *ctx, const uint8_t *iv, size_t len);
static int ofb_encrypt(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int ofb_encryptfast(drew_mode_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int ofb_fini(drew_mode_t *ctx, int flags);
static int ofb_test(void *p, const drew_loader_t *ldr);
static int ofb_clone(drew_mode_t *newctx, const drew_mode_t *oldctx, int flags);
static int ofb_setdata(drew_mode_t *, const uint8_t *, size_t);
static int ofb_final(drew_mode_t *, uint8_t *, size_t);

static const drew_mode_functbl_t ofb_functbl = {
	ofb_info, ofb_init, ofb_clone, ofb_fini, ofb_setpad, ofb_setblock,
	ofb_setiv, ofb_encrypt, ofb_encrypt, ofb_encrypt, ofb_encrypt,
	ofb_setdata, ofb_final, ofb_final,
	ofb_test
};
static const drew_mode_functbl_t ofb_functblfast = {
	ofb_info, ofb_init, ofb_clone, ofb_fini, ofb_setpad, ofb_setblock,
	ofb_setiv, ofb_encrypt, ofb_encrypt, ofb_encryptfast, ofb_encryptfast,
	ofb_setdata, ofb_final, ofb_final,
	ofb_test
};

static int ofb_info(int op, void *p)
{
	switch (op) {
		case DREW_MODE_VERSION:
			return 2;
		case DREW_MODE_INTSIZE:
			return sizeof(struct ofb);
		case DREW_MODE_QUANTUM:
		default:
			return DREW_ERR_INVALID;
	}
}

static int ofb_init(drew_mode_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	struct ofb *newctx = ctx->ctx;

	if (!(flags & DREW_MODE_FIXED))
		newctx = malloc(sizeof(*newctx));
	newctx->ldr = ldr;
	newctx->algo = NULL;
	newctx->boff = 0;
	
	ctx->ctx = newctx;
	ctx->functbl = &ofb_functbl;

	return 0;
}

static int ofb_setpad(drew_mode_t *ctx, const drew_pad_t *algoname)
{
	return -EINVAL;
}

static int ofb_setblock(drew_mode_t *ctx, const drew_block_t *algoctx)
{
	struct ofb *c = ctx->ctx;

	/* You really do need to pass something for the algoctx parameter, because
	 * otherwise you haven't set a key for the algorithm.  That's a bit bizarre,
	 * but we might allow it in the future (such as for PRNGs).
	 */
	if (!algoctx)
		return DREW_ERR_INVALID;

	c->algo = algoctx;
	c->blksize = c->algo->functbl->info(DREW_BLOCK_BLKSIZE, NULL);
	if (c->blksize == 8 || c->blksize == 16) {
		c->chunks = DREW_MODE_ALIGNMENT / c->blksize;
		ctx->functbl = &ofb_functblfast;
	}

	return 0;
}

static int ofb_setiv(drew_mode_t *ctx, const uint8_t *iv, size_t len)
{
	struct ofb *c = ctx->ctx;

	if (c->blksize != len)
		return -EINVAL;

	memcpy(c->buf, iv, len);
	return 0;
}

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

/* There is no decrypt function because encryption and decryption are exactly
 * the same.
 */
static int ofb_encrypt(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct ofb *c = ctx->ctx;
	uint8_t *out = outp;
	const uint8_t *in = inp;

	if (c->boff) {
		const size_t b = MIN(c->blksize - c->boff, len);
		for (size_t i = 0; i < b; i++)
			out[i] = c->buf[c->boff + i] ^ in[i];
		if ((c->boff += b) == c->blksize)
			c->boff = 0;
		len -= b;
		out += b;
		in += b;
	}

	while (len >= c->blksize) {
		c->algo->functbl->encrypt(c->algo, c->buf, c->buf);
		for (size_t i = 0; i < c->blksize; i++)
			out[i] = c->buf[i] ^ in[i];
		len -= c->blksize;
		out += c->blksize;
		in += c->blksize;
	}

	if (len) {
		c->algo->functbl->encrypt(c->algo, c->buf, c->buf);
		for (size_t i = 0; i < len; i++)
			out[i] = c->buf[i] ^ in[i];
		c->boff = len;
	}
	return 0;
}

struct aligned {
	uint8_t data[DREW_MODE_ALIGNMENT] ALIGNED_T;
};

static int ofb_encryptfast(drew_mode_t *ctx, uint8_t *outp, const uint8_t *inp,
		size_t len)
{
	struct ofb *c = ctx->ctx;
	struct aligned *out = (struct aligned *)outp;
	const struct aligned *in = (const struct aligned *)inp;

	len /= DREW_MODE_ALIGNMENT;
	for (size_t iters = 0; iters < len; iters++, in++, out++) {
		c->algo->functbl->encryptfast(c->algo, c->buf, c->buf, c->chunks);
#ifdef VECTOR_T
		typedef int vector_t __attribute__ ((vector_size (16)));
		vector_t bufv, inv;
		memcpy(&bufv, c->buf, sizeof(vector_t));
		memcpy(&inv, in->data, sizeof(vector_t));
		bufv ^= inv;
		memcpy(out->data, &bufv, sizeof(vector_t));
#else
		for (int i = 0; i < DREW_MODE_ALIGNMENT; i++)
			out->data[i] = c->buf[i] ^ in->data[i];
#endif
	}
	return 0;
}

static int ofb_setdata(drew_mode_t *ctx, const uint8_t *data, size_t len)
{
	return -DREW_ERR_NOT_ALLOWED;
}

static int ofb_final(drew_mode_t *ctx, uint8_t *data, size_t len)
{
	return -DREW_ERR_NOT_ALLOWED;
}


struct test {
	const uint8_t *key;
	size_t keysz;
	const uint8_t *iv;
	size_t ivsz;
	const uint8_t *input;
	const uint8_t *output;
	size_t datasz;
};

static int ofb_test_generic(const drew_loader_t *ldr, const char *name,
		const struct test *testdata, size_t ntests)
{
	int id, result = 0;
	const drew_block_functbl_t *functbl;
	drew_block_t algo;
	drew_mode_t c;
	const void *tmp;
	uint8_t buf[128];

	id = drew_loader_lookup_by_name(ldr, name, 0, -1);
	if (id < 0)
		return id;

	drew_loader_get_functbl(ldr, id, &tmp);
	functbl = tmp;

	for (size_t i = 0; i < ntests; i++) {
		memset(buf, 0, sizeof(buf));
		result <<= 1;

		ofb_init(&c, 0, ldr, NULL);
		functbl->init(&algo, 0, ldr, NULL);
		algo.functbl->setkey(&algo, testdata[i].key, testdata[i].keysz,
				DREW_BLOCK_MODE_ENCRYPT);
		ofb_setblock(&c, &algo);
		ofb_setiv(&c, testdata[i].iv, testdata[i].ivsz);
		/* We use 9 here because it tests all three code paths for 64-bit
		 * blocks.
		 */
		for (size_t j = 0; j < testdata[i].datasz; j += 9)
			ofb_encrypt(&c, buf+j, testdata[i].input+j,
					MIN(9, testdata[i].datasz - j));

		result |= !!memcmp(buf, testdata[i].output, testdata[i].datasz);
		ofb_fini(&c, 0);
		algo.functbl->fini(&algo, 0);

		ofb_init(&c, 0, ldr, NULL);
		functbl->init(&algo, 0, ldr, NULL);
		algo.functbl->setkey(&algo, testdata[i].key, testdata[i].keysz,
				DREW_BLOCK_MODE_ENCRYPT);
		ofb_setblock(&c, &algo);
		ofb_setiv(&c, testdata[i].iv, testdata[i].ivsz);
		for (size_t j = 0; j < testdata[i].datasz; j += 9)
			ofb_encrypt(&c, buf+j, testdata[i].output+j,
					MIN(9, testdata[i].datasz - j));

		result |= !!memcmp(buf, testdata[i].input, testdata[i].datasz);
		ofb_fini(&c, 0);
		algo.functbl->fini(&algo, 0);
	}
	
	return result;
}

static int ofb_test_cast5(const drew_loader_t *ldr, size_t *ntests)
{
	uint8_t buf[8];
	struct test testdata[] = {
		{
			(const uint8_t *)"\x01\x23\x45\x67\x12\x34\x56\x78"
				"\x23\x45\x67\x89\x34\x56\x78\x9a",
			16,
			buf,
			8,
			(const uint8_t *)"\x01\x23\x45\x67\x89\xab\xcd\xef",
			(const uint8_t *)"\x34\xf2\x64\x83\x3a\x2e\x07\x5d",
			8
		},
		{
			(const uint8_t *)"\xfe\xdc\xba\x98\x76\x54\x32\x10"
				"\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87",
			16,
			(const uint8_t *)"\x01\x23\x45\x67\x12\x34\x56\x78",
			8,
			(const uint8_t *)"This is CAST5/OFB.",
			(const uint8_t *)"\x2c\xfc\xe2\xf4\x55\xe3\x8d\x7f"
				"\x84\x81\xf8\x42\x87\x66\x28\x94\x02\x4a",
			18
		},
	};

	memset(buf, 0, sizeof(buf));
	*ntests = DIM(testdata);

	return ofb_test_generic(ldr, "CAST-128", testdata, DIM(testdata));
}

static int ofb_test_blowfish(const drew_loader_t *ldr, size_t *ntests)
{
	struct test testdata[] = {
		{
			(const uint8_t *)"\x01\x23\x45\x67\x89\xab\xcd\xef"
				"\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87",
			16,
			(const uint8_t *)"\xfe\xdc\xba\x98\x76\x54\x32\x10",
			8,
			(const uint8_t *)"7654321 Now is the time for ",
			(const uint8_t *)"\xe7\x32\x14\xa2\x82\x21\x39\xca"
				"\x62\xb3\x43\xcc\x5b\x65\x58\x73"
				"\x10\xdd\x90\x8d\x0c\x24\x1b\x22"
				"\x63\xc2\xcf\x80\xda",
			29
		}
	};

	*ntests = DIM(testdata);

	return ofb_test_generic(ldr, "Blowfish", testdata, DIM(testdata));
}

static int ofb_test(void *p, const drew_loader_t *ldr)
{
	int result = 0, tres;
	size_t ntests = 0;

	if ((tres = ofb_test_cast5(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}
	if ((tres = ofb_test_blowfish(ldr, &ntests)) >= 0) {
		result <<= ntests;
		result |= tres;
	}

	return result;
}

static int ofb_fini(drew_mode_t *ctx, int flags)
{
	struct ofb *c = ctx->ctx;

	memset(c, 0, sizeof(*c));
	if (!(flags & DREW_MODE_FIXED))
		free(c);

	ctx->ctx = NULL;
	return 0;
}

static int ofb_clone(drew_mode_t *newctx, const drew_mode_t *oldctx, int flags)
{
	if (!(flags & DREW_MODE_FIXED))
		newctx->ctx = malloc(sizeof(struct ofb));
	memcpy(newctx->ctx, oldctx->ctx, sizeof(struct ofb));
	newctx->functbl = oldctx->functbl;
	return 0;
}


struct plugin {
	const char *name;
	const drew_mode_functbl_t *functbl;
};

static struct plugin plugin_data[] = {
	{ "OFB", &ofb_functbl }
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
			return DREW_TYPE_MODE;
		case DREW_LOADER_GET_FUNCTBL_SIZE:
			return sizeof(drew_mode_functbl_t);
		case DREW_LOADER_GET_FUNCTBL:
			memcpy(p, plugin_data[id].functbl, sizeof(drew_mode_functbl_t));
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
