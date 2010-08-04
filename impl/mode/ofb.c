#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mode.h>
#include <block.h>
#include <plugin.h>

#define DIM(x) (sizeof(x)/sizeof((x)[0]))

struct ofb {
	drew_loader_t *ldr;
	void *algo;
	const drew_block_functbl_t *functbl;
	uint8_t *buf;
	size_t blksize;
	size_t boff;
};

static int ofb_info(int op, void *p)
{
	return -EINVAL;
}

static void ofb_init(void **ctx, drew_loader_t *ldr, const drew_param_t *param)
{
	struct ofb *newctx;

	newctx = malloc(sizeof(*newctx));
	newctx->ldr = ldr;
	newctx->blksize = 0;
	newctx->algo = NULL;
	newctx->functbl = NULL;
	newctx->boff = 0;

	*ctx = newctx;
}

static int ofb_setpad(void *ctx, const char *algoname, void *algoctx)
{
	return -EINVAL;
}

static int ofb_setblock(void *ctx, const char *algoname, void *algoctx)
{
	struct ofb *c = ctx;
	const void *tmp;
	int id;

	id = drew_loader_lookup_by_name(c->ldr, algoname, 0, -1);
	if (id < 0)
		return id;
	drew_loader_get_functbl(c->ldr, id, &tmp);
	c->functbl = tmp;

	/* You really do need to pass something for the algoctx parameter, because
	 * otherwise you haven't set a key for the algorithm.  That's a bit bizarre,
	 * but we might allow it in the future (such as for PRNGs).
	 */
	if (algoctx)
		c->algo = algoctx;
	else
		return -EINVAL;

	c->blksize = c->functbl->info(DREW_BLOCK_BLKSIZE, NULL);
	if (!c->blksize)
		c->blksize = c->blksize;
	if (!(c->buf = malloc(c->blksize)))
		return -ENOMEM;

	return 0;
}

static int ofb_setiv(void *ctx, const uint8_t *iv, size_t len)
{
	struct ofb *c = ctx;

	if (c->blksize != len)
		return -EINVAL;

	memcpy(c->buf, iv, len);
	return 0;
}

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

/* There is no decrypt function because encryption and decryption are exactly
 * the same.
 */
static void ofb_encrypt(void *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
	struct ofb *c = ctx;

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
		c->functbl->encrypt(c->algo, c->buf, c->buf);
		for (size_t i = 0; i < c->blksize; i++)
			out[i] = c->buf[i] ^ in[i];
		len -= c->blksize;
		out += c->blksize;
		in += c->blksize;
	}

	if (len) {
		c->functbl->encrypt(c->algo, c->buf, c->buf);
		for (size_t i = 0; i < len; i++)
			out[i] = c->buf[i] ^ in[i];
		c->boff = len;
	}
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

static void ofb_fini(void **ctx);

static int ofb_test_generic(drew_loader_t *ldr, const char *name,
		const struct test *testdata, size_t ntests)
{
	int id, result = 0;
	const drew_block_functbl_t *functbl;
	void *algo, *c;
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

		ofb_init(&c, ldr, NULL);
		functbl->init(&algo, ldr, NULL);
		functbl->setkey(algo, testdata[i].key, testdata[i].keysz);
		ofb_setblock(c, name, algo);
		ofb_setiv(c, testdata[i].iv, testdata[i].ivsz);
		/* We use 9 here because it tests all three code paths for 64-bit
		 * blocks.
		 */
		for (size_t j = 0; j < testdata[i].datasz; j += 9)
			ofb_encrypt(c, buf+j, testdata[i].input+j,
					MIN(9, testdata[i].datasz - j));

		result |= !!memcmp(buf, testdata[i].output, testdata[i].datasz);
		ofb_fini(&c);
		functbl->fini(&algo);

		ofb_init(&c, ldr, NULL);
		functbl->init(&algo, ldr, NULL);
		functbl->setkey(algo, testdata[i].key, testdata[i].keysz);
		ofb_setblock(c, name, algo);
		ofb_setiv(c, testdata[i].iv, testdata[i].ivsz);
		for (size_t j = 0; j < testdata[i].datasz; j += 9)
			ofb_encrypt(c, buf+j, testdata[i].output+j,
					MIN(9, testdata[i].datasz - j));

		result |= !!memcmp(buf, testdata[i].input, testdata[i].datasz);
		ofb_fini(&c);
		functbl->fini(&algo);
	}
	
	return result;
}

static int ofb_test_cast5(drew_loader_t *ldr, size_t *ntests)
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

static int ofb_test_blowfish(drew_loader_t *ldr, size_t *ntests)
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

static int ofb_test(void *p)
{
	drew_loader_t *ldr = p;
	int result = 0, tres;
	size_t ntests = 0;
	if (!p)
		return -EINVAL;

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

static void ofb_fini(void **ctx)
{
	struct ofb *c = *ctx;

	memset(c, 0, sizeof(*c));
	free(c);

	*ctx = NULL;
}

static int ofb_clone(void **newctx, void *oldctx, int flags)
{
	struct ofb *c;
	if (flags & DREW_MODE_CLONE_FIXED) {
		memcpy(*newctx, oldctx, sizeof(*c));
	}
	else {
		c = malloc(sizeof(*c));
		*newctx = c;
	}
	return 0;
}

static drew_mode_functbl_t ofb_functbl = {
	ofb_info, ofb_init, ofb_setpad, ofb_setblock, ofb_setiv, ofb_encrypt,
	ofb_encrypt, ofb_test, ofb_fini, ofb_clone
};

struct plugin {
	const char *name;
	drew_mode_functbl_t *functbl;
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
