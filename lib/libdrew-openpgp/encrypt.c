#include "internal.h"

#include <string.h>

#include <drew/block.h>
#include <drew/drew.h>
#include <drew/hash.h>
#include <drew/mem.h>
#include <drew/mode.h>
#include <drew/prng.h>

#include <drew-opgp/drew-opgp.h>

#include "structs.h"

struct drew_opgp_s;
typedef struct drew_opgp_s *drew_opgp_t;

struct drew_opgp_s {
	const drew_loader_t *ldr;
	drew_prng_t prng;
};

static int get_key_length(int skalgo)
{
	switch (skalgo) {
		case 1:
		case 3:
		case 4:
		case 7:
		case 11:
			return 16;
		case 2:
		case 8:
		case 12:
			return 24;
		case 9:
		case 10:
		case 13:
			return 32;
		case 0:
		default:
			return -DREW_ERR_INVALID;
	}
}

static int get_sk_name(const char **skname, int skalgo)
{
	const char *names[] = {
		NULL,
		"IDEA",
		"DESede",
		"CAST5",
		"Blowfish",
		NULL,
		NULL,
		"AES128",
		"AES192",
		"AES256",
		"Twofish",
		"Camellia",
		"Camellia",
		"Camellia"
	};
	if (skalgo < 0 || skalgo >= DIM(names))
		return -DREW_ERR_INVALID;
	*skname = names[skalgo];
	return 0;
}

static int make_sk(const drew_loader_t *ldr, drew_block_t *block, int algoid)
{
	int id = 0, res = 0;
	const void *tbl = NULL;
	const char *name = NULL;

	RETFAIL(get_sk_name(&name, algoid));

	id = drew_loader_lookup_by_name(ldr, name, 0, -1);
	if (id == -DREW_ERR_NONEXISTENT)
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	else if (id < 0)
		return id;	
	res = drew_loader_get_functbl(ldr, id, &tbl);
	if (res < 0)
		return res;
	block->functbl = tbl;
	RETFAIL(block->functbl->init(block, 0, ldr, NULL));
	return 0;
}

static int make_cfb(const drew_loader_t *ldr, drew_mode_t *mode,
		const drew_block_t *block)
{
	int id = 0, res = 0;
	const void *tbl = NULL;

	id = drew_loader_lookup_by_name(ldr, "CFB", 0, -1);
	if (id == -DREW_ERR_NONEXISTENT)
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	else if (id < 0)
		return id;	
	res = drew_loader_get_functbl(ldr, id, &tbl);
	if (res < 0)
		return res;
	mode->functbl = tbl;
	RETFAIL(mode->functbl->init(mode, 0, ldr, NULL));
	RETFAIL(mode->functbl->setblock(mode, block));
	return 0;
}

static int make_prng(const drew_loader_t *ldr, drew_prng_t *prng)
{
	int id = 0, res = 0;
	const void *tbl = NULL;

	id = drew_loader_lookup_by_name(ldr, "CounterDRBG", 0, -1);
	if (id == -DREW_ERR_NONEXISTENT)
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	else if (id < 0)
		return id;	
	res = drew_loader_get_functbl(ldr, id, &tbl);
	if (res < 0)
		return res;
	prng->functbl = tbl;
	RETFAIL(prng->functbl->init(prng, 0, ldr, NULL));
	return 0;
}

struct crypto {
	size_t keylen;
	size_t blocklen;
	drew_hash_t hash;
	drew_mode_t mode;
	drew_block_t block;
};

static int make_crypto(const drew_opgp_t ctx, struct crypto *c,
		const uint8_t *key, int skalgo)
{
	int res = 0;
	int keylen = get_key_length(skalgo);
	uint8_t zero[MAX_BLOCK_BLKSIZE] = {0x00};

	if (keylen < 0)
		return keylen;

	memset(c, 0, sizeof(*c));

	c->keylen = keylen;
	RETFAIL(make_hash(ctx->ldr, &c->hash, 2));
	RETFAIL(make_sk(ctx->ldr, &c->block, skalgo));
	c->blocklen = c->block.functbl->info(DREW_BLOCK_BLKSIZE, 0);
	/* CFB only uses encryption; no reason to set up decryption keys. */
	if ((res = c->block.functbl->setkey(&c->block, key, keylen,
					DREW_BLOCK_MODE_ENCRYPT)))
		goto out;
	if ((res = make_cfb(ctx->ldr, &c->mode, &c->block)))
		goto out;
	c->mode.functbl->setiv(&c->mode, zero, c->blocklen);
	return 0;
out:
	if (c->block.ctx)
		c->block.functbl->fini(&c->block, 0);
	if (c->hash.ctx)
		c->hash.functbl->fini(&c->hash, 0);
	return res;
}

static void free_crypto(struct crypto *c)
{
	c->hash.functbl->fini(&c->hash, 0);
	c->mode.functbl->fini(&c->mode, 0);
	c->block.functbl->fini(&c->block, 0);
}

int drew_opgp_new(drew_opgp_t *ctx, const drew_loader_t *ldr)
{
	drew_opgp_t c;
	int res = 0;
	if (!(c = drew_mem_calloc(1, sizeof(*c))))
		return -ENOMEM;
	c->ldr = ldr;
	if ((res = make_prng(ldr, &c->prng))) {
		drew_mem_free(c);
		return res;
	}
	*ctx = c;
	return 0;
}

int drew_opgp_free(drew_opgp_t *ctx)
{
	drew_opgp_t c = *ctx;
	c->prng.functbl->fini(&c->prng, 0);
	drew_mem_free(c);
	return 0;
}

/* This does not generate a public-private keypair, but instead a symmetric key.
 * It would be prudent to allocate the buffer from secure memory.
 */
int drew_opgp_sk_generate_key_random(drew_opgp_t ctx, uint8_t *buf,
		int skalgo)
{
	int keylen = get_key_length(skalgo);

	if (keylen < 0 || !buf)
		return keylen;
	
	ctx->prng.functbl->bytes(&ctx->prng, buf, keylen);
	ctx->prng.functbl->fini(&ctx->prng, 0);

	return keylen;
}

/* TODO: add as kdf algorithms. */
#define EXPBIAS 6
int drew_opgp_sk_s2k_octet_to_count(uint8_t c)
{
	return ((int32_t)16 + (c & 0xf)) << ((c >> 4) + EXPBIAS);
}

int drew_opgp_sk_s2k_count_to_octet(int32_t cnt)
{
	for (int i = 0; i < 16; i++) {
		int32_t val = cnt >> (i + EXPBIAS);
		if (val >= 16 && val <= 31)
			return (i << 4) | (val - 16);
	}
	return -DREW_ERR_INVALID;
}

int drew_opgp_sk_generate_key_from_passphrase(const drew_opgp_t ctx,
		uint8_t *buf, int skalgo, int s2kalgo, int mdalgo,
		const char *passphrase, const uint8_t *salt, int32_t count)
{
	uint8_t zero[4] = {0x00};
	size_t mdlen, niters;
	size_t passlen = strlen(passphrase);
	drew_hash_t hash;
	int keylen;

	if (mdalgo < 0 && mdalgo >= MAX_HASHES)
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	if ((keylen = get_key_length(skalgo)) < 0)
		return keylen;
	mdlen = hashes[mdalgo].len;
	niters = (keylen + mdlen - 1) / mdlen;
	RETFAIL(make_hash(ctx->ldr, &hash, mdalgo));
	for (size_t i = 0, off = 0; i < niters; i++, off += mdlen) {
		size_t nhashed = 0;
		hash.functbl->reset(&hash);
		hash.functbl->update(&hash, zero, i);
		do {
			if (s2kalgo & 1)
				hash.functbl->update(&hash, salt, 8);
			hash.functbl->update(&hash, (const uint8_t *)passphrase, passlen);
			nhashed += 8 + passlen;
		} while ((s2kalgo & 2) && nhashed < count);

		if ((keylen - off) < mdlen) {
			uint8_t tmp[MAX_DIGEST_SIZE];
			hash.functbl->final(&hash, tmp, 0);
			memset(tmp, 0, sizeof(tmp));
		}
		else
			hash.functbl->final(&hash, buf+off, 0);
	}
	hash.functbl->fini(&hash, 0);
	return 0;
}

static int endecrypt_skesk(const drew_opgp_t ctx, uint8_t *out,
		const uint8_t *in, size_t skesklen, const uint8_t *key, size_t keylen,
		int skalgo, int keyalgo)
{
	uint8_t algo = keyalgo;
	int res = 0;
	struct crypto c;

	RETFAIL(make_crypto(ctx, &c, key, skalgo));
	if (keyalgo) {
		c.mode.functbl->encrypt(&c.mode, out, &algo, 1);
		c.mode.functbl->encrypt(&c.mode, out+1, in, skesklen);
	}
	else {
		c.mode.functbl->decrypt(&c.mode, &algo, in, 1);
		c.mode.functbl->decrypt(&c.mode, out, in+1, skesklen);
	}
	res = algo;
	free_crypto(&c);
	return res ? res : (keyalgo ? 0 : algo);
}

/* out must be skesklen+1 bytes and in must be skesklen bytes. */
int drew_opgp_sk_encrypt_skesk(const drew_opgp_t ctx, uint8_t *out,
		const uint8_t *in, size_t skesklen, const uint8_t *key, size_t keylen,
		int skalgo, int keyalgo)
{
	return endecrypt_skesk(ctx, out, in, skesklen, key, keylen, skalgo,
			keyalgo);
}

/* out must be skesklen bytes and in must be skesklen+1 bytes. */
int drew_opgp_sk_decrypt_skesk(const drew_opgp_t ctx, uint8_t *out,
		const uint8_t *in, size_t skesklen, const uint8_t *key, size_t keylen,
		int skalgo)
{
	return endecrypt_skesk(ctx, out, in, skesklen, key, keylen, skalgo, 0);
}

/* in is of length len.  out is of length len + 2 + blocklength of skalgo. */
int drew_opgp_sk_encrypt_data_mdc(drew_opgp_t ctx, drew_opgp_hash_t mdc,
		uint8_t *out, const uint8_t *in, size_t len, const uint8_t *key,
		int skalgo)
{
	struct crypto c;
	const uint8_t suffix[2] = {0xd3, 0x14};
	int res = 0;
	size_t off;
	uint8_t randbytes[MAX_BLOCK_BLKSIZE];

	RETFAIL(make_crypto(ctx, &c, key, skalgo));
	ctx->prng.functbl->bytes(&ctx->prng, randbytes, c.blocklen);
	c.hash.functbl->update(&c.hash, randbytes, c.blocklen);
	c.hash.functbl->update(&c.hash, randbytes+c.blocklen-2, 2);
	c.mode.functbl->encrypt(&c.mode, out, randbytes, c.blocklen);
	off = c.blocklen;
	c.mode.functbl->encrypt(&c.mode, out+off, randbytes+off-2, 2);
	off += 2;
	memset(randbytes, 0, sizeof(randbytes));
	c.mode.functbl->encrypt(&c.mode, out+off, in, len);
	c.hash.functbl->update(&c.hash, in, len);
	c.hash.functbl->update(&c.hash, suffix, sizeof(suffix));
	c.hash.functbl->final(&c.hash, mdc, 0);
	free_crypto(&c);
	return res;
}
