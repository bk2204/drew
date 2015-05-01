/*-
 * Copyright © 2011 brian m. carlson
 *
 * This file is part of the Drew Cryptography Suite.
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of your choice of version 2 of the GNU General Public License as
 * published by the Free Software Foundation or version 2.0 of the Apache
 * License as published by the Apache Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but without
 * any warranty; without even the implied warranty of merchantability or fitness
 * for a particular purpose.
 *
 * Note that people who make modified versions of this file are not obligated to
 * dual-license their modified versions; it is their choice whether to do so.
 * If a modified version is not distributed under both licenses, the copyright
 * and permission notices should be updated accordingly.
 */
#include "sp800-90.hh"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <utility>

#include "prng-plugin.h"
#include "util.hh"

HIDE()
template<class T>
static int make_new(T *ctx, DrewLoader *ldr, const drew_param_t *param,
		const char *paramname, int type, const char *algonames[], size_t nalgos)
{
	for (const drew_param_t *p = param; p && paramname; p = p->next) {
		if (!strcmp(p->name, paramname)) {
			memcpy(ctx, p->param.value, sizeof(*ctx));
			return 0;
		}
	}
	for (size_t i = 0; i < nalgos; i++) {
		int id = -1;
		if ((id = drew_loader_lookup_by_name(ldr, algonames[i], 0, -1)) < 0)
			continue;
		if (drew_loader_get_type(ldr, id) != type)
			continue;
		const void *functbl;
		if ((id = drew_loader_get_functbl(ldr, id, &functbl)) < 0)
			continue;
		// We need this since we can't assign void * to non-void *.
		memcpy(&ctx->functbl, &functbl, sizeof(void *));
		if (ctx->functbl->init(ctx, 0, ldr, param))
			continue;
		return 0;
	}
	return -DREW_ERR_NONEXISTENT;
}

template<class T>
static int sp_algo_info(int op, void *p)
{
	switch (op) {
		case DREW_PRNG_VERSION:
			return CURRENT_ABI;
		case DREW_PRNG_BLKSIZE:
			return 256;
		case DREW_PRNG_SEEDABLE:
			return 1;
		case DREW_PRNG_MUST_SEED:
			return 0;
		case DREW_PRNG_INTSIZE:
			return sizeof(T);
		case DREW_PRNG_BLOCKING:
			return 0;
		default:
			return -DREW_ERR_INVALID;
	}
}

template<class T>
static int sp_algo_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *)
{
	switch (op) {
		case DREW_PRNG_VERSION:
			return CURRENT_ABI;
		case DREW_PRNG_BLKSIZE_CTX:
			return -DREW_ERR_NOT_IMPL;
		case DREW_PRNG_SEEDABLE:
			return 1;
		case DREW_PRNG_MUST_SEED:
			return 0;
		case DREW_PRNG_INTSIZE:
			return sizeof(T);
		case DREW_PRNG_BLOCKING:
			return 0;
		default:
			return -DREW_ERR_INVALID;
	}
}

template<class T>
static int sp_algo_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	T *p;
	const T *q = reinterpret_cast<const T *>(oldctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p = new (newctx->ctx) T(*q);
	else
		p = new T(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

template<class T>
static int sp_algo_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy)
{
	T *p = reinterpret_cast<T *>(ctx->ctx);
	p->AddRandomData(key, len, entropy);
	return 0;
}

template<class T>
static int sp_algo_bytes(drew_prng_t *ctx, uint8_t *out, size_t len)
{
	T *p = reinterpret_cast<T *>(ctx->ctx);
	return p->GetBytes(out, len);
}

template<class T>
static int sp_algo_entropy(const drew_prng_t *ctx)
{
	const T *p =
		reinterpret_cast<const T *>(ctx->ctx);
	return p->GetEntropyAvailable();
}

template<class T>
static int sp_algo_test(void *, DrewLoader *)
{
	using namespace drew;

	return -DREW_ERR_NOT_IMPL;
}

extern "C" {

static int sp_hash_info(int op, void *p);
static int sp_hash_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *);
static int sp_hash_init(drew_prng_t *ctx, int flags, DrewLoader *,
		const drew_param_t *);
static int sp_hash_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags);
static int sp_hash_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy);
static int sp_hash_bytes(drew_prng_t *ctx, uint8_t *out, size_t len);
static int sp_hash_entropy(const drew_prng_t *ctx);
static int sp_hash_fini(drew_prng_t *ctx, int flags);
static int sp_hash_test(void *, DrewLoader *);

static int sp_ctr_info(int op, void *p);
static int sp_ctr_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *);
static int sp_ctr_init(drew_prng_t *ctx, int flags, DrewLoader *,
		const drew_param_t *);
static int sp_ctr_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags);
static int sp_ctr_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy);
static int sp_ctr_bytes(drew_prng_t *ctx, uint8_t *out, size_t len);
static int sp_ctr_entropy(const drew_prng_t *ctx);
static int sp_ctr_fini(drew_prng_t *ctx, int flags);
static int sp_ctr_test(void *, DrewLoader *);

static int sp_hmac_info(int op, void *p);
static int sp_hmac_info2(const drew_prng_t *, int op, drew_param_t *,
		const drew_param_t *);
static int sp_hmac_init(drew_prng_t *ctx, int flags, DrewLoader *,
		const drew_param_t *);
static int sp_hmac_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags);
static int sp_hmac_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy);
static int sp_hmac_bytes(drew_prng_t *ctx, uint8_t *out, size_t len);
static int sp_hmac_entropy(const drew_prng_t *ctx);
static int sp_hmac_fini(drew_prng_t *ctx, int flags);
static int sp_hmac_test(void *, DrewLoader *);

PLUGIN_FUNCTBL(sphash, sp_hash_info, sp_hash_info2, sp_hash_init, sp_hash_clone, sp_hash_fini, sp_hash_seed, sp_hash_bytes, sp_hash_entropy, sp_hash_test);

PLUGIN_FUNCTBL(spctr, sp_ctr_info, sp_ctr_info2, sp_ctr_init, sp_ctr_clone, sp_ctr_fini, sp_ctr_seed, sp_ctr_bytes, sp_ctr_entropy, sp_ctr_test);

PLUGIN_FUNCTBL(sphmac, sp_hmac_info, sp_hmac_info2, sp_hmac_init, sp_hmac_clone, sp_hmac_fini, sp_hmac_seed, sp_hmac_bytes, sp_hmac_entropy, sp_hmac_test);

static int sp_hash_info(int op, void *p)
{
	return sp_algo_info<drew::HashDRBG>(op, p);
}

static int sp_hash_info2(const drew_prng_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return sp_algo_info2<drew::CounterDRBG>(ctx, op, out, in);
}

static int sp_hash_init(drew_prng_t *ctx, int flags, DrewLoader *ldr,
		const drew_param_t *param)
{
	drew::HashDRBG *p;
	drew_hash_t hash;
	const char *names[] = {"SHA-512", "SHA-384", "SHA-256", "SHA-224", "SHA-1"};
	int res = 0;
	res = make_new(&hash, ldr, param, "digest", DREW_TYPE_HASH, names,
			DIM(names));
	if (res < 0)
		return res;
	if (flags & DREW_PRNG_FIXED)
		p = new (ctx->ctx) drew::HashDRBG(hash);
	else
		p = new drew::HashDRBG(hash);
	ctx->ctx = p;
	ctx->functbl = &sphashfunctbl;
	return 0;
}

static int sp_hash_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	return sp_algo_clone<drew::HashDRBG>(newctx, oldctx, flags);
}

static int sp_hash_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy)
{
	return sp_algo_seed<drew::HashDRBG>(ctx, key, len, entropy);
}

static int sp_hash_bytes(drew_prng_t *ctx, uint8_t *out, size_t len)
{
	return sp_algo_bytes<drew::HashDRBG>(ctx, out, len);
}

static int sp_hash_entropy(const drew_prng_t *ctx)
{
	return sp_algo_entropy<drew::HashDRBG>(ctx);
}

static int sp_hash_fini(drew_prng_t *ctx, int flags)
{
	drew::HashDRBG *p = reinterpret_cast<drew::HashDRBG *>(ctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p->~HashDRBG();
	else {
		delete p;
		ctx->ctx = NULL;
	}
	return 0;
}

static int sp_hash_test(void *p, DrewLoader *ldr)
{
	return sp_algo_test<drew::HashDRBG>(p, ldr);
}

static int sp_ctr_info(int op, void *p)
{
	return sp_algo_info<drew::CounterDRBG>(op, p);
}

static int sp_ctr_info2(const drew_prng_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return sp_algo_info2<drew::CounterDRBG>(ctx, op, out, in);
}


// This has to be at least as large as the key size plus the block size.
#define CTR_BUFFER_SIZE	512
static int sp_ctr_init(drew_prng_t *ctx, int flags, DrewLoader *ldr,
		const drew_param_t *param)
{
	drew::CounterDRBG *p;
	drew_mode_t ctr;
	drew_block_t block;
	size_t outlen, keylen;
	const char *blocks[] = {"AES256", "AES192", "AES128", "Rijndael", "DESede"};
	const char *modes[] = {"CTR", "Counter-BE", "Counter-LE"};
	int res = 0, tmp = 0, totallen;
	res = make_new(&block, ldr, param, "cipher", DREW_TYPE_BLOCK, blocks,
			DIM(blocks));
	if (res < 0)
		return res;
	res = make_new(&ctr, ldr, NULL, NULL, DREW_TYPE_MODE, modes,
			DIM(modes));
	if (res < 0)
		return res;
	ctr.functbl->init(&ctr, 0, ldr, param);
	block.functbl->init(&block, 0, ldr, param);
	outlen = block.functbl->info(DREW_BLOCK_BLKSIZE, 0);
	keylen = block.functbl->info(DREW_BLOCK_KEYSIZE, &tmp);
	totallen = outlen + keylen;
	if (totallen > CTR_BUFFER_SIZE)
		return -DREW_ERR_INVALID;
	if (flags & DREW_PRNG_FIXED)
		p = new (ctx->ctx) drew::CounterDRBG(ctr, block, outlen, keylen);
	else
		p = new drew::CounterDRBG(ctr, block, outlen, keylen);
	ctx->ctx = p;
	ctx->functbl = &spctrfunctbl;
	return 0;
}

static int sp_ctr_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	return sp_algo_clone<drew::CounterDRBG>(newctx, oldctx, flags);
}

static int sp_ctr_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy)
{
	return sp_algo_seed<drew::CounterDRBG>(ctx, key, len, entropy);
}

static int sp_ctr_bytes(drew_prng_t *ctx, uint8_t *out, size_t len)
{
	return sp_algo_bytes<drew::CounterDRBG>(ctx, out, len);
}

static int sp_ctr_entropy(const drew_prng_t *ctx)
{
	return sp_algo_entropy<drew::CounterDRBG>(ctx);
}

static int sp_ctr_fini(drew_prng_t *ctx, int flags)
{
	drew::CounterDRBG *p = reinterpret_cast<drew::CounterDRBG *>(ctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p->~CounterDRBG();
	else {
		delete p;
		ctx->ctx = NULL;
	}
	return 0;
}

static int sp_ctr_test(void *p, DrewLoader *ldr)
{
	return sp_algo_test<drew::CounterDRBG>(p, ldr);
}

static int sp_hmac_info(int op, void *p)
{
	return sp_algo_info<drew::HMACDRBG>(op, p);
}

static int sp_hmac_info2(const drew_prng_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return sp_algo_info2<drew::HMACDRBG>(ctx, op, out, in);
}

// This has to be at least as large as the digest size.
#define HMAC_BUFFER_SIZE	512
static int sp_hmac_init(drew_prng_t *ctx, int flags, DrewLoader *ldr,
		const drew_param_t *param)
{
	drew::HMACDRBG *p;
	drew_mac_t *hmac = new drew_mac_t;
	drew_hash_t *hash = new drew_hash_t;
	size_t outlen;
	drew_param_t p2;
	const char *names[] = {"SHA-512", "SHA-384", "SHA-256", "SHA-224", "SHA-1"};
	const char *macs[] = {"HMAC"};
	int res = 0;
	res = make_new(hash, ldr, param, "digest", DREW_TYPE_HASH, names,
			DIM(names));
	if (res < 0)
		return res;
	p2.name = "digest";
	p2.next = const_cast<drew_param_t *>(param);
	p2.param.value = hash;
	res = make_new(hmac, ldr, &p2, NULL, DREW_TYPE_MAC, macs, DIM(macs));
	if (res < 0)
		return res;
	outlen = hash->functbl->info(DREW_HASH_SIZE, 0);
	if (outlen > HMAC_BUFFER_SIZE)
		return -DREW_ERR_INVALID;
	if (flags & DREW_PRNG_FIXED)
		p = new (ctx->ctx) drew::HMACDRBG(hmac, outlen);
	else
		p = new drew::HMACDRBG(hmac, outlen);
	ctx->ctx = p;
	ctx->functbl = &spctrfunctbl;
	return 0;
}

static int sp_hmac_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags)
{
	return sp_algo_clone<drew::HMACDRBG>(newctx, oldctx, flags);
}

static int sp_hmac_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy)
{
	return sp_algo_seed<drew::HMACDRBG>(ctx, key, len, entropy);
}

static int sp_hmac_bytes(drew_prng_t *ctx, uint8_t *out, size_t len)
{
	return sp_algo_bytes<drew::HMACDRBG>(ctx, out, len);
}

static int sp_hmac_entropy(const drew_prng_t *ctx)
{
	return sp_algo_entropy<drew::HMACDRBG>(ctx);
}

static int sp_hmac_fini(drew_prng_t *ctx, int flags)
{
	drew::HMACDRBG *p = reinterpret_cast<drew::HMACDRBG *>(ctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p->~HMACDRBG();
	else {
		delete p;
		ctx->ctx = NULL;
	}
	return 0;
}

static int sp_hmac_test(void *p, DrewLoader *ldr)
{
	return sp_algo_test<drew::HMACDRBG>(p, ldr);
}

	PLUGIN_DATA_START()
	PLUGIN_DATA(sphash, "HashDRBG")
	PLUGIN_DATA(spctr, "CounterDRBG")
	PLUGIN_DATA(sphmac, "HMACDRBG")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(sp800_90)
}

drew::HashHelper::HashHelper(const drew_hash_t *h) :
	orighash(h), hash(new drew_hash_t)
{
	hash->ctx = 0;
	Reset();
}

drew::HashHelper::~HashHelper()
{
	if (hash->ctx) {
		hash->functbl->fini(hash, 0);
		hash->ctx = 0;
	}
	delete hash;
}

void drew::HashHelper::AddData(const uint8_t *data, size_t len)
{
	hash->functbl->update(hash, data, len);
}

void drew::HashHelper::GetDigest(uint8_t *data, size_t len)
{
	const size_t digsz = GetDigestLength();
	if (len == digsz) {
		hash->functbl->final(hash, data, digsz, 0);
		return;
	}
	uint8_t *buf = new uint8_t[digsz];
	hash->functbl->final(hash, buf, digsz, 0);
	memcpy(data, buf, std::min(digsz, len));
	memset(buf, 0, digsz);
	delete[] buf;
}

size_t drew::HashHelper::GetSeedLength() const
{
	const size_t blksz = GetBlockSize();
	// This calculation is always correct for the SHA-2 family of functions, but
	// not all hash functions.
	return blksz - 1 - (blksz / 8);
}

size_t drew::HashHelper::GetDigestLength() const
{
	return hash->functbl->info(DREW_HASH_SIZE, NULL);
}

size_t drew::HashHelper::GetBlockSize() const
{
	return hash->functbl->info(DREW_HASH_BLKSIZE, NULL);
}

void drew::HashHelper::Reset()
{
	if (hash->ctx) {
		hash->functbl->fini(hash, 0);
		hash->ctx = 0;
	}
	orighash->functbl->clone(hash, orighash, 0);
}

drew::DRBG::DRBG() : inited(false)
{
}

void drew::DRBG::Stir()
{
	this->Reseed(NULL, 0);
}

int drew::DRBG::Initialize()
{
	return AddRandomData(NULL, 0, 0);
}

int drew::DRBG::AddRandomData(const uint8_t *buf, size_t len, size_t entropy)
{
	if (inited)
		Reseed(buf, len);
	else {
		inited = true;
		Initialize(buf, len);
	}
	return 0;
}

void drew::DRBG::GeneratePersonalizationString(uint8_t *buf, size_t *len)
{
	Personalization data;
	const size_t finallen = std::min(sizeof(data), *len);
	data.pid = getpid();
	data.ppid = getppid();
	data.sid = getsid(0);
	data.uid = getuid();
	data.euid = geteuid();
	data.gid = getgid();
	data.egid = getegid();
#ifdef CLOCK_REALTIME
	clock_gettime(CLOCK_REALTIME, &data.rt);
#endif
#ifdef CLOCK_MONOTONIC
	clock_gettime(CLOCK_MONOTONIC, &data.mt);
#endif
#ifdef CLOCK_PROCESS_CPUTIME_ID
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &data.pt);
#endif
#ifdef CLOCK_THREAD_CPUTIME_ID
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &data.tt);
#endif
	memcpy(buf, &data, finallen);
	*len = finallen;
}

drew::HashDRBG::HashDRBG(const drew_hash_t &h)
{
	hash = new drew_hash_t(h);
	HashHelper hh(hash);
	digestlen = hh.GetDigestLength();
	seedlen = hh.GetSeedLength();
}

drew::HashDRBG::~HashDRBG()
{
	hash->functbl->fini(const_cast<drew_hash_t *>(hash), 0);
	delete hash;
}

void drew::HashDRBG::HashDF(const drew_hash_t *h, const uint8_t *in,
		size_t inlen, uint8_t *out, size_t outlen)
{
	HashHelper hh(h);
	const size_t len = (outlen + (digestlen - 1)) / digestlen;
	uint8_t *temp = new uint8_t[len*digestlen];
	uint8_t counter = 1;
	uint32_t outbits = outlen * 8;

	for (size_t i = 0, off = 0; i < len; i++, off += digestlen, counter++) {
		hh.AddData(&counter, sizeof(counter));
		hh.AddData(reinterpret_cast<const uint8_t *>(&outbits),
				sizeof(outbits));
		hh.AddData(in, inlen);
		hh.GetDigest(temp+off, digestlen);
		hh.Reset();
	}
	// FIXME: don't copy needlessly here.
	memcpy(out, temp, outlen);
	memset(temp, 0, len*digestlen);
	delete[] temp;
}

// This data passed to this function is treated as a nonce.
int drew::HashDRBG::Initialize(const uint8_t *data, size_t len)
{
	// Arbitrary constants.
	const size_t buflen = std::max(len + 128, (size_t)1024) + 1;
	uint8_t *buf = new uint8_t[buflen];
	int res = 0;
	DevURandom du;
	res = du.GetBytes(buf, seedlen);
	if (res < 0)
		return res;
	size_t off = seedlen;
	memcpy(buf+off, data, len);
	off += len;
	size_t perslen = buflen - off;
	GeneratePersonalizationString(buf+off, &perslen);
	off += perslen;
	HashDF(hash, buf, off, V, seedlen);
	buf[0] = 0;
	// Guaranteed big enough because seedlen < buflen.
	memcpy(buf+1, V, seedlen);
	HashDF(hash, buf, seedlen+1, C, seedlen);
	rc = 1;
	memset(buf, 0, buflen);
	delete[] buf;
	return 0;
}

int drew::HashDRBG::Reseed(const uint8_t *data, size_t len)
{
	const size_t buflen = 1 + sizeof(V) + seedlen + len;
	uint8_t *buf = new uint8_t[buflen];
	DevURandom du;
	int res = 0;
	buf[0] = 0x01;
	size_t off = 1;
	memcpy(buf+off, V, seedlen);
	off += seedlen;
	res = du.GetBytes(buf+off, seedlen);
	if (res < 0)
		return res;
	off += res;
	memcpy(buf+off, data, len);
	off += len;
	HashDF(hash, buf, off, V, seedlen);
	buf[0] = 0;
	memcpy(buf+1, V, seedlen);
	HashDF(hash, buf, seedlen+1, C, seedlen);
	rc = 1;
	memset(buf, 0, buflen);
	delete[] buf;
	return 0;
}

// This is horribly inefficient.
// FIXME: vectorize if possible.
inline static void AddArrays(uint8_t *buf, size_t len, const uint8_t *input)
{
	bool carry = 0;
	for (ssize_t i = len - 1; i >= 0; i--) {
		uint16_t val = buf[i];
		buf[i] = val += input[i] + carry;
		carry = (val >> 8);
	}
}

int drew::HashDRBG::GetBytes(uint8_t *data, size_t len)
{
	HashHelper hh(hash);
	uint8_t b = 0x03;
	int res = 0;

	if (!inited)
		res = this->DRBG::Initialize();
	else if (rc >= reseed_interval)
		this->Stir();

	if (res < 0)
		return res;

	HashGen(data, len);

	hh.AddData(&b, 1);
	hh.AddData(V, seedlen);
	uint8_t *buf = new uint8_t[seedlen];
	memset(buf, 0, seedlen);
	hh.GetDigest(buf+(seedlen-digestlen), seedlen);
	AddArrays(V, seedlen, buf);
	AddArrays(V, seedlen, C);
	memset(buf, 0, seedlen);
	BigEndian::Copy(buf+(seedlen-sizeof(rc)), &rc, sizeof(rc));
	AddArrays(V, seedlen, buf);
	rc++;
	memset(buf, 0, seedlen);
	delete[] buf;
	return len;
}

void drew::HashDRBG::HashGen(uint8_t *buf, size_t len)
{
	HashHelper hh(hash);
	const size_t m = (len + (digestlen - 1)) / digestlen;
	uint8_t *data = new uint8_t[seedlen];
	uint8_t *one = new uint8_t[seedlen];

	memset(one, 0, seedlen);
	one[seedlen-1] = 0x01;
	memcpy(data, V, seedlen);

	for (size_t i = 0, j = 0; i < m; i++, j += digestlen) {
		hh.AddData(data, seedlen);
		hh.GetDigest(buf+j, std::min(seedlen, len-j));
		hh.Reset();
		AddArrays(data, seedlen, one);
	}
	// No need to clear one, since it's not cryptographically sensitive.
	memset(data, 0, seedlen);
	delete[] data;
	delete[] one;
}

drew::CounterDRBG::CounterDRBG(const drew_mode_t &c, const drew_block_t &b,
		size_t outl, size_t keyl)
{
	ctr = new drew_mode_t(c);
	block = new drew_block_t(b);
	ctr->functbl->setblock(ctr, block);
	outlen = outl;
	keylen = keyl;
	seedlen = outlen + keylen;
}

drew::CounterDRBG::~CounterDRBG()
{
	ctr->functbl->fini(ctr, 0);
	block->functbl->fini(block, 0);
	delete block;
	delete ctr;
}

// Provided needs to be of size seedlen.
void drew::CounterDRBG::Update(const uint8_t *provided)
{
	uint8_t buf[CTR_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	ctr->functbl->encryptfast(ctr, buf, buf, seedlen);
	XorBuffers(buf, buf, provided, seedlen);
	block->functbl->setkey(block, buf, keylen, 0);
	ctr->functbl->setblock(ctr, block);
	ctr->functbl->setiv(ctr, buf+keylen, outlen);
	memset(buf, 0, sizeof(buf));
}

// This data passed to this function is treated as a nonce.
int drew::CounterDRBG::Initialize(const uint8_t *data, size_t len)
{
	// We choose to deviate from the specification here and allow the seed
	// material to exceed seedlen bytes.  At least seedlen/2 bytes must be from
	// DevURandom (or equivalent) and we use the full personalization string.
	// After that, we use as much of the provided nonce as possible, making up
	// the rest of it with DevURandom bits.
	uint8_t buf[CTR_BUFFER_SIZE];
	uint8_t zero[CTR_BUFFER_SIZE];
	const size_t half = seedlen / 2;
	const size_t noncelen = std::min(len, sizeof(buf) -
			(half + sizeof(Personalization)));
	size_t dulen = sizeof(buf) - noncelen - sizeof(Personalization);
	size_t nbytes = sizeof(Personalization);
	int res = 0;
	DevURandom du;

	res = du.GetBytes(buf, dulen);
	if (res < 0)
		return res;
	else if (res)
		dulen = res;
	memcpy(buf+dulen, data, noncelen);
	GeneratePersonalizationString(buf+dulen+noncelen, &nbytes);

	BlockCipherDF(block, buf, sizeof(buf), buf, seedlen);

	memset(zero, 0, sizeof(zero));
	block->functbl->setkey(block, zero, keylen, 0);
	ctr->functbl->setblock(ctr, block);
	ctr->functbl->setiv(ctr, zero, outlen);
	Update(buf);
	rc = 1;
	memset(buf, 0, sizeof(buf));
	// No need to set zero to 0, because it's, uh, already zero.
	return 0;
}

void drew::CounterDRBG::BlockCipherDF(const drew_block_t *bt, const uint8_t *in,
		uint32_t l, uint8_t *out, uint32_t n)
{
	static const uint8_t K[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	drew_block_t *b = new drew_block_t;
	size_t off;
	size_t slen = RoundUpToMultiple(sizeof(l) + sizeof(n) + 1 + l, outlen);
	size_t biglen = slen + outlen;
	uint8_t *bigbuf = new uint8_t[biglen];
	uint8_t *buf = bigbuf + outlen;
	uint8_t *iv = bigbuf;

	// Copy the data and pad it.
	memset(bigbuf, 0, biglen);
	memcpy(buf, &l, 4);
	memcpy(buf+4, &n, 4);
	off = 8;
	memcpy(buf+off, in, l);
	off += l;
	buf[off] = 0x80;

	b->functbl = bt->functbl;
	b->functbl->clone(b, bt, 0);
	b->functbl->setkey(b, K, keylen, 0);

	size_t templen = RoundUpToMultiple(std::max<size_t>(seedlen, n), outlen);
	uint8_t *temp = new uint8_t[templen], *tmp = temp;
	for (uint32_t i = 0; i < DivideAndRoundUp(seedlen, outlen);
			i++, tmp += outlen) {
		memcpy(iv, &i, sizeof(i));
		BCC(b, bigbuf, biglen, tmp);
	}

	b->functbl->setkey(b, temp, keylen, 0);
	uint8_t *from = temp + keylen, *to = temp;
	for (uint32_t i = 0; i < n; i += outlen, from = to, to += outlen)
		b->functbl->encrypt(b, to, from);
	memcpy(out, temp, n);

	b->functbl->fini(b, 0);
	memset(bigbuf, 0, biglen);
	memset(temp, 0, templen);
	delete b;
	delete[] bigbuf;
	delete[] temp;
}

void drew::CounterDRBG::BCC(const drew_block_t *b, const uint8_t *data,
		size_t len, uint8_t *out)
{
	memset(out, 0, outlen);
	const uint8_t *p = data;
	for (size_t i = 0; i < len / outlen; i++, p += outlen) {
		XorBuffers(out, out, p, outlen);
		b->functbl->encrypt(b, out, out);
	}
}

int drew::CounterDRBG::Reseed(const uint8_t *data, size_t len)
{
	int res = 0;
	uint8_t buf[CTR_BUFFER_SIZE];
	DevURandom du;
	size_t dubytes = sizeof(buf) - std::min(len, sizeof(buf) / 2);

	res = du.GetBytes(buf, dubytes);
	if (res < 0)
		return res;
	else if (res)
		dubytes = res;
	memcpy(buf+dubytes, data, sizeof(buf) - dubytes);

	BlockCipherDF(block, buf, sizeof(buf), buf, seedlen);
	Update(buf);
	rc = 1;

	memset(buf, 0, sizeof(buf));
	return 0;
}

int drew::CounterDRBG::GetBytes(uint8_t *data, size_t len)
{
	int res = 0;
	uint8_t buf[CTR_BUFFER_SIZE];
	if (!inited)
		res = this->DRBG::Initialize();
	else if (rc >= reseed_interval)
		this->Stir();

	if (res < 0)
		return res;

	memset(buf, 0, sizeof(buf));
	memcpy(buf, data, std::min(sizeof(buf), len));
	Update(buf);

	memset(data, 0, len);
	ctr->functbl->encrypt(ctr, data, data, len);
	Update(buf);
	rc++;
	return len;
}

drew::HMACDRBG::HMACDRBG(drew_mac_t *m, size_t outl)
{
	hmac = m;
	outlen = outl;
	V = new uint8_t[outlen];
}

drew::HMACDRBG::~HMACDRBG()
{
	hmac->functbl->fini(hmac, 0);
	memset(V, 0, outlen);
	delete[] V;
	delete hmac;
}

void drew::HMACDRBG::Update(const Buffer *b, size_t nbufs)
{
	size_t totallen = 0;
	const uint8_t zero = 0x00, one = 0x01;
	uint8_t buf[HMAC_BUFFER_SIZE];

	hmac->functbl->reset(hmac);
	hmac->functbl->update(hmac, V, outlen);
	hmac->functbl->update(hmac, &zero, 1);
	for (size_t i = 0; i < nbufs; totallen += b[i].len, i++)
		hmac->functbl->update(hmac, b[i].data, b[i].len);
	hmac->functbl->final(hmac, buf, 0);

	hmac->functbl->reset(hmac);
	hmac->functbl->setkey(hmac, buf, outlen);
	hmac->functbl->update(hmac, V, outlen);
	hmac->functbl->final(hmac, V, 0);

	if (totallen) {
		hmac->functbl->reset(hmac);
		hmac->functbl->update(hmac, V, outlen);
		hmac->functbl->update(hmac, &one, 1);
		for (size_t i = 0; i < nbufs; i++)
			hmac->functbl->update(hmac, b[i].data, b[i].len);
		hmac->functbl->final(hmac, buf, 0);

		hmac->functbl->reset(hmac);
		hmac->functbl->setkey(hmac, buf, outlen);
		hmac->functbl->update(hmac, V, outlen);
		hmac->functbl->final(hmac, V, 0);
	}
	hmac->functbl->reset(hmac);

	memset(buf, 0, sizeof(buf));
}

// This data passed to this function is treated as a nonce.
int drew::HMACDRBG::Initialize(const uint8_t *data, size_t len)
{
	uint8_t buf[HMAC_BUFFER_SIZE], ps[sizeof(Personalization)];
	uint8_t zero[HMAC_BUFFER_SIZE];
	size_t nbytes = sizeof(Personalization);
	int res = 0;
	DevURandom du;
	Buffer b[3];

	res = du.GetBytes(buf, outlen);
	if (res < 0)
		return res;
	GeneratePersonalizationString(ps, &nbytes);
	b[0].data = buf;
	b[0].len = res;
	b[1].data = data;
	b[1].len = len;
	b[2].data = ps;
	b[2].len = nbytes;

	memset(zero, 0, outlen);
	hmac->functbl->reset(hmac);
	hmac->functbl->setkey(hmac, zero, outlen);
	memset(V, 1, outlen);

	Update(b, DIM(b));

	rc = 1;
	memset(buf, 0, sizeof(buf));
	return 0;
}

int drew::HMACDRBG::Reseed(const uint8_t *data, size_t len)
{
	uint8_t buf[HMAC_BUFFER_SIZE];
	DevURandom du;
	int res = 0;
	Buffer b[2];

	res = du.GetBytes(buf, outlen);
	if (res < 0)
		return res;
	b[0].data = buf;
	b[0].len = res;
	b[1].data = data;
	b[1].len = len;

	Update(b, DIM(b));
	rc = 1;

	memset(buf, 0, sizeof(buf));
	return 0;
}

int drew::HMACDRBG::GetBytes(uint8_t *data, size_t len)
{
	Buffer b;
	int res = 0;
	if (!inited)
		res = this->DRBG::Initialize();
	else if (rc >= reseed_interval)
		this->Stir();

	if (res < 0)
		return res;

	b.data = data;
	b.len = len;
	if (len)
		Update(&b, 1);

	for (size_t i = 0; i < len; i += outlen) {
		hmac->functbl->reset(hmac);
		hmac->functbl->update(hmac, V, outlen);
		hmac->functbl->final(hmac, V, 0);
		if (i + outlen < len)
			memcpy(data+i, V, outlen);
		else
			memcpy(data+i, V, len-i);
	}
	Update(&b, 1);
	rc++;
	return len;
}
UNHIDE()
