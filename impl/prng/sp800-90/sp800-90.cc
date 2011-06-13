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

template<class T>
static int make_new(T *ctx, const drew_loader_t *ldr, const drew_param_t *param,
		const char *paramname, int type, const char *algonames[], size_t nalgos)
{
	for (const drew_param_t *p = param; p; p = p->next) {
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

extern "C" {

static int sp_hash_info(int op, void *p);
static int sp_hash_init(drew_prng_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int sp_hash_clone(drew_prng_t *newctx, const drew_prng_t *oldctx, int flags);
static int sp_hash_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy);
static int sp_hash_bytes(drew_prng_t *ctx, uint8_t *out, size_t len);
static int sp_hash_entropy(const drew_prng_t *ctx);
static int sp_hash_fini(drew_prng_t *ctx, int flags);
static int sp_hash_test(void *, const drew_loader_t *);

PLUGIN_FUNCTBL(sphash, sp_hash_info, sp_hash_init, sp_hash_clone, sp_hash_fini, sp_hash_seed, sp_hash_bytes, sp_hash_entropy, sp_hash_test);

static int sp_hash_info(int op, void *p)
{
	switch (op) {
		case DREW_PRNG_VERSION:
			return 2;
		case DREW_PRNG_BLKSIZE:
			return 256;
		case DREW_PRNG_SEEDABLE:
			return 1;
		case DREW_PRNG_MUST_SEED:
			return 0;
		case DREW_PRNG_INTSIZE:
			return sizeof(drew::HashDRBG);
		case DREW_PRNG_BLOCKING:
			return 0;
		default:
			return -EINVAL;
	}
}

static int sp_hash_init(drew_prng_t *ctx, int flags, const drew_loader_t *ldr,
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
	using namespace drew;
	HashDRBG *p;
	const HashDRBG *q = reinterpret_cast<const HashDRBG *>(oldctx->ctx);
	if (flags & DREW_PRNG_FIXED)
		p = new (newctx->ctx) HashDRBG(*q);
	else
		p = new HashDRBG(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int sp_hash_seed(drew_prng_t *ctx, const uint8_t *key, size_t len,
		size_t entropy)
{
	drew::HashDRBG *p = reinterpret_cast<drew::HashDRBG *>(ctx->ctx);
	p->AddRandomData(key, len, entropy);
	return 0;
}

static int sp_hash_bytes(drew_prng_t *ctx, uint8_t *out, size_t len)
{
	drew::HashDRBG *p = reinterpret_cast<drew::HashDRBG *>(ctx->ctx);
	p->GetBytes(out, len);
	return 0;
}

static int sp_hash_entropy(const drew_prng_t *ctx)
{
	const drew::HashDRBG *p =
		reinterpret_cast<const drew::HashDRBG *>(ctx->ctx);
	return p->GetEntropyAvailable();
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

static int sp_hash_test(void *, const drew_loader_t *)
{
	using namespace drew;

	return -DREW_ERR_NOT_IMPL;
}

	PLUGIN_DATA_START()
	PLUGIN_DATA(sphash, "HashDRBG")
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
		hash->functbl->final(hash, data, 0);
		return;
	}
	uint8_t *buf = new uint8_t[digsz];
	hash->functbl->final(hash, buf, 0);
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

int drew::DRBG::AddRandomData(const uint8_t *buf, size_t len, size_t entropy)
{
	if (inited)
		Reseed(buf, len);
	else
		Initialize(buf, len);
	return 0;
}

void drew::DRBG::GeneratePersonalizationString(uint8_t *buf, size_t *len)
{
	struct {
		pid_t pid, ppid, sid;
		uid_t uid, euid;
		gid_t gid, egid;
		struct timespec rt, mt, pt, tt;
	} data;
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
}

drew::HashDRBG::~HashDRBG()
{
	delete hash;
}

void drew::HashDRBG::HashDF(const drew_hash_t *h, const uint8_t *in,
		size_t inlen, uint8_t *out, size_t outlen)
{
	HashHelper hh(h);
	const size_t digestsz = hh.GetDigestLength();
	const size_t len = (outlen + (digestsz - 1)) / digestsz;
	uint8_t *temp = new uint8_t[len*digestsz];
	uint8_t counter = 1;
	uint32_t outbits = outlen * 8;
	
	for (size_t i = 0, off = 0; i < len; i++, off += digestsz) {
		hh.AddData(&counter, sizeof(counter));
		hh.AddData(reinterpret_cast<const uint8_t *>(&outbits),
				sizeof(outbits));
		hh.AddData(in, inlen);
		hh.GetDigest(temp+off, digestsz);
		hh.Reset();
	}
	// FIXME: don't copy needlessly here.
	memcpy(out, temp, outlen);
	memset(temp, 0, len*digestsz);
	delete[] temp;
}

size_t drew::HashDRBG::GetSeedLength() const
{
	return HashHelper(hash).GetSeedLength();
}

// This data passed to this function is treated as a nonce.
void drew::HashDRBG::Initialize(const uint8_t *data, size_t len)
{
	// Arbitrary constants.
	const size_t buflen = std::max(len + 128, (size_t)1024) + 1;
	const size_t seedlen = GetSeedLength();
	uint8_t *buf = new uint8_t[buflen];
	DevURandom du;
	du.GetBytes(buf, seedlen);
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
}

void drew::HashDRBG::Reseed(const uint8_t *data, size_t len)
{
	const size_t seedlen = GetSeedLength();
	const size_t buflen = 1 + sizeof(V) + seedlen + len;
	uint8_t *buf = new uint8_t[buflen];
	DevURandom du;
	buf[0] = 0x01;
	size_t off = 1;
	memcpy(buf+off, V, seedlen);
	off += seedlen;
	du.GetBytes(buf+off, seedlen);
	off += seedlen;
	memcpy(buf+off, data, len);
	off += len;
	HashDF(hash, buf, off, V, seedlen);
	buf[0] = 0;
	memcpy(buf+1, V, seedlen);
	HashDF(hash, buf, seedlen+1, C, seedlen);
	rc = 1;
	memset(buf, 0, buflen);
	delete[] buf;
}

// This is horribly inefficient.
// FIXME: vectorize if possible.
inline static void AddArrays(uint8_t *buf, size_t len, const uint8_t *input)
{
	bool carry = 0;
	for (size_t i = 0; i < len; i++) {
		uint8_t bufb = buf[i], inputb = input[i];
		buf[i] += input[i] + carry;
		carry = ((buf[i] < bufb) || (buf[i] < inputb));
	}
}

void drew::HashDRBG::GetBytes(uint8_t *data, size_t len)
{
	HashHelper hh(hash);
	uint8_t b = 0x03;
	const size_t seedlen = hh.GetSeedLength();
	const size_t digestlen = hh.GetDigestLength();
	// FIXME: test rc against the reseed interval.
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

}

void drew::HashDRBG::HashGen(uint8_t *buf, size_t len)
{
	HashHelper hh(hash);
	const size_t seedlen = hh.GetSeedLength();
	const size_t digestsize = hh.GetDigestLength();
	const size_t m = (len + (digestsize - 1)) / digestsize;
	uint8_t *data = new uint8_t[seedlen];
	uint8_t *one = new uint8_t[seedlen];

	memset(one, 0, seedlen);
	one[seedlen-1] = 0x01;
	memcpy(data, V, seedlen);

	for (size_t i = 0, j = 0; i < m; i++, j += digestsize) {
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
