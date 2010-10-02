#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include "camellia.hh"
#include "block-plugin.hh"

extern "C" {

static const int camelliakeysz[] =
{
	16, 24, 32
};

static void str2bytes(uint8_t *bytes, const char *s, size_t len = 0)
{
	if (!len)
		len = strlen(s);

	unsigned x;
	for (size_t i = 0; i < (len / 2); i++) {
		sscanf(s+(i*2), "%02x", &x);
		bytes[i] = x;
	}
}


static int camellia128_test(void)
{
	uint8_t key[16], pt[16], ct[16];
	uint8_t final[16], buf[16];

	memset(key, 0, sizeof(key));
	memset(pt, 0, sizeof(pt));

	str2bytes(final, "5d9d4eeffa9151575524f115815a12e0");
	for (size_t i = 0; i < 49; i++) {
		drew::Camellia ctx;
		ctx.SetKey(key, sizeof(key));
		ctx.Encrypt(ct, pt);
		ctx.Decrypt(buf, ct);

		if (memcmp(buf, pt, sizeof(pt)))
			return 1;
		memcpy(key, pt, sizeof(key));
		memcpy(pt, ct, sizeof(pt));
	}
	return !!memcmp(final, pt, sizeof(pt)) << 1;
}

static int camelliatest(void *, drew_loader_t *)
{
	int res = 0;

	res |= camellia128_test();

	return res;
}

}

extern "C" {
	PLUGIN_STRUCTURE(camellia, drew::Camellia, Camellia)
	PLUGIN_DATA_START()
	PLUGIN_DATA(camellia, "Camellia")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE()
}

typedef drew::Camellia::endian_t E;

// Note that this function does not handle n greater than 63.  However, if you
// switch x and y and subtract 64 from n, it will work just fine.
inline void rolpair(uint64_t &a, uint64_t &b, uint64_t x, uint64_t y,
		unsigned n)
{
	a = (x << n) | (y >> (64-n));
	b = (y << n) | (x >> (64-n));
}

inline uint32_t rol32(uint32_t x, unsigned n)
{
	return (x << n) | (x >> (32-n));
}

drew::Camellia::Camellia()
{
}

// Number of bits in a uint64_t.
#define NBITS (64)
void drew::Camellia::SetKey(const uint8_t *key, size_t sz)
{
	uint64_t ko[4];
	
	E::Copy(ko, key, sizeof(sz));
	if (sz == 16)
		ko[2] = ko[3] = 0;
	else if (sz == 24)
		ko[3] = ~ko[2];

	uint64_t d1, d2;
	d1 = ko[0] ^ ko[2];
	d2 = ko[1] ^ ko[3];
	d2 ^= f(d1, 0xa09e667f3bcc908b);
	d1 ^= f(d2, 0xb67ae8584caa73b2);
	d1 ^= ko[0];
	d2 ^= ko[1];
	d2 ^= f(d1, 0xc6ef372fe94f82be);
	d1 ^= f(d2, 0x54ff53a5f1d36f1c);
	uint64_t ka[2];
	ka[0] = d1;
	ka[1] = d2;
	d1 ^= ko[2];
	d2 ^= ko[3];
	d2 ^= f(d1, 0x10e527fade682d1d);
	d1 ^= f(d2, 0xb05688c2b3e6c1fd);
	uint64_t kb[2];
	kb[0] = d1;
	kb[1] = d2;
	uint64_t dummy;

	kw[0] = ko[0];
	kw[1] = ko[1];
	ku[0] = ka[0];
	ku[1] = ka[1];
	rolpair(ku[2], ku[3], ko[0], ko[1], 15);
	rolpair(ku[4], ku[5], ka[0], ka[1], 15);
	rolpair(kl[0], kl[1], ka[0], ka[1], 30);
	rolpair(ku[6], ku[7], ko[0], ko[1], 45);
	rolpair(ku[8], dummy, ka[0], ka[1], 45);
	rolpair(dummy, ku[9], ko[0], ko[1], 60);
	rolpair(ku[10], ku[11], ka[0], ka[1], 60);
	rolpair(kl[2], kl[3], ko[1], ko[0], 77-NBITS);
	rolpair(ku[12], ku[13], ko[1], ko[0], 94-NBITS);
	rolpair(ku[14], ku[15], ka[1], ka[0], 94-NBITS);
	rolpair(ku[16], ku[17], ko[1], ko[0], 111-NBITS);
	rolpair(kw[2], kw[3], ka[1], ka[0], 111-NBITS);
}

inline uint64_t drew::Camellia::f(uint64_t x, uint64_t k)
{
	return spfunc(x ^ k);
}

inline uint64_t drew::Camellia::fl(uint64_t x, uint64_t k)
{
	uint32_t xl = (x >> 32), xr = x, kl = (k >> 32), kr = k;

	uint32_t yr = rol32(xl & kl, 1) ^ xr;
	uint32_t yl = (yr | kr) ^ xl;

	return (((uint64_t)yl) << 32) | yr;
}

inline uint64_t drew::Camellia::flinv(uint64_t y, uint64_t k)
{
	uint32_t yl = (y >> 32), yr = y, kl = (k >> 32), kr = k;

	uint32_t xl = (yr | kr) ^ yl;
	uint32_t xr = rol32(xl & kl, 1) ^ yr;

	return (((uint64_t)xl) << 32) | xr;
}

#define SP(n) sp[n][E::GetByte(x, (7 - (n)))]

inline uint64_t drew::Camellia::spfunc(uint64_t x)
{
	return SP(0) ^ SP(1) ^ SP(2) ^ SP(3) ^ SP(4) ^ SP(5) ^ SP(6) ^ SP(7);
}

#define E128_ROUND2(x, y, n) do { \
	y ^= f(x, ku[n]); x ^= f(y, ku[n+1]); \
} while(0)
#define D128_ROUND2(x, y, n) do { \
	y ^= f(x, ku[n+1]); x ^= f(y, ku[n]); \
} while(0)
void drew::Camellia::Encrypt(uint8_t *out, const uint8_t *in)
{
	uint64_t d[2];
	uint64_t &y = d[0], &x = d[1];

	endian_t::Copy(d, in, sizeof(data));

	x ^= kw[0];
	y ^= kw[1];
	E128_ROUND2(x, y,  0);
	E128_ROUND2(x, y,  2);
	E128_ROUND2(x, y,  4);
	x = fl(x, kl[0]);
	y = flinv(y, kl[1]);
	E128_ROUND2(x, y,  6);
	E128_ROUND2(x, y,  8);
	E128_ROUND2(x, y, 10);
	x = fl(x, kl[2]);
	y = flinv(y, kl[3]);
	E128_ROUND2(x, y, 12);
	E128_ROUND2(x, y, 14);
	E128_ROUND2(x, y, 16);
	x ^= kw[2];
	y ^= kw[3];

	endian_t::Copy(out, d, sizeof(data));
}

void drew::Camellia::Decrypt(uint8_t *out, const uint8_t *in)
{
	uint64_t d[2];
	uint64_t &y = d[0], &x = d[1];

	endian_t::Copy(d, in, sizeof(data));

	x ^= kw[2];
	y ^= kw[3];
	E128_ROUND2(x, y, 16);
	E128_ROUND2(x, y, 14);
	E128_ROUND2(x, y, 12);
	x = fl(x, kl[3]);
	y = flinv(y, kl[2]);
	E128_ROUND2(x, y, 10);
	E128_ROUND2(x, y,  8);
	E128_ROUND2(x, y,  6);
	x = fl(x, kl[1]);
	y = flinv(y, kl[0]);
	E128_ROUND2(x, y,  4);
	E128_ROUND2(x, y,  2);
	E128_ROUND2(x, y,  0);
	x ^= kw[0];
	y ^= kw[1];

	endian_t::Copy(out, d, sizeof(data));
}

#include "tables.cc"
