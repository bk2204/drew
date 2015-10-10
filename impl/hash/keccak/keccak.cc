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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "keccak.hh"
#include "testcase.hh"
#include "hash-plugin.hh"

HIDE()
template<class T>
static int keccak_test(void *, const drew_loader_t *)
{
	int res = 0;

	using namespace drew;
	typedef VariableSizedHashTestCase<T, 224/8> TestCase224;
	typedef VariableSizedHashTestCase<T, 256/8> TestCase256;
	typedef VariableSizedHashTestCase<T, 384/8> TestCase384;
	typedef VariableSizedHashTestCase<T, 512/8> TestCase512;

	static const uint8_t test[] = {
		0x83, 0xaf, 0x34, 0x27, 0x9c, 0xcb, 0x54, 0x30,
		0xfe, 0xbe, 0xc0, 0x7a, 0x81, 0x95, 0x0d, 0x30,
		0xf4, 0xb6, 0x6f, 0x48, 0x48, 0x26, 0xaf, 0xee,
		0x74, 0x56, 0xf0, 0x07, 0x1a, 0x51, 0xe1, 0xbb,
		0xc5, 0x55, 0x70, 0xb5, 0xcc, 0x7e, 0xc6, 0xf9,
		0x30, 0x9c, 0x17, 0xbf, 0x5b, 0xef, 0xdd, 0x7c,
		0x6b, 0xa6, 0xe9, 0x68, 0xcf, 0x21, 0x8a, 0x2b,
		0x34, 0xbd, 0x5c, 0xf9, 0x27, 0xab, 0x84, 0x6e,
		0x38, 0xa4, 0x0b, 0xbd, 0x81, 0x75, 0x9e, 0x9e,
		0x33, 0x38, 0x10, 0x16, 0xa7, 0x55, 0xf6, 0x99,
		0xdf, 0x35, 0xd6, 0x60, 0x00, 0x7b, 0x5e, 0xad,
		0xf2, 0x92, 0xfe, 0xef, 0xb7, 0x35, 0x20, 0x7e,
		0xbf, 0x70, 0xb5, 0xbd, 0x17, 0x83, 0x4f, 0x7b,
		0xfa, 0x0e, 0x16, 0xcb, 0x21, 0x9a, 0xd4, 0xaf,
		0x52, 0x4a, 0xb1, 0xea, 0x37, 0x33, 0x4a, 0xa6,
		0x64, 0x35, 0xe5, 0xd3, 0x97, 0xfc, 0x0a, 0x06,
		0x5c, 0x41, 0x1e, 0xbb, 0xce, 0x32, 0xc2, 0x40,
		0xb9, 0x04, 0x76, 0xd3, 0x07, 0xce, 0x80, 0x2e,
		0xc8, 0x2c, 0x1c, 0x49, 0xbc, 0x1b, 0xec, 0x48,
		0xc0, 0x67, 0x5e, 0xc2, 0xa6, 0xc6, 0xf3, 0xed,
		0x3e, 0x5b, 0x74, 0x1d, 0x13, 0x43, 0x70, 0x95,
		0x70, 0x7c, 0x56, 0x5e, 0x10, 0xd8, 0xa2, 0x0b,
		0x8c, 0x20, 0x46, 0x8f, 0xf9, 0x51, 0x4f, 0xcf,
		0x31, 0xb4, 0x24, 0x9c, 0xd8, 0x2d, 0xce, 0xe5,
		0x8c, 0x0a, 0x2a, 0xf5, 0x38, 0xb2, 0x91, 0xa8,
		0x7e, 0x33, 0x90, 0xd7, 0x37, 0x19, 0x1a, 0x07,
		0x48, 0x4a, 0x5d, 0x3f, 0x3f, 0xb8, 0xc8, 0xf1,
		0x5c, 0xe0, 0x56, 0xe5, 0xe5, 0xf8, 0xfe, 0xbe,
		0x5e, 0x1f, 0xb5, 0x9d, 0x67, 0x40, 0x98, 0x0a,
		0xa0, 0x6c, 0xa8, 0xa0, 0xc2, 0x0f, 0x57, 0x12,
		0xb4, 0xcd, 0xe5, 0xd0, 0x32, 0xe9, 0x2a, 0xb8,
		0x9f, 0x0a, 0xe1
	};

	res |= !TestCase224(test, sizeof(test), 1).Test("ecde4d6eb0cf28010b45d0d310e7d05f08b80afc44b8a359be7e1923");
	res <<= 1;
	res |= !TestCase224("", 0).Test("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd");
	res <<= 1;
	res |= !TestCase256("", 0).Test("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
	res <<= 1;
	res |= !TestCase384("", 0).Test("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff");
	res <<= 1;
	res |= !TestCase512("", 0).Test("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e");

	return res;
}

static int keccak_get_digest_size(const drew_param_t *param, bool unlimited)
{
	size_t digestsizeval = 0, result = 0;

	for (const drew_param_t *p = param; p; p = p->next) {
		if (!p->name)
			continue;
		// This is in bytes.
		if (!digestsizeval && !strcmp(p->name, "digestSize"))
			digestsizeval = p->param.number;
	}
	if (digestsizeval)
		result = digestsizeval;
	if (!result)
		return -DREW_ERR_MORE_INFO;
	if (!unlimited && result > (512/8))
		return -DREW_ERR_INVALID;
	return result;
}

template<class T>
static int keccak_info(int op, void *p, bool unlimited = false)
{
	using namespace drew;
	const drew_param_t *param = reinterpret_cast<const drew_param_t *>(p);
	const drew_hash_t *ctx = reinterpret_cast<const drew_hash_t *>(p);
	switch (op) {
		case DREW_HASH_VERSION:
			return 3;
		case DREW_HASH_SIZE:
			return keccak_get_digest_size(param, unlimited);
		case DREW_HASH_BLKSIZE:
			if (p)
				return ((const T *)ctx->ctx)->GetBlockSize();
			return -DREW_ERR_MORE_INFO;
		case DREW_HASH_BUFSIZE:
			return 1600/8;
		case DREW_HASH_INTSIZE:
			return sizeof(T);
		case DREW_HASH_ENDIAN:
			return T::endian_t::GetEndianness();
		default:
			return -DREW_ERR_INVALID;
	}
}

static const int hash_sizes[] = {
	224/8, 256/8, 384/8, 512/8
};

static const int block_sizes[] = {
	224/8, 256/8, 384/8, 512/8
};

static const int buffer_sizes[] = {
	5*5*(64/8)
};

template<class T>
static int keccak_info2(const drew_hash_t *ctxt, int op, drew_param_t *outp,
		const drew_param_t *inp, bool unlimited = false)
{
	using namespace drew;
	switch (op) {
		case DREW_HASH_VERSION:
			return 3;
		case DREW_HASH_SIZE_LIST:
			if (unlimited)
				return -DREW_ERR_UNLIMITED;
			for (drew_param_t *p = outp; p; p = p->next)
				if (!strcmp(p->name, "digestSize")) {
					p->param.array.ptr = (void *)hash_sizes;
					p->param.array.len = DIM(hash_sizes);
				}
			return 0;
		case DREW_HASH_BLKSIZE_LIST:
			for (drew_param_t *p = outp; p; p = p->next)
				if (!strcmp(p->name, "blockSize")) {
					p->param.array.ptr = (void *)block_sizes;
					p->param.array.len = DIM(block_sizes);
				}
			return 0;
		case DREW_HASH_BUFSIZE_LIST:
			for (drew_param_t *p = outp; p; p = p->next)
				if (!strcmp(p->name, "bufferSize")) {
					p->param.array.ptr = (void *)buffer_sizes;
					p->param.array.len = DIM(buffer_sizes);
				}
			return 0;
		case DREW_HASH_SIZE_CTX:
			if (ctxt && ctxt->ctx) {
				const T *ctx = (const T *)ctxt->ctx;
				return ctx->GetBlockSize();
			}
			return -DREW_ERR_MORE_INFO;
		case DREW_HASH_BLKSIZE_CTX:
			if (ctxt && ctxt->ctx) {
				const T *ctx = (const T *)ctxt->ctx;
				return ctx->GetBlockSize();
			}
			return -DREW_ERR_MORE_INFO;
		case DREW_HASH_BUFSIZE_CTX:
			return 1600/8;
		case DREW_HASH_INTSIZE:
			return sizeof(T);
		case DREW_HASH_ENDIAN:
			return T::endian_t::GetEndianness();
		default:
			return -DREW_ERR_INVALID;
	}
}

template<class T>
static int keccak_init(drew_hash_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *param, const drew_hash_functbl_t *tbl,
		bool unlimited = false)
{
	T *p;
	int size = keccak_get_digest_size(param, unlimited);
	if (size <= 0)
		return size;
	if (flags & DREW_HASH_FIXED)
		p = new (ctx->ctx) T(size);
	else
		p = new T(size);
	ctx->ctx = p;
	ctx->functbl = tbl;
	return 0;
}

extern "C" {
PLUGIN_STRUCTURE2(keccak, Keccak)
PLUGIN_STRUCTURE2(keccakwln, KeccakWithLimitedNots)
PLUGIN_STRUCTURE2(keccakcompact, KeccakCompact)
PLUGIN_STRUCTURE2(shake128, SHAKE128)
PLUGIN_STRUCTURE2(shake256, SHAKE256)
PLUGIN_STRUCTURE(sha3512, SHA3512)
PLUGIN_STRUCTURE(sha3384, SHA3384)
PLUGIN_STRUCTURE(sha3256, SHA3256)
PLUGIN_STRUCTURE(sha3224, SHA3224)
PLUGIN_DATA_START()
PLUGIN_DATA(keccak, "Keccak")
PLUGIN_DATA(keccakwln, "Keccak")
PLUGIN_DATA(keccakcompact, "Keccak")
PLUGIN_DATA(sha3512, "SHA3-512")
PLUGIN_DATA(sha3384, "SHA3-384")
PLUGIN_DATA(sha3256, "SHA3-256")
PLUGIN_DATA(sha3224, "SHA3-224")
PLUGIN_DATA(shake128, "SHAKE128")
PLUGIN_DATA(shake256, "SHAKE256")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(keccak)

static int keccakinfo(int op, void *p)
{
	return keccak_info<drew::Keccak>(op, p);
}

static int keccakinfo2(const drew_hash_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return keccak_info2<drew::Keccak>(ctx, op, out, in);
}

static int keccakinit(drew_hash_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	return keccak_init<drew::Keccak>(ctx, flags, ldr, param, &keccakfunctbl);
}

static int keccaktest(void *p, const drew_loader_t *ldr)
{
	return keccak_test<drew::Keccak>(p, ldr);
}

static int keccakwlninfo(int op, void *p)
{
	return keccak_info<drew::KeccakWithLimitedNots>(op, p);
}

static int keccakwlninfo2(const drew_hash_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return keccak_info2<drew::KeccakWithLimitedNots>(ctx, op, out, in);
}

static int keccakwlninit(drew_hash_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	return keccak_init<drew::KeccakWithLimitedNots>(ctx, flags, ldr, param,
			&keccakwlnfunctbl);
}

static int keccakwlntest(void *p, const drew_loader_t *ldr)
{
	return keccak_test<drew::KeccakWithLimitedNots>(p, ldr);
}

static int keccakcompactinfo(int op, void *p)
{
	return keccak_info<drew::KeccakCompact>(op, p);
}

static int keccakcompactinfo2(const drew_hash_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return keccak_info2<drew::KeccakCompact>(ctx, op, out, in);
}

static int keccakcompactinit(drew_hash_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	return keccak_init<drew::KeccakCompact>(ctx, flags, ldr, param,
			&keccakcompactfunctbl);
}

static int keccakcompacttest(void *p, const drew_loader_t *ldr)
{
	return keccak_test<drew::KeccakCompact>(p, ldr);
}

static int shake128info(int op, void *p)
{
	return keccak_info<drew::SHAKE128>(op, p, true);
}

static int shake128info2(const drew_hash_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return keccak_info2<drew::SHAKE128>(ctx, op, out, in, true);
}

static int shake128init(drew_hash_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	return keccak_init<drew::SHAKE128>(ctx, flags, ldr, param,
			&shake128functbl, true);
}

static int shake256info(int op, void *p)
{
	return keccak_info<drew::SHAKE256>(op, p, true);
}

static int shake256info2(const drew_hash_t *ctx, int op, drew_param_t *out,
		const drew_param_t *in)
{
	return keccak_info2<drew::SHAKE256>(ctx, op, out, in, true);
}

static int shake256init(drew_hash_t *ctx, int flags, const drew_loader_t *ldr,
		const drew_param_t *param)
{
	return keccak_init<drew::SHAKE256>(ctx, flags, ldr, param,
			&shake256functbl, true);
}

// Test vectors from http://www.di-mgt.com.au/sha_testvectors.html.
static int sha3224test(void *p, const drew_loader_t *ldr)
{
	int res = 0;

	using namespace drew;

	res |= !HashTestCase<SHA3224>("", 0).Test("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
	res <<= 1;
	res |= !HashTestCase<SHA3224>("abc", 1).Test("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
	res <<= 1;
	res |= !HashTestCase<SHA3224>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");
	res <<= 1;
	res |= !HashTestCase<SHA3224>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c");

	return res;
}

static int sha3256test(void *p, const drew_loader_t *ldr)
{
	int res = 0;

	using namespace drew;

	res |= !HashTestCase<SHA3256>("", 0).Test("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
	res <<= 1;
	res |= !HashTestCase<SHA3256>("abc", 1).Test("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
	res <<= 1;
	res |= !HashTestCase<SHA3256>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
	res <<= 1;
	res |= !HashTestCase<SHA3256>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1");

	return res;
}


static int sha3384test(void *p, const drew_loader_t *ldr)
{
	int res = 0;

	using namespace drew;

	res |= !HashTestCase<SHA3384>("", 0).Test("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
	res <<= 1;
	res |= !HashTestCase<SHA3384>("abc", 1).Test("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
	res <<= 1;
	res |= !HashTestCase<SHA3384>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22");
	res <<= 1;
	res |= !HashTestCase<SHA3384>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340");

	return res;
}

static int sha3512test(void *p, const drew_loader_t *ldr)
{
	int res = 0;

	using namespace drew;

	res |= !HashTestCase<SHA3512>("", 0).Test("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
	res <<= 1;
	res |= !HashTestCase<SHA3512>("abc", 1).Test("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
	res <<= 1;
	res |= !HashTestCase<SHA3512>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e");
	res <<= 1;
	res |= !HashTestCase<SHA3512>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87");

	return res;
}

static int shake128test(void *p, const drew_loader_t *ldr)
{
	return -DREW_ERR_NOT_IMPL;
}

static int shake256test(void *p, const drew_loader_t *ldr)
{
	return -DREW_ERR_NOT_IMPL;
}

}

typedef drew::Keccak::endian_t E;

drew::Keccak::Keccak(size_t t_) : m_pad(0x01), m_c(t_*2), m_r(200-m_c)
{
	Reset();
}

drew::KeccakWithLimitedNots::KeccakWithLimitedNots(size_t t_)
{
	m_c = t_ * 2;
	m_r = 200 - m_c;
	m_pad = 0x01;
	Reset();
}

drew::KeccakCompact::KeccakCompact(size_t t_)
{
	m_c = t_ * 2;
	m_r = 200 - m_c;
	m_pad = 0x01;
	Reset();
}


inline static void dump(const char *s, uint64_t a[25])
{
#if 0
	for (size_t i = 0; i < 5; i++)
		printf("%s%d: %016lx %016lx %016lx %016lx %016lx\n", s, i, a[i*5+0],
				a[i*5+1], a[i*5+2], a[i*5+3], a[i*5+4]);
#endif
}

inline static void theta(uint64_t a[25])
{
	uint64_t c[5], d;
	uint64_t *w = a + 5, *x = a + 10, *y = a + 15, *z = a + 20;

	for (size_t i = 0; i < 5; i++) {
		c[i] = a[i] ^ w[i] ^ x[i] ^ y[i] ^ z[i];
	}
	for (size_t i = 0; i < 5; i++) {
		d = c[(i+4) % 5] ^ RotateLeft(c[(i+1) % 5], 1);
		a[i] ^= d;
		w[i] ^= d;
		x[i] ^= d;
		y[i] ^= d;
		z[i] ^= d;
		//for (size_t j = 0; j < 5; j++)
		//	a[i+5*j] ^= d;
	}
}

inline static void rhopi(uint64_t b[25], const uint64_t a[25])
{
	b[0+5*(((2*0)+(3*0))%5)] = a[0];
	b[0+5*(((2*1)+(3*0))%5)] = RotateLeft(a[1+5*0],  1);
	b[0+5*(((2*2)+(3*0))%5)] = RotateLeft(a[2+5*0], 62);
	b[0+5*(((2*3)+(3*0))%5)] = RotateLeft(a[3+5*0], 28);
	b[0+5*(((2*4)+(3*0))%5)] = RotateLeft(a[4+5*0], 27);

	b[1+5*(((2*0)+(3*1))%5)] = RotateLeft(a[0+5*1], 36);
	b[1+5*(((2*1)+(3*1))%5)] = RotateLeft(a[1+5*1], 44);
	b[1+5*(((2*2)+(3*1))%5)] = RotateLeft(a[2+5*1],  6);
	b[1+5*(((2*3)+(3*1))%5)] = RotateLeft(a[3+5*1], 55);
	b[1+5*(((2*4)+(3*1))%5)] = RotateLeft(a[4+5*1], 20);

	b[2+5*(((2*0)+(3*2))%5)] = RotateLeft(a[0+5*2],  3);
	b[2+5*(((2*1)+(3*2))%5)] = RotateLeft(a[1+5*2], 10);
	b[2+5*(((2*2)+(3*2))%5)] = RotateLeft(a[2+5*2], 43);
	b[2+5*(((2*3)+(3*2))%5)] = RotateLeft(a[3+5*2], 25);
	b[2+5*(((2*4)+(3*2))%5)] = RotateLeft(a[4+5*2], 39);

	b[3+5*(((2*0)+(3*3))%5)] = RotateLeft(a[0+5*3], 41);
	b[3+5*(((2*1)+(3*3))%5)] = RotateLeft(a[1+5*3], 45);
	b[3+5*(((2*2)+(3*3))%5)] = RotateLeft(a[2+5*3], 15);
	b[3+5*(((2*3)+(3*3))%5)] = RotateLeft(a[3+5*3], 21);
	b[3+5*(((2*4)+(3*3))%5)] = RotateLeft(a[4+5*3],  8);

	b[4+5*(((2*0)+(3*4))%5)] = RotateLeft(a[0+5*4], 18);
	b[4+5*(((2*1)+(3*4))%5)] = RotateLeft(a[1+5*4],  2);
	b[4+5*(((2*2)+(3*4))%5)] = RotateLeft(a[2+5*4], 61);
	b[4+5*(((2*3)+(3*4))%5)] = RotateLeft(a[3+5*4], 56);
	b[4+5*(((2*4)+(3*4))%5)] = RotateLeft(a[4+5*4], 14);
}

template<int T>
inline static void chi(uint64_t *a, const uint64_t *b)
{
	uint64_t *p = a;
	const uint64_t *q = b;
	for (size_t j = 0; j < 5; j++, q += 5) {
		// If the processor has an and-not instruction, such as SPARC or ARM,
		// then the compiler will adjust this appropriately to use that
		// instruction.  (We hope.)
		const uint64_t v = q[0], w = q[1], x = q[2], y = q[3], z = q[4];
		*p++ = v ^ ((~w) & x);
		*p++ = w ^ ((~x) & y);
		*p++ = x ^ ((~y) & z);
		*p++ = y ^ ((~z) & v);
		*p++ = z ^ ((~v) & w);
	}
}

template<>
inline void chi<1>(uint64_t *a, const uint64_t *b)
{
	// This version is used when the processor does not have an and-not
	// instruction; it reduces the number of nots used by using the lane
	// complementation technique.
	a[0+5*0] =  b[0+5*0] ^ ( b[1+5*0] |  b[2+5*0]);
	a[0+5*1] =  b[0+5*1] ^ ( b[1+5*1] |  b[2+5*1]);
	a[0+5*2] =  b[0+5*2] ^ ( b[1+5*2] |  b[2+5*2]);
	a[0+5*3] =  b[0+5*3] ^ ( b[1+5*3] &  b[2+5*3]);
	a[0+5*4] =  b[0+5*4] ^ (~b[1+5*4] &  b[2+5*4]);

	a[1+5*0] =  b[1+5*0] ^ (~b[2+5*0] |  b[3+5*0]);
	a[1+5*1] =  b[1+5*1] ^ ( b[2+5*1] &  b[3+5*1]);
	a[1+5*2] =  b[1+5*2] ^ ( b[2+5*2] &  b[3+5*2]);
	a[1+5*3] =  b[1+5*3] ^ ( b[2+5*3] |  b[3+5*3]);
	a[1+5*4] = ~b[1+5*4] ^ ( b[2+5*4] |  b[3+5*4]);

	a[2+5*0] =  b[2+5*0] ^ ( b[3+5*0] &  b[4+5*0]);
	a[2+5*1] =  b[2+5*1] ^ ( b[3+5*1] | ~b[4+5*1]);
	a[2+5*2] =  b[2+5*2] ^ (~b[3+5*2] &  b[4+5*2]);
	a[2+5*3] =  b[2+5*3] ^ (~b[3+5*3] |  b[4+5*3]);
	a[2+5*4] =  b[2+5*4] ^ ( b[3+5*4] &  b[4+5*4]);

	a[3+5*0] =  b[3+5*0] ^ ( b[4+5*0] |  b[0+5*0]);
	a[3+5*1] =  b[3+5*1] ^ ( b[4+5*1] |  b[0+5*1]);
	a[3+5*2] = ~b[3+5*2] ^ ( b[4+5*2] |  b[0+5*2]);
	a[3+5*3] = ~b[3+5*3] ^ ( b[4+5*3] &  b[0+5*3]);
	a[3+5*4] =  b[3+5*4] ^ ( b[4+5*4] |  b[0+5*4]);

	a[4+5*0] =  b[4+5*0] ^ ( b[0+5*0] &  b[1+5*0]);
	a[4+5*1] =  b[4+5*1] ^ ( b[0+5*1] &  b[1+5*1]);
	a[4+5*2] =  b[4+5*2] ^ ( b[0+5*2] &  b[1+5*2]);
	a[4+5*3] =  b[4+5*3] ^ ( b[0+5*3] |  b[1+5*3]);
	a[4+5*4] =  b[4+5*4] ^ ( b[0+5*4] &  b[1+5*4]);
}

template<int T>
inline static void chirhopi(uint64_t a[25])
{
	uint64_t b[25];
	rhopi(b, a);
	chi<T>(a, b);
}

inline static void iota(uint64_t a[25], uint64_t k)
{
	a[0] ^= k;
}

template<int T>
inline static void round(uint64_t a[25], uint64_t k)
{
	theta(a);
	chirhopi<T>(a);
	iota(a, k);
}

static const uint64_t rc[] = {
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008
};



template<int T>
static void keccak_f(uint64_t state[25])
{
	dump("s", state);
	for (size_t i = 0; i < 24; i += 6) {
		round<T>(state, rc[i+0]);
		round<T>(state, rc[i+1]);
		round<T>(state, rc[i+2]);
		round<T>(state, rc[i+3]);
		round<T>(state, rc[i+4]);
		round<T>(state, rc[i+5]);
	}
	dump("e", state);
}

// This optimized implementation is based the 64-bit optimized version (in the
// public domain) provided by the Keccak designers.  It has been updated to
// include the limited-nots modification to improve performance.
static inline void round2(uint64_t a[25], uint64_t e[25], uint64_t c[5],
		uint64_t k)
{
	uint64_t b0, b1, b2, b3, b4;
	uint64_t d0, d1, d2, d3, d4;
	d0 = c[4] ^ RotateLeft(c[1], 1);
	d1 = c[0] ^ RotateLeft(c[2], 1);
	d2 = c[1] ^ RotateLeft(c[3], 1);
	d3 = c[2] ^ RotateLeft(c[4], 1);
	d4 = c[3] ^ RotateLeft(c[0], 1);

	// Piece 1.
	b0 = a[0] ^= d0;
	b1 = RotateLeft(a[ 6] ^= d1, 44);
	b2 = RotateLeft(a[12] ^= d2, 43);
	b3 = RotateLeft(a[18] ^= d3, 21);
	b4 = RotateLeft(a[24] ^= d4, 14);

	c[0] = e[ 0] =  b0 ^ ( b1 |  b2) ^ k;
	c[1] = e[ 1] =  b1 ^ (~b2 |  b3);
	c[2] = e[ 2] =  b2 ^ ( b3 &  b4);
	c[3] = e[ 3] =  b3 ^ ( b4 |  b0);
	c[4] = e[ 4] =  b4 ^ ( b0 &  b1);

	// Piece 2.
	b0 = RotateLeft(a[ 3] ^= d3, 28);
	b1 = RotateLeft(a[ 9] ^= d4, 20);
	b2 = RotateLeft(a[10] ^= d0,  3);
	b3 = RotateLeft(a[16] ^= d1, 45);
	b4 = RotateLeft(a[22] ^= d2, 61);

	c[0] ^= e[ 5] =  b0 ^ ( b1 |  b2);
	c[1] ^= e[ 6] =  b1 ^ ( b2 &  b3);
	c[2] ^= e[ 7] =  b2 ^ ( b3 | ~b4);
	c[3] ^= e[ 8] =  b3 ^ ( b4 |  b0);
	c[4] ^= e[ 9] =  b4 ^ ( b0 &  b1);

	// Piece 3.
	b0 = RotateLeft(a[ 1] ^= d1,  1);
	b1 = RotateLeft(a[ 7] ^= d2,  6);
	b2 = RotateLeft(a[13] ^= d3, 25);
	b3 = RotateLeft(a[19] ^= d4,  8);
	b4 = RotateLeft(a[20] ^= d0, 18);

	c[0] ^= e[10] =  b0 ^ ( b1 |  b2);
	c[1] ^= e[11] =  b1 ^ ( b2 &  b3);
	c[2] ^= e[12] =  b2 ^ (~b3 &  b4);
	c[3] ^= e[13] = ~b3 ^ ( b4 |  b0);
	c[4] ^= e[14] =  b4 ^ ( b0 &  b1);

	// Piece 4.
	b0 = RotateLeft(a[ 4] ^= d4, 27);
	b1 = RotateLeft(a[ 5] ^= d0, 36);
	b2 = RotateLeft(a[11] ^= d1, 10);
	b3 = RotateLeft(a[17] ^= d2, 15);
	b4 = RotateLeft(a[23] ^= d3, 56);

	c[0] ^= e[15] =  b0 ^ ( b1 &  b2);
	c[1] ^= e[16] =  b1 ^ ( b2 |  b3);
	c[2] ^= e[17] =  b2 ^ (~b3 |  b4);
	c[3] ^= e[18] = ~b3 ^ ( b4 &  b0);
	c[4] ^= e[19] =  b4 ^ ( b0 |  b1);

	// Piece 5.
	b0 = RotateLeft(a[ 2] ^= d2, 62);
	b1 = RotateLeft(a[ 8] ^= d3, 55);
	b2 = RotateLeft(a[14] ^= d4, 39);
	b3 = RotateLeft(a[15] ^= d0, 41);
	b4 = RotateLeft(a[21] ^= d1,  2);

	c[0] ^= e[20] =  b0 ^ (~b1 &  b2);
	c[1] ^= e[21] = ~b1 ^ ( b2 |  b3);
	c[2] ^= e[22] =  b2 ^ ( b3 &  b4);
	c[3] ^= e[23] =  b3 ^ ( b4 |  b0);
	c[4] ^= e[24] =  b4 ^ ( b0 &  b1);
}

static void round1(uint64_t a[25], uint64_t e[25], uint64_t c[5],
		uint64_t k)
{
	c[0] = a[ 0] ^ a[ 5] ^ a[10] ^ a[15] ^ a[20];
	c[1] = a[ 1] ^ a[ 6] ^ a[11] ^ a[16] ^ a[21];
	c[2] = a[ 2] ^ a[ 7] ^ a[12] ^ a[17] ^ a[22];
	c[3] = a[ 3] ^ a[ 8] ^ a[13] ^ a[18] ^ a[23];
	c[4] = a[ 4] ^ a[ 9] ^ a[14] ^ a[19] ^ a[24];
}

template<>
void keccak_f<2>(uint64_t state[25])
{
	uint64_t a[25], e[25], c[5];
	dump("s", state);
	memcpy(a, state, sizeof(a));
	round1(a, e, c, rc[0]);
	for (size_t i = 0; i < 24; i += 4) {
		round2(a, e, c, rc[i+0]);
		round2(e, a, c, rc[i+1]);
		round2(a, e, c, rc[i+2]);
		round2(e, a, c, rc[i+3]);
	}
	memcpy(state, a, sizeof(a));
	dump("e", state);
}

// This is not very useful, but is required for the API.
void drew::Keccak::Transform(uint64_t state[25], const uint8_t *block)
{
	return Transform(state, block, (1600 - 576) / 8);
}

void drew::KeccakWithLimitedNots::Transform(uint64_t state[25],
		const uint8_t *block)
{
	return Transform(state, block, (1600 - 576) / 8);
}

void drew::Keccak::Transform(uint64_t state[25], const uint8_t *block,
		size_t r)
{
	uint64_t blk[1600/64];
	const uint64_t *b;
	const size_t nwords = r / sizeof(uint64_t);
	b = E::CopyIfNeeded(blk, block, r);
	for (size_t i = 0; i < nwords; i++)
		state[i] ^= b[i];
	keccak_f<0>(state);
}

void drew::Keccak::Reset()
{
	m_len = 0;
	memset(m_buf, 0, sizeof(m_buf));
	memset(m_hash, 0, sizeof(m_hash));
}

void drew::KeccakWithLimitedNots::Reset()
{
	m_len = 0;
	memset(m_buf, 0, sizeof(m_buf));
	memset(m_hash, 0, sizeof(m_hash));
	m_hash[1+5*0] = ~0;
	m_hash[2+5*0] = ~0;
	m_hash[3+5*1] = ~0;
	m_hash[2+5*2] = ~0;
	m_hash[2+5*3] = ~0;
	m_hash[0+5*4] = ~0;
}

void drew::KeccakCompact::Reset()
{
	m_len = 0;
	memset(m_buf, 0, sizeof(m_buf));
	memset(m_hash, 0, sizeof(m_hash));
	m_hash[1+5*0] = ~0;
	m_hash[2+5*0] = ~0;
	m_hash[3+5*1] = ~0;
	m_hash[2+5*2] = ~0;
	m_hash[2+5*3] = ~0;
	m_hash[0+5*4] = ~0;
}

void drew::KeccakWithLimitedNots::Transform(uint64_t state[25],
		const uint8_t *block, size_t r)
{
	uint64_t blk[1600/64];
	const uint64_t *b;
	const size_t nwords = r / sizeof(uint64_t);
	b = E::CopyIfNeeded(blk, block, r);
	for (size_t y = 0; y < DivideAndRoundUp(nwords, 5); y++)
		for (size_t x = 0; x < 5 && (x+(5*y)) < nwords; x++)
			state[x+5*y] ^= b[x + (5*y)];
	keccak_f<1>(state);
}

void drew::Keccak::GetDigest(uint8_t *digest, size_t len, bool nopad)
{
	if (!nopad)
		Pad();

	const size_t nwords = m_r / sizeof(uint64_t);
	uint8_t *d = digest;
	for (size_t i = 0; i < len; i += m_r, d += m_r) {
		uint64_t b[1600/64];
		for (size_t y = 0; y < DivideAndRoundUp(nwords, 5); y++)
			for (size_t x = 0; x < 5 && (x+(5*y)) < nwords; x++)
				b[x + (5*y)] = m_hash[x+5*y];
		E::CopyCarefully(d, b, std::min(m_r, len - i));
		if (i + m_r < len)
			Transform(m_hash, NULL, 0);
	}
}

void drew::KeccakWithLimitedNots::GetDigest(uint8_t *digest, size_t len,
		bool nopad)
{
	if (!nopad)
		Pad();

	m_hash[1+5*0] = ~m_hash[1+5*0];
	m_hash[2+5*0] = ~m_hash[2+5*0];
	m_hash[3+5*1] = ~m_hash[3+5*1];
	m_hash[2+5*2] = ~m_hash[2+5*2];
	m_hash[2+5*3] = ~m_hash[2+5*3];
	m_hash[0+5*4] = ~m_hash[0+5*4];
	const size_t nwords = m_r / sizeof(uint64_t);
	uint8_t *d = digest;
	for (size_t i = 0; i < len; i += m_r, d += m_r) {
		uint64_t b[1600/64];
		for (size_t y = 0; y < DivideAndRoundUp(nwords, 5); y++)
			for (size_t x = 0; x < 5 && (x+(5*y)) < nwords; x++)
				b[x + (5*y)] = m_hash[x+5*y];
		E::CopyCarefully(d, b, std::min(m_r, len - i));
	}
}

void drew::KeccakCompact::GetDigest(uint8_t *digest, size_t len,
		bool nopad)
{
	if (!nopad)
		Pad();

	m_hash[1+5*0] = ~m_hash[1+5*0];
	m_hash[2+5*0] = ~m_hash[2+5*0];
	m_hash[3+5*1] = ~m_hash[3+5*1];
	m_hash[2+5*2] = ~m_hash[2+5*2];
	m_hash[2+5*3] = ~m_hash[2+5*3];
	m_hash[0+5*4] = ~m_hash[0+5*4];
	const size_t nwords = m_r / sizeof(uint64_t);
	uint8_t *d = digest;
	for (size_t i = 0; i < len; i += m_r, d += m_r) {
		uint64_t b[1600/64];
		for (size_t y = 0; y < DivideAndRoundUp(nwords, 5); y++)
			for (size_t x = 0; x < 5 && (x+(5*y)) < nwords; x++)
				b[x + (5*y)] = m_hash[x+5*y];
		E::CopyCarefully(d, b, std::min(m_r, len - i));
	}
}

void drew::KeccakCompact::Transform(uint64_t state[25], const uint8_t *block,
		size_t r)
{
	uint64_t blk[1600/64];
	const uint64_t *b;
	const size_t nwords = r / sizeof(uint64_t);
	b = E::CopyIfNeeded(blk, block, r);
	for (size_t y = 0; y < DivideAndRoundUp(nwords, 5); y++)
		for (size_t x = 0; x < 5 && (x+(5*y)) < nwords; x++)
			state[x+5*y] ^= b[x + (5*y)];
	keccak_f<2>(state);
}

UNHIDE()
