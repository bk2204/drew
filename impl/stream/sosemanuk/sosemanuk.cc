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
#include <utility>

#include <stdio.h>
#include <string.h>

#include <internal.h>
#include <drew/plugin.h>
#include <drew/stream.h>
#include "sosemanuk.hh"
#include "stream-plugin.h"
#include "testcase.hh"

HIDE()
extern "C" {

static int sosemanuk_test(void *, const drew_loader_t *);
static int sosemanuk_info(int op, void *p);
static int sosemanuk_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *);
static int sosemanuk_reset(drew_stream_t *ctx);
static int sosemanuk_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags);
static int sosemanuk_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len);
static int sosemanuk_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode);
static int sosemanuk_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len);
static int sosemanuk_fini(drew_stream_t *ctx, int flags);

PLUGIN_FUNCTBL(sosemanuk, sosemanuk_info, sosemanuk_init, sosemanuk_setiv, sosemanuk_setkey, sosemanuk_encrypt, sosemanuk_encrypt, sosemanuk_encrypt, sosemanuk_encrypt, sosemanuk_test, sosemanuk_fini, sosemanuk_clone, sosemanuk_reset);

static int sosemanuk_standard_test(void)
{
	using namespace drew;

	int res = 0;

	res |= StreamTestCase<Sosemanuk>("00112233445566778899aabbccddeeff",
			16).Test(
			"0000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000" 
			"0000000000000000000000000000000000000000000000000000000000000000" 
			"0000000000000000000000000000000000000000000000000000000000000000"
			"0000000000000000000000000000000000000000000000000000000000000000",
			"fa61dbeb71178131a77c714bd2eabf4e1394207a25698aa1308f2f063a0f7606"
			"04cf67569ba59a3dfad7f00145c78d29c5ffe5f964950486424451952c84039d"
			"234d9c37eecbbca1ebfb0dd16ea1194a6afc1a460e33e33fe8d55c48977079c6"
			"87810d74feddee1b3986218fb1e1c1765e4df64d7f6911c19a270c59c74b2446"
			"1717f86ce3b11808facd4f2e714168da44cf6360d54dda2241bcb79401a4edcc",
			160, "8899aabbccddeeff0011223344556677", 16);

	return res;
}

static int sosemanuk_test(void *, const drew_loader_t *)
{
	using namespace drew;

	int res = 0;
	res |= sosemanuk_standard_test();

	return res;
}

static const int sosemanuk_keysz[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
};

static int sosemanuk_info(int op, void *p)
{
	switch (op) {
		case DREW_STREAM_VERSION:
			return 2;
		case DREW_STREAM_KEYSIZE:
			for (size_t i = 0; i < DIM(sosemanuk_keysz); i++) {
				const int *x = reinterpret_cast<int *>(p);
				if (sosemanuk_keysz[i] > *x)
					return sosemanuk_keysz[i];
			}
			return 0;
		case DREW_STREAM_INTSIZE:
			return sizeof(drew::Sosemanuk);
		case DREW_STREAM_BLKSIZE:
			return 4;
		default:
			return -EINVAL;
	}
}

static int sosemanuk_init(drew_stream_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *)
{
	drew::Sosemanuk *p;
	if (flags & DREW_STREAM_FIXED)
		p = new (ctx->ctx) drew::Sosemanuk;
	else
		p = new drew::Sosemanuk;
	ctx->ctx = p;
	ctx->functbl = &sosemanukfunctbl;
	return 0;
}

static int sosemanuk_clone(drew_stream_t *newctx, const drew_stream_t *oldctx,
		int flags)
{
	drew::Sosemanuk *p;
	const drew::Sosemanuk *q = reinterpret_cast<drew::Sosemanuk *>(oldctx->ctx);
	if (flags & DREW_STREAM_FIXED)
		p = new (newctx->ctx) drew::Sosemanuk(*q);
	else
		p = new drew::Sosemanuk(*q);
	newctx->ctx = p;
	newctx->functbl = oldctx->functbl;
	return 0;
}

static int sosemanuk_reset(drew_stream_t *ctx)
{
	drew::Sosemanuk *p = reinterpret_cast<drew::Sosemanuk *>(ctx->ctx);
	p->Reset();
	return 0;
}

static int sosemanuk_setiv(drew_stream_t *ctx, const uint8_t *key, size_t len)
{
	drew::Sosemanuk *p = reinterpret_cast<drew::Sosemanuk *>(ctx->ctx);
	p->SetNonce(key, len);
	return 0;
}

static int sosemanuk_setkey(drew_stream_t *ctx, const uint8_t *key, size_t len,
		int mode)
{
	drew::Sosemanuk *p = reinterpret_cast<drew::Sosemanuk *>(ctx->ctx);
	p->SetKey(key, len);
	return 0;
}

static int sosemanuk_encrypt(drew_stream_t *ctx, uint8_t *out, const uint8_t *in,
		size_t len)
{
	drew::Sosemanuk *p = reinterpret_cast<drew::Sosemanuk *>(ctx->ctx);
	p->Encrypt(out, in, len);
	return 0;
}

static int sosemanuk_fini(drew_stream_t *ctx, int flags)
{
	drew::Sosemanuk *p = reinterpret_cast<drew::Sosemanuk *>(ctx->ctx);
	if (flags & DREW_STREAM_FIXED)
		p->~Sosemanuk();
	else 
		delete p;
	return 0;
}

PLUGIN_DATA_START()
PLUGIN_DATA(sosemanuk, "Sosemanuk")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(sosemanuk)

}

typedef drew::SosemanukKeystream::endian_t E;

drew::Sosemanuk::Sosemanuk()
{
}


void drew::Sosemanuk::SetKey(const uint8_t *key, size_t sz)
{
	m_ks.Reset();
	m_ks.SetKey(key, sz);
	memcpy(m_k, key, sz);
	m_keysz = sz;
	m_nbytes = 0;
}

void drew::Sosemanuk::Reset()
{
	m_ks.Reset();
	m_ks.SetKey(m_k, m_keysz);
	m_ks.SetNonce(m_iv, 16);
	m_nbytes = 0;
}

void drew::Sosemanuk::SetNonce(const uint8_t *iv, size_t sz)
{
	memcpy(m_iv, iv, sz);
	m_ks.SetNonce(iv, sz);
}

void drew::Sosemanuk::Encrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	CopyAndXor(out, in, len, m_buf, sizeof(m_buf), m_nbytes, m_ks);
}

void drew::Sosemanuk::Decrypt(uint8_t *out, const uint8_t *in, size_t len)
{
	return Encrypt(out, in, len);
}

typedef drew::SosemanukKeystream::endian_t E;

drew::SosemanukKeystream::SosemanukKeystream()
{
	Reset();
}

void drew::SosemanukKeystream::Reset()
{
	m_serpent.Reset();
}

void drew::SosemanukKeystream::SetKey(const uint8_t *key, size_t sz)
{
	m_serpent.SetKey(key, sz);
}

void drew::SosemanukKeystream::SetNonce(const uint8_t *iv, size_t sz)
{
	uint32_t vals[12];
	m_serpent.Serpent24(vals, iv);
	for (size_t i = 0; i < 4; i++) {
		m_s[i] = vals[11-i];
		m_s[9-i] = vals[i];
	}
	m_s[4] = vals[5];
	m_s[5] = vals[7];
	m_r1 = vals[4];
	m_r2 = vals[6];
}

/* TODO: consider processing 160 bytes at a time; that is, one full LFSR at a
 * time.
 */
void drew::SosemanukKeystream::FillBuffer(uint8_t buf[160])
{
	uint32_t f[40] ALIGNED_T, s[40] ALIGNED_T, z[40] ALIGNED_T;
	for (size_t i = 0; i < 40; i++) {
		uint32_t r1 = m_r2 + ((m_r1 & 1) ? m_s[1] ^ m_s[8] : m_s[1]);
		uint32_t r2 = RotateLeft(m_r1 * 0x54655307, 7);
		m_r1 = r1;
		m_r2 = r2;
		f[i] = (m_s[9] + r1) ^ r2;
		uint32_t s0 = m_s[0];
		memmove(m_s, m_s+1, 9 * 4);
		uint32_t s0a = (s0 << 8) ^ tablea[s0 >> 24];
		uint32_t s2i = (m_s[2] >> 8) ^ tableainv[uint8_t(m_s[2])];
		m_s[9] = m_s[8] ^ s0a ^ s2i;
		s[i] = s0;
	}
	for (size_t i = 0; i < 10; i++)
		m_serpent.Serpent1(f+(i*4));
	if (E::GetEndianness() == NativeEndian::GetEndianness())
		XorAligned(reinterpret_cast<uint32_t *>(buf), f, s, 160);
	else {
		XorAligned(z, f, s, 160);
		E::Copy(buf, z, sizeof(z));
	}
}

/* From the Sosemanuk reference implementation in the ecrypt SVN.
 * Not copyrightable since computing a table is not original.
 * The same tables are available from Crypto++ as well.
 */
const uint32_t drew::SosemanukKeystream::tablea[] = {
	0x00000000, 0xe19fcf13, 0x6b973726, 0x8a08f835,
	0xd6876e4c, 0x3718a15f, 0xbd10596a, 0x5c8f9679,
	0x05a7dc98, 0xe438138b, 0x6e30ebbe, 0x8faf24ad,
	0xd320b2d4, 0x32bf7dc7, 0xb8b785f2, 0x59284ae1,
	0x0ae71199, 0xeb78de8a, 0x617026bf, 0x80efe9ac,
	0xdc607fd5, 0x3dffb0c6, 0xb7f748f3, 0x566887e0,
	0x0f40cd01, 0xeedf0212, 0x64d7fa27, 0x85483534,
	0xd9c7a34d, 0x38586c5e, 0xb250946b, 0x53cf5b78,
	0x1467229b, 0xf5f8ed88, 0x7ff015bd, 0x9e6fdaae,
	0xc2e04cd7, 0x237f83c4, 0xa9777bf1, 0x48e8b4e2,
	0x11c0fe03, 0xf05f3110, 0x7a57c925, 0x9bc80636,
	0xc747904f, 0x26d85f5c, 0xacd0a769, 0x4d4f687a,
	0x1e803302, 0xff1ffc11, 0x75170424, 0x9488cb37,
	0xc8075d4e, 0x2998925d, 0xa3906a68, 0x420fa57b,
	0x1b27ef9a, 0xfab82089, 0x70b0d8bc, 0x912f17af,
	0xcda081d6, 0x2c3f4ec5, 0xa637b6f0, 0x47a879e3,
	0x28ce449f, 0xc9518b8c, 0x435973b9, 0xa2c6bcaa,
	0xfe492ad3, 0x1fd6e5c0, 0x95de1df5, 0x7441d2e6,
	0x2d699807, 0xccf65714, 0x46feaf21, 0xa7616032,
	0xfbeef64b, 0x1a713958, 0x9079c16d, 0x71e60e7e,
	0x22295506, 0xc3b69a15, 0x49be6220, 0xa821ad33,
	0xf4ae3b4a, 0x1531f459, 0x9f390c6c, 0x7ea6c37f,
	0x278e899e, 0xc611468d, 0x4c19beb8, 0xad8671ab,
	0xf109e7d2, 0x109628c1, 0x9a9ed0f4, 0x7b011fe7,
	0x3ca96604, 0xdd36a917, 0x573e5122, 0xb6a19e31,
	0xea2e0848, 0x0bb1c75b, 0x81b93f6e, 0x6026f07d,
	0x390eba9c, 0xd891758f, 0x52998dba, 0xb30642a9,
	0xef89d4d0, 0x0e161bc3, 0x841ee3f6, 0x65812ce5,
	0x364e779d, 0xd7d1b88e, 0x5dd940bb, 0xbc468fa8,
	0xe0c919d1, 0x0156d6c2, 0x8b5e2ef7, 0x6ac1e1e4,
	0x33e9ab05, 0xd2766416, 0x587e9c23, 0xb9e15330,
	0xe56ec549, 0x04f10a5a, 0x8ef9f26f, 0x6f663d7c,
	0x50358897, 0xb1aa4784, 0x3ba2bfb1, 0xda3d70a2,
	0x86b2e6db, 0x672d29c8, 0xed25d1fd, 0x0cba1eee,
	0x5592540f, 0xb40d9b1c, 0x3e056329, 0xdf9aac3a,
	0x83153a43, 0x628af550, 0xe8820d65, 0x091dc276,
	0x5ad2990e, 0xbb4d561d, 0x3145ae28, 0xd0da613b,
	0x8c55f742, 0x6dca3851, 0xe7c2c064, 0x065d0f77,
	0x5f754596, 0xbeea8a85, 0x34e272b0, 0xd57dbda3,
	0x89f22bda, 0x686de4c9, 0xe2651cfc, 0x03fad3ef,
	0x4452aa0c, 0xa5cd651f, 0x2fc59d2a, 0xce5a5239,
	0x92d5c440, 0x734a0b53, 0xf942f366, 0x18dd3c75,
	0x41f57694, 0xa06ab987, 0x2a6241b2, 0xcbfd8ea1,
	0x977218d8, 0x76edd7cb, 0xfce52ffe, 0x1d7ae0ed,
	0x4eb5bb95, 0xaf2a7486, 0x25228cb3, 0xc4bd43a0,
	0x9832d5d9, 0x79ad1aca, 0xf3a5e2ff, 0x123a2dec,
	0x4b12670d, 0xaa8da81e, 0x2085502b, 0xc11a9f38,
	0x9d950941, 0x7c0ac652, 0xf6023e67, 0x179df174,
	0x78fbcc08, 0x9964031b, 0x136cfb2e, 0xf2f3343d,
	0xae7ca244, 0x4fe36d57, 0xc5eb9562, 0x24745a71,
	0x7d5c1090, 0x9cc3df83, 0x16cb27b6, 0xf754e8a5,
	0xabdb7edc, 0x4a44b1cf, 0xc04c49fa, 0x21d386e9,
	0x721cdd91, 0x93831282, 0x198beab7, 0xf81425a4,
	0xa49bb3dd, 0x45047cce, 0xcf0c84fb, 0x2e934be8,
	0x77bb0109, 0x9624ce1a, 0x1c2c362f, 0xfdb3f93c,
	0xa13c6f45, 0x40a3a056, 0xcaab5863, 0x2b349770,
	0x6c9cee93, 0x8d032180, 0x070bd9b5, 0xe69416a6,
	0xba1b80df, 0x5b844fcc, 0xd18cb7f9, 0x301378ea,
	0x693b320b, 0x88a4fd18, 0x02ac052d, 0xe333ca3e,
	0xbfbc5c47, 0x5e239354, 0xd42b6b61, 0x35b4a472,
	0x667bff0a, 0x87e43019, 0x0decc82c, 0xec73073f,
	0xb0fc9146, 0x51635e55, 0xdb6ba660, 0x3af46973,
	0x63dc2392, 0x8243ec81, 0x084b14b4, 0xe9d4dba7,
	0xb55b4dde, 0x54c482cd, 0xdecc7af8, 0x3f53b5eb
};

const uint32_t drew::SosemanukKeystream::tableainv[] = {
	0x00000000, 0x180f40cd, 0x301e8033, 0x2811c0fe,
	0x603ca966, 0x7833e9ab, 0x50222955, 0x482d6998,
	0xc078fbcc, 0xd877bb01, 0xf0667bff, 0xe8693b32,
	0xa04452aa, 0xb84b1267, 0x905ad299, 0x88559254,
	0x29f05f31, 0x31ff1ffc, 0x19eedf02, 0x01e19fcf,
	0x49ccf657, 0x51c3b69a, 0x79d27664, 0x61dd36a9,
	0xe988a4fd, 0xf187e430, 0xd99624ce, 0xc1996403,
	0x89b40d9b, 0x91bb4d56, 0xb9aa8da8, 0xa1a5cd65,
	0x5249be62, 0x4a46feaf, 0x62573e51, 0x7a587e9c,
	0x32751704, 0x2a7a57c9, 0x026b9737, 0x1a64d7fa,
	0x923145ae, 0x8a3e0563, 0xa22fc59d, 0xba208550,
	0xf20decc8, 0xea02ac05, 0xc2136cfb, 0xda1c2c36,
	0x7bb9e153, 0x63b6a19e, 0x4ba76160, 0x53a821ad,
	0x1b854835, 0x038a08f8, 0x2b9bc806, 0x339488cb,
	0xbbc11a9f, 0xa3ce5a52, 0x8bdf9aac, 0x93d0da61,
	0xdbfdb3f9, 0xc3f2f334, 0xebe333ca, 0xf3ec7307,
	0xa492d5c4, 0xbc9d9509, 0x948c55f7, 0x8c83153a,
	0xc4ae7ca2, 0xdca13c6f, 0xf4b0fc91, 0xecbfbc5c,
	0x64ea2e08, 0x7ce56ec5, 0x54f4ae3b, 0x4cfbeef6,
	0x04d6876e, 0x1cd9c7a3, 0x34c8075d, 0x2cc74790,
	0x8d628af5, 0x956dca38, 0xbd7c0ac6, 0xa5734a0b,
	0xed5e2393, 0xf551635e, 0xdd40a3a0, 0xc54fe36d,
	0x4d1a7139, 0x551531f4, 0x7d04f10a, 0x650bb1c7,
	0x2d26d85f, 0x35299892, 0x1d38586c, 0x053718a1,
	0xf6db6ba6, 0xeed42b6b, 0xc6c5eb95, 0xdecaab58,
	0x96e7c2c0, 0x8ee8820d, 0xa6f942f3, 0xbef6023e,
	0x36a3906a, 0x2eacd0a7, 0x06bd1059, 0x1eb25094,
	0x569f390c, 0x4e9079c1, 0x6681b93f, 0x7e8ef9f2,
	0xdf2b3497, 0xc724745a, 0xef35b4a4, 0xf73af469,
	0xbf179df1, 0xa718dd3c, 0x8f091dc2, 0x97065d0f,
	0x1f53cf5b, 0x075c8f96, 0x2f4d4f68, 0x37420fa5,
	0x7f6f663d, 0x676026f0, 0x4f71e60e, 0x577ea6c3,
	0xe18d0321, 0xf98243ec, 0xd1938312, 0xc99cc3df,
	0x81b1aa47, 0x99beea8a, 0xb1af2a74, 0xa9a06ab9,
	0x21f5f8ed, 0x39fab820, 0x11eb78de, 0x09e43813,
	0x41c9518b, 0x59c61146, 0x71d7d1b8, 0x69d89175,
	0xc87d5c10, 0xd0721cdd, 0xf863dc23, 0xe06c9cee,
	0xa841f576, 0xb04eb5bb, 0x985f7545, 0x80503588,
	0x0805a7dc, 0x100ae711, 0x381b27ef, 0x20146722,
	0x68390eba, 0x70364e77, 0x58278e89, 0x4028ce44,
	0xb3c4bd43, 0xabcbfd8e, 0x83da3d70, 0x9bd57dbd,
	0xd3f81425, 0xcbf754e8, 0xe3e69416, 0xfbe9d4db,
	0x73bc468f, 0x6bb30642, 0x43a2c6bc, 0x5bad8671,
	0x1380efe9, 0x0b8faf24, 0x239e6fda, 0x3b912f17,
	0x9a34e272, 0x823ba2bf, 0xaa2a6241, 0xb225228c,
	0xfa084b14, 0xe2070bd9, 0xca16cb27, 0xd2198bea,
	0x5a4c19be, 0x42435973, 0x6a52998d, 0x725dd940,
	0x3a70b0d8, 0x227ff015, 0x0a6e30eb, 0x12617026,
	0x451fd6e5, 0x5d109628, 0x750156d6, 0x6d0e161b,
	0x25237f83, 0x3d2c3f4e, 0x153dffb0, 0x0d32bf7d,
	0x85672d29, 0x9d686de4, 0xb579ad1a, 0xad76edd7,
	0xe55b844f, 0xfd54c482, 0xd545047c, 0xcd4a44b1,
	0x6cef89d4, 0x74e0c919, 0x5cf109e7, 0x44fe492a,
	0x0cd320b2, 0x14dc607f, 0x3ccda081, 0x24c2e04c,
	0xac977218, 0xb49832d5, 0x9c89f22b, 0x8486b2e6,
	0xccabdb7e, 0xd4a49bb3, 0xfcb55b4d, 0xe4ba1b80,
	0x17566887, 0x0f59284a, 0x2748e8b4, 0x3f47a879,
	0x776ac1e1, 0x6f65812c, 0x477441d2, 0x5f7b011f,
	0xd72e934b, 0xcf21d386, 0xe7301378, 0xff3f53b5,
	0xb7123a2d, 0xaf1d7ae0, 0x870cba1e, 0x9f03fad3,
	0x3ea637b6, 0x26a9777b, 0x0eb8b785, 0x16b7f748,
	0x5e9a9ed0, 0x4695de1d, 0x6e841ee3, 0x768b5e2e,
	0xfedecc7a, 0xe6d18cb7, 0xcec04c49, 0xd6cf0c84,
	0x9ee2651c, 0x86ed25d1, 0xaefce52f, 0xb6f3a5e2
};
UNHIDE()
