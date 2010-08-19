/*-
 * Copyright © 2000-2009 The Legion Of The Bouncy Castle
 * (http://www.bouncycastle.org)
 * Copyright © 2010 brian m. carlson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/* This has been ported from the Java version written by the Legion of the
 * Bouncy Castle.  This implementation supports arbitrary block sizes and
 * arbitrary key sizes, unlike the version in the aes directory.
 */

#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include <block.h>
#include "block-plugin.h"
#include "rijndael.hh"


extern "C" {

static const int rd_keysz[] =
{
	16, 20, 24, 28, 32
};


static const int rd_aes128_keysz[] = {16};
static const int rd_aes192_keysz[] = {24};
static const int rd_aes256_keysz[] = {32};

#define DIM(x) (sizeof(x)/sizeof(x[0]))

static int rd_main_info(int op, void *p, size_t blksz, const int *keysz,
		size_t nkeysz)
{
	switch (op) {
		case DREW_BLOCK_VERSION:
			return 0;
		case DREW_BLOCK_BLKSIZE:
			return blksz;
		case DREW_BLOCK_KEYSIZE:
			for (size_t i = 0; i < nkeysz; i++) {
				const int *x = reinterpret_cast<int *>(p);
				if (keysz[i] > *x)
					return keysz[i];
			}
			return 0;
		case DREW_BLOCK_INTSIZE:
			return sizeof(drew::Rijndael);
		default:
			return -EINVAL;
	}
}

static int rd_info(int op, void *p)
{
	return rd_main_info(op, p, 16, rd_keysz, DIM(rd_keysz));
}

static int rd160_info(int op, void *p)
{
	return rd_main_info(op, p, 20, rd_keysz, DIM(rd_keysz));
}

static int rd192_info(int op, void *p)
{
	return rd_main_info(op, p, 24, rd_keysz, DIM(rd_keysz));
}

static int rd224_info(int op, void *p)
{
	return rd_main_info(op, p, 28, rd_keysz, DIM(rd_keysz));
}

static int rd256_info(int op, void *p)
{
	return rd_main_info(op, p, 32, rd_keysz, DIM(rd_keysz));
}

static int rd_aes128_info(int op, void *p)
{
	return rd_main_info(op, p, 16, rd_aes128_keysz, DIM(rd_aes128_keysz));
}

static int rd_aes192_info(int op, void *p)
{
	return rd_main_info(op, p, 16, rd_aes192_keysz, DIM(rd_aes192_keysz));
}

static int rd_aes256_info(int op, void *p)
{
	return rd_main_info(op, p, 16, rd_aes256_keysz, DIM(rd_aes256_keysz));
}

static void rd_main_init(void **ctx, size_t blksz)
{
	drew::Rijndael *p = new drew::Rijndael(blksz);
	*ctx = p;
}

static void rd_aes_init(void **ctx, drew_loader_t *, const drew_param_t *)
{
	return rd_main_init(ctx, 16);
}

static void rd160_init(void **ctx, drew_loader_t *, const drew_param_t *)
{
	return rd_main_init(ctx, 20);
}

static void rd192_init(void **ctx, drew_loader_t *, const drew_param_t *)
{
	return rd_main_init(ctx, 24);
}

static void rd224_init(void **ctx, drew_loader_t *, const drew_param_t *)
{
	return rd_main_init(ctx, 28);
}

static void rd256_init(void **ctx, drew_loader_t *, const drew_param_t *)
{
	return rd_main_init(ctx, 32);
}

static int rd_clone(void **newctx, void *oldctx, int flags)
{
	drew::Rijndael *p = new drew::Rijndael(*reinterpret_cast<drew::Rijndael *>(oldctx));
	if (flags & DREW_BLOCK_CLONE_FIXED) {
		memcpy(*newctx, p, sizeof(*p));
		delete p;
	}
	else
		*newctx = p;
	return 0;
}

static int rd_setkey(void *ctx, const uint8_t *key, size_t len)
{
	drew::Rijndael *p = reinterpret_cast<drew::Rijndael *>(ctx);
	p->SetKey(key, len);
	return 0;
}

static void rd_encrypt(void *ctx, uint8_t *out, const uint8_t *in)
{
	drew::Rijndael *p = reinterpret_cast<drew::Rijndael *>(ctx);
	p->Encrypt(out, in);
}

static void rd_decrypt(void *ctx, uint8_t *out, const uint8_t *in)
{
	drew::Rijndael *p = reinterpret_cast<drew::Rijndael *>(ctx);
	p->Decrypt(out, in);
}

static void rd_fini(void **ctx)
{
	drew::Rijndael *p = reinterpret_cast<drew::Rijndael *>(*ctx);
	delete p;
	*ctx = NULL;
}

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

static bool test(const char *key, const char *plain, const char *cipher,
		size_t keybytes = 0, size_t blocksz = 16)
{
	using namespace drew;

	uint8_t kb[32], pb[32], cb[32], buf[32];
	str2bytes(kb, key, keybytes * 2);
	str2bytes(pb, plain, blocksz * 2);
	str2bytes(cb, cipher, blocksz * 2);

	if (!keybytes)
		keybytes = 16;

	Rijndael ctx(blocksz);
	ctx.SetKey(kb, keybytes);
	ctx.Encrypt(buf, pb);

	if (memcmp(buf, cb, blocksz))
		return false;

	ctx.SetKey(kb, keybytes);
	ctx.Decrypt(buf, cb);

	return !memcmp(buf, pb, blocksz);
}

static int rd_test(void *)
{
	int res = 0;

	const char *key =
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	const char *pt = "00112233445566778899aabbccddeeff";
	res |= !test(key, pt, "69c4e0d86a7b0430d8cdb78070b4c55a", 16);
	res |= !test(key, pt, "dda97ca4864cdfe06eaf70a0ec0d7191", 24);
	res |= !test(key, pt, "8ea2b7ca516745bfeafc49904b496089", 32);
	res <<= 1;
	const char *key2 = "2b7e151628aed2a6abf7158809cf4f3c";
	const char *pt1 = "6bc1bee22e409f96e93d7e117393172a";
	const char *pt2 = "ae2d8a571e03ac9c9eb76fac45af8e51";
	const char *pt3 = "30c81c46a35ce411e5fbc1191a0a52ef";
	const char *pt4 = "f69f2445df4f9b17ad2b417be66c3710";
	res |= !test(key2, pt1, "3ad77bb40d7a3660a89ecaf32466ef97");
	res |= !test(key2, pt2, "f5d3d58503b9699de785895a96fdbaaf");
	res |= !test(key2, pt3, "43b1cd7f598ece23881b00e3ed030688");
	res |= !test(key2, pt4, "7b0c785e27e8ad3f8223207104725dd4");
	res <<= 1;
	const char *key3 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
	res |= !test(key3, pt1, "bd334f1d6e45f25ff712a214571fa5cc", 24);
	res |= !test(key3, pt2, "974104846d0ad3ad7734ecb3ecee4eef", 24);
	res |= !test(key3, pt3, "ef7afd2270e2e60adce0ba2face6444e", 24);
	res |= !test(key3, pt4, "9a4b41ba738d6c72fb16691603c18e0e", 24);
	res <<= 1;
	const char *key4 =
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
	res |= !test(key4, pt1, "f3eed1bdb5d2a03c064b5a7e3db181f8", 32);
	res |= !test(key4, pt2, "591ccb10d410ed26dc5ba74a31362870", 32);
	res |= !test(key4, pt3, "b6ed21b99ca6f4f9f153e7b1beafed1d", 32);
	res |= !test(key4, pt4, "23304b7a39f9f3ff067d8d8f9e24ecc7", 32);
	res <<= 1;

	const char *key5 =
		"2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe";
	const char *blk = 
		"3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8";
	res |= !test(key5, blk, "3925841d02dc09fbdc118597196a0b32", 16, 16);
	res |= !test(key5, blk, "231d844639b31b412211cfe93712b880", 20, 16);
	res |= !test(key5, blk, "f9fb29aefc384a250340d833b87ebc00", 24, 16);
	res |= !test(key5, blk, "8faa8fe4dee9eb17caa4797502fc9d3f", 28, 16);
	res |= !test(key5, blk, "1a6e6c2c662e7da6501ffb62bc9e93f3", 32, 16);
	res <<= 1;

	res |= !test(key5, blk, "16e73aec921314c29df905432bc8968ab64b1f51", 16, 20);
	res |= !test(key5, blk, "0553eb691670dd8a5a5b5addf1aa7450f7a0e587", 20, 20);
	res |= !test(key5, blk, "73cd6f3423036790463aa9e19cfcde894ea16623", 24, 20);
	res |= !test(key5, blk, "601b5dcd1cf4ece954c740445340bf0afdc048df", 28, 20);
	res |= !test(key5, blk, "579e930b36c1529aa3e86628bacfe146942882cf", 32, 20);
	res <<= 1;

	res |= !test(key5, blk, "b24d275489e82bb8f7375e0d5fcdb1f481757c538b65148a",
			16, 24);
	res |= !test(key5, blk, "738dae25620d3d3beff4a037a04290d73eb33521a63ea568",
			20, 24);
	res |= !test(key5, blk, "725ae43b5f3161de806a7c93e0bca93c967ec1ae1b71e1cf",
			24, 24);
	res |= !test(key5, blk, "bbfc14180afbf6a36382a061843f0b63e769acdc98769130",
			28, 24);
	res |= !test(key5, blk, "0ebacf199e3315c2e34b24fcc7c46ef4388aa475d66c194c",
			32, 24);
	res <<= 1;

	res |= !test(key5, blk,
			"b0a8f78f6b3c66213f792ffd2a61631f79331407a5e5c8d3793aceb1", 16, 28);
	res |= !test(key5, blk,
			"08b99944edfce33a2acb131183ab0168446b2d15e958480010f545e3", 20, 28);
	res |= !test(key5, blk,
			"be4c597d8f7efe22a2f7e5b1938e2564d452a5bfe72399c7af1101e2", 24, 28);
	res |= !test(key5, blk,
			"ef529598ecbce297811b49bbed2c33bbe1241d6e1a833dbe119569e8", 28, 28);
	res |= !test(key5, blk,
			"02fafc200176ed05deb8edb82a3555b0b10d47a388dfd59cab2f6c11", 32, 28);
	res <<= 1;

	res |= !test(key5, blk,
			"7d15479076b69a46ffb3b3beae97ad8313f622f67fedb487de9f06b9ed9c8f19",
			16, 32);
	res |= !test(key5, blk,
			"514f93fb296b5ad16aa7df8b577abcbd484decacccc7fb1f18dc567309ceeffd",
			20, 32);
	res |= !test(key5, blk,
			"5d7101727bb25781bf6715b0e6955282b9610e23a43c2eb062699f0ebf5887b2",
			24, 32);
	res |= !test(key5, blk,
			"d56c5a63627432579e1dd308b2c8f157b40a4bfb56fea1377b25d3ed3d6dbf80",
			28, 32);
	res |= !test(key5, blk,
			"a49406115dfb30a40418aafa4869b7c6a886ff31602a7dd19c889dc64f7e4e7a",
			32, 32);

	return res;
}

	PLUGIN_FUNCTBL(rijndael, rd_info, rd_aes_init, rd_setkey, rd_encrypt, rd_decrypt, rd_test, rd_fini, rd_clone);
	PLUGIN_FUNCTBL(rijndael160, rd160_info, rd160_init, rd_setkey, rd_encrypt, rd_decrypt, rd_test, rd_fini, rd_clone);
	PLUGIN_FUNCTBL(rijndael192, rd192_info, rd192_init, rd_setkey, rd_encrypt, rd_decrypt, rd_test, rd_fini, rd_clone);
	PLUGIN_FUNCTBL(rijndael224, rd224_info, rd224_init, rd_setkey, rd_encrypt, rd_decrypt, rd_test, rd_fini, rd_clone);
	PLUGIN_FUNCTBL(rijndael256, rd256_info, rd256_init, rd_setkey, rd_encrypt, rd_decrypt, rd_test, rd_fini, rd_clone);
	PLUGIN_FUNCTBL(aes128, rd_aes128_info, rd_aes_init, rd_setkey, rd_encrypt, rd_decrypt, rd_test, rd_fini, rd_clone);
	PLUGIN_FUNCTBL(aes192, rd_aes192_info, rd_aes_init, rd_setkey, rd_encrypt, rd_decrypt, rd_test, rd_fini, rd_clone);
	PLUGIN_FUNCTBL(aes256, rd_aes256_info, rd_aes_init, rd_setkey, rd_encrypt, rd_decrypt, rd_test, rd_fini, rd_clone);
	PLUGIN_DATA_START()
	PLUGIN_DATA(rijndael, "Rijndael")
	PLUGIN_DATA(rijndael160, "Rijndael-160")
	PLUGIN_DATA(rijndael192, "Rijndael-192")
	PLUGIN_DATA(rijndael224, "Rijndael-224")
	PLUGIN_DATA(rijndael256, "Rijndael-256")
	PLUGIN_DATA(aes128, "AES128")
	PLUGIN_DATA(aes192, "AES192")
	PLUGIN_DATA(aes256, "AES256")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE()
}

drew::Rijndael::Rijndael(size_t blocksz)
{
	m_nb = (blocksz / 4);
	m_bc = (blocksz * 2);
	switch (blocksz) {
		case 16: // 128 bits
			m_bcmask = 0xffffffff;
			m_sh0 = shifts0[0];
			m_sh1 = shifts1[0];
			break;
		case 20: // 160 bits
			m_bcmask = 0xffffffffff;
			m_sh0 = shifts0[1];
			m_sh1 = shifts1[1];
			break;
		case 24: // 192 bits
			m_bcmask = 0xffffffffffff;
			m_sh0 = shifts0[2];
			m_sh1 = shifts1[2];
			break;
		case 28: // 224 bits
			m_bcmask = 0xffffffffffffff;
			m_sh0 = shifts0[3];
			m_sh1 = shifts1[3];
			break;
		case 32: // 256 bits
			m_bcmask = 0xffffffffffffffff;
			m_sh0 = shifts0[4];
			m_sh1 = shifts1[4];
			break;
	}
}

#define MAXNK 8

void drew::Rijndael::SetKey(const uint8_t *key, size_t len)
{
	m_nk = (len / 4);
	m_nr = 6 + std::max(m_nb, m_nk);

	uint8_t tk[4][MAXNK];

	for (size_t i = 0; i < len; i++) {
	    tk[i % 4][i / 4] = key[i];
	}

	int t = 0;

	memset(m_rk, 0, sizeof(m_rk));

	for (int j = 0; (j < m_nk) && (t < (m_nr+1)*(m_bc / 8)); j++, t++) {
		for (size_t i = 0; i < 4; i++) {
			m_rk[t / (m_bc / 8)][i] |=
				uint64_t(tk[i][j] & 0xff) << ((t * 8) % m_bc); 
		}
	}

	int ri = 0;

	while (t < (m_nr+1)*(m_bc/8)) {
		for (size_t i = 0; i < 4; i++)
			tk[i][0] ^= S[tk[(i+1)%4][m_nk-1] & 0xff];
		tk[0][0] ^= rcon[ri++];

		if (m_nk <= 6)
			for (int j = 1; j < m_nk; j++)
				for (int i = 0; i < 4; i++)
					tk[i][j] ^= tk[i][j-1];
		else {
			for (int j = 1; j < 4; j++)
				for (int i = 0; i < 4; i++)
					tk[i][j] ^= tk[i][j-1];
			for (int i = 0; i < 4; i++)
				tk[i][4] ^= S[tk[i][3] & 0xff];
			for (int j = 5; j < m_nk; j++)
				for (int i = 0; i < 4; i++)
					tk[i][j] ^= tk[i][j-1];
		}
		for (int j = 0; (j < m_nk) && (t < (m_nr+1)*(m_bc/8)); j++, t++) {
			for (int i = 0; i < 4; i++) {
				m_rk[t / (m_bc/8)][i] |= 
					uint64_t(tk[i][j] & 0xff) << ((t * 8) % (m_bc));
			}
		}
	}
}

void drew::Rijndael::Encrypt(uint8_t *out, const uint8_t *in)
{
	UnpackBlock(in);
	EncryptBlock();
	PackBlock(out);
}

void drew::Rijndael::Decrypt(uint8_t *out, const uint8_t *in)
{
	UnpackBlock(in);
	DecryptBlock();
	PackBlock(out);
}

const uint8_t drew::Rijndael::shifts0[5][4] = {
   { 0, 8, 16, 24 },
   { 0, 8, 16, 24 },
   { 0, 8, 16, 24 },
   { 0, 8, 16, 32 },
   { 0, 8, 24, 32 }
};

const uint8_t drew::Rijndael::shifts1[5][4] = {
   { 0, 24, 16, 8 },
   { 0, 32, 24, 16 },
   { 0, 40, 32, 24 },
   { 0, 48, 40, 24 },
   { 0, 56, 40, 32 }
};


void drew::Rijndael::KeyAddition(uint64_t *rk)
{
	m_a0 ^= rk[0];
	m_a1 ^= rk[1];
	m_a2 ^= rk[2];
	m_a3 ^= rk[3];
}

void drew::Rijndael::ShiftRow(const uint8_t *shifts)
{
	m_a1 = shift(m_a1, shifts[1]);
	m_a2 = shift(m_a2, shifts[2]);
	m_a3 = shift(m_a3, shifts[3]);
}

void drew::Rijndael::Substitution(const uint8_t *box)
{
	m_a0 = ApplyS(m_a0, box);
	m_a1 = ApplyS(m_a1, box);
	m_a2 = ApplyS(m_a2, box);
	m_a3 = ApplyS(m_a3, box);
}

uint64_t drew::Rijndael::ApplyS(uint64_t r, const uint8_t *box)
{
	uint64_t res = 0;

	for (size_t i = 0; i < m_bc; i += 8) {
		res |= uint64_t(box[(r >> i) & 0xff] & 0xff) << i;
	}

	return res;
}

void drew::Rijndael::MixColumn(void)
{
	uint64_t r0 = 0, r1 = 0, r2 = 0, r3 = 0;

	for (size_t i = 0; i < m_bc; i += 8)
	{
		uint8_t a0 = ((m_a0 >> i) & 0xff);
		uint8_t a1 = ((m_a1 >> i) & 0xff);
		uint8_t a2 = ((m_a2 >> i) & 0xff);
		uint8_t a3 = ((m_a3 >> i) & 0xff);

		r0 |= uint64_t((mul0x2(a0) ^ mul0x3(a1) ^ a2 ^ a3) & 0xff) << i;
		r1 |= uint64_t((mul0x2(a1) ^ mul0x3(a2) ^ a3 ^ a0) & 0xff) << i;
		r2 |= uint64_t((mul0x2(a2) ^ mul0x3(a3) ^ a0 ^ a1) & 0xff) << i;
		r3 |= uint64_t((mul0x2(a3) ^ mul0x3(a0) ^ a1 ^ a2) & 0xff) << i;
	}

	m_a0 = r0;
	m_a1 = r1;
	m_a2 = r2;
	m_a3 = r3;
}

void drew::Rijndael::InvMixColumn()
{
	uint64_t r0 = 0, r1 = 0, r2 = 0, r3 = 0;

	for (size_t i = 0; i < m_bc; i += 8)
	{
		int a0 = ((m_a0 >> i) & 0xff);
		int a1 = ((m_a1 >> i) & 0xff);
		int a2 = ((m_a2 >> i) & 0xff);
		int a3 = ((m_a3 >> i) & 0xff);

		a0 = (a0 != 0) ? (logtable[a0 & 0xff] & 0xff) : -1;
		a1 = (a1 != 0) ? (logtable[a1 & 0xff] & 0xff) : -1;
		a2 = (a2 != 0) ? (logtable[a2 & 0xff] & 0xff) : -1;
		a3 = (a3 != 0) ? (logtable[a3 & 0xff] & 0xff) : -1;

		r0 |= uint64_t((mul0xe(a0) ^ mul0xb(a1) ^ mul0xd(a2) ^ mul0x9(a3)) & 0xff) << i;
		r1 |= uint64_t((mul0xe(a1) ^ mul0xb(a2) ^ mul0xd(a3) ^ mul0x9(a0)) & 0xff) << i;
		r2 |= uint64_t((mul0xe(a2) ^ mul0xb(a3) ^ mul0xd(a0) ^ mul0x9(a1)) & 0xff) << i;
		r3 |= uint64_t((mul0xe(a3) ^ mul0xb(a0) ^ mul0xd(a1) ^ mul0x9(a2)) & 0xff) << i;
	}

	m_a0 = r0;
	m_a1 = r1;
	m_a2 = r2;
	m_a3 = r3;
}

void drew::Rijndael::EncryptBlock()
{
	KeyAddition(m_rk[0]);

	for (size_t i = 1; i < m_nr; i++) {
		Substitution(S);
		ShiftRow(m_sh0);
		MixColumn();
		KeyAddition(m_rk[i]);
	}

	Substitution(S);
	ShiftRow(m_sh0);
	KeyAddition(m_rk[m_nr]);
}

void drew::Rijndael::DecryptBlock()
{
	KeyAddition(m_rk[m_nr]);
	Substitution(Si);
	ShiftRow(m_sh1);

	for (size_t i = m_nr-1; i > 0; i--) {
		KeyAddition(m_rk[i]);
		InvMixColumn();
		Substitution(Si);
		ShiftRow(m_sh1);
	}

	KeyAddition(m_rk[0]);
}

void drew::Rijndael::PackBlock(uint8_t *blk)
{
	for (int j = 0; j != m_bc; j += 8) {
		*blk++ = m_a0 >> j;
		*blk++ = m_a1 >> j;
		*blk++ = m_a2 >> j;
		*blk++ = m_a3 >> j;
	}
}

void drew::Rijndael::UnpackBlock(const uint8_t *blk)
{
	m_a0 = m_a1 = m_a2 = m_a3 = 0;
	m_a0 = *blk++;
	m_a1 = *blk++;
	m_a2 = *blk++;
	m_a3 = *blk++;

	for (int j = 8; j != m_bc; j += 8) {
		m_a0 |= uint64_t(*blk++) << j;
		m_a1 |= uint64_t(*blk++) << j;
		m_a2 |= uint64_t(*blk++) << j;
		m_a3 |= uint64_t(*blk++) << j;
	}
}

const uint8_t drew::Rijndael::logtable[] = {
	0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6,
	0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
	0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef,
	0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
	0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a,
	0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
	0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24,
	0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
	0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94,
	0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
	0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62,
	0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
	0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42,
	0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
	0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca,
	0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
	0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74,
	0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
	0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5,
	0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
	0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec,
	0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
	0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86,
	0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
	0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc,
	0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
	0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47,
	0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
	0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89,
	0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
	0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18,
	0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07,
};

const uint8_t drew::Rijndael::aLogtable[] = {
	0x00, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
	0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
	0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
	0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
	0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
	0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
	0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
	0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
	0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
	0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
	0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
	0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
	0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
	0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
	0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
	0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
	0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
	0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
	0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
	0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
	0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
	0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
	0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
	0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
	0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
	0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
	0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
	0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
	0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
	0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
	0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
	0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01,
	0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a,
	0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
	0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
	0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
	0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
	0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
	0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
	0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
	0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
	0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
	0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
	0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
	0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
	0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
	0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
	0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
	0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01,
};

const uint8_t drew::Rijndael::S[] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

const uint8_t drew::Rijndael::Si[] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

const uint8_t drew::Rijndael::rcon[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
};
