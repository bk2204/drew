/*-
 * Copyright © 2011 brian m. carlson
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
#ifdef __linux__
#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>

#include <drew/block.h>
#include "block-plugin.h"
#include "linuxaes.hh"

extern "C" {

static const int rijndaelkeysz[] =
{
	16, 24, 32
};

static const int cast6keysz[] =
{
	16, 20, 24, 28, 32
};

static const int aes128keysz[] = {16};
static const int aes192keysz[] = {24};
static const int aes256keysz[] = {32};

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

	LinuxAES ctx;
	ctx.SetKey(kb, keybytes);
	ctx.Encrypt(buf, pb);

	if (memcmp(buf, cb, blocksz))
		return false;

	ctx.SetKey(kb, keybytes);
	ctx.Decrypt(buf, cb);

	return !memcmp(buf, pb, blocksz);
}

static int rd_test(void *, const drew_loader_t *)
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


	return res;
}

static int rijndaeltest(void *p, const drew_loader_t *ldr)
{
	return rd_test(p, ldr);
}

static int aes128test(void *p, const drew_loader_t *ldr)
{
	return rd_test(p, ldr);
}

static int aes192test(void *p, const drew_loader_t *ldr)
{
	return rd_test(p, ldr);
}

static int aes256test(void *p, const drew_loader_t *ldr)
{
	return rd_test(p, ldr);
}

static int cast6test(void *p, const drew_loader_t *ldr)
{
	return -DREW_ERR_NOT_IMPL;
}

	PLUGIN_STRUCTURE(rijndael, LinuxAES)
	PLUGIN_STRUCTURE(aes128, LinuxAES)
	PLUGIN_STRUCTURE(aes192, LinuxAES)
	PLUGIN_STRUCTURE(aes256, LinuxAES)
	PLUGIN_STRUCTURE(cast6, LinuxCAST6)
	PLUGIN_DATA_START()
	PLUGIN_DATA(rijndael, "Rijndael")
	PLUGIN_DATA(aes128, "AES128")
	PLUGIN_DATA(aes192, "AES192")
	PLUGIN_DATA(aes256, "AES256")
	PLUGIN_DATA(cast6, "CAST-256")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE(linuxaes)
}

drew::LinuxAES::LinuxAES()
{
	ecbname = "ecb(aes)";
}

drew::LinuxAES::LinuxAES(const LinuxAES &other)
{
	Clone(other);
}

int drew::LinuxAES::SetKeyInternal(const uint8_t *key, size_t len)
{
	switch (len) {
		case 16:
		case 24:
		case 32:
			break;
		case 20:
		case 28:
			return -DREW_ERR_NOT_IMPL;
		default:
			return -DREW_ERR_INVALID;
	}

	return this->LinuxCryptoImplementation<16, BigEndian>::SetKeyInternal(key, len);
}

drew::LinuxCAST6::LinuxCAST6()
{
	ecbname = "ecb(cast6)";
}

drew::LinuxCAST6::LinuxCAST6(const LinuxCAST6 &other)
{
	Clone(other);
}

int drew::LinuxCAST6::SetKeyInternal(const uint8_t *key, size_t len)
{
	switch (len) {
		case 16:
		case 20:
		case 24:
		case 28:
		case 32:
			break;
		default:
			return -DREW_ERR_INVALID;
	}

	return this->LinuxCryptoImplementation<16, BigEndian>::SetKeyInternal(key, len);
}

#endif
