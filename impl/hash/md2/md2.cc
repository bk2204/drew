#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "md2.hh"
#include "testcase.hh"
#include "hash-plugin.hh"

#define MD2_BLOCK_LENGTH 16

HIDE()
extern "C" {
PLUGIN_STRUCTURE(md2, MD2)
PLUGIN_DATA_START()
PLUGIN_DATA(md2, "MD2")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(md2)

static int md2test(void *, const drew_loader_t *)
{
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<MD2>("", 0).Test("8350e5a3e24c153df2275c9f80692773");
	res <<= 1;
	res |= !HashTestCase<MD2>("a", 1).Test("32ec01ec4a6dac72c0ab96fb34c0b5d1");
	res <<= 1;
	res |= !HashTestCase<MD2>("abc", 1).Test("da853b0d3f88d99b30283a69e6ded6bb");
	res <<= 1;
	res |= !HashTestCase<MD2>("message digest", 1).Test("ab4f496bfb2a530b219ff33031fe06b0");
	res <<= 1;
	res |= !HashTestCase<MD2>("abcdefghijklmnopqrstuvwxyz", 1).Test("4e8ddff3650292ab5a4108c3aa47940b");
	res <<= 1;
	res |= !HashTestCase<MD2>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("da33def2a42df13975352846c30338cd");
	res <<= 1;
	res |= !HashTestCase<MD2>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("d5976f79d83d3a0dc9806c3c66f3efd8");
	res <<= 1;
	res |= !HashTestCase<MD2>::MaintenanceTest("312f262041f37e402a19b73c43f4a299");

	return res;
}
}

drew::MD2::MD2()
{
	Reset();
}

void drew::MD2::Reset()
{
	memset(m_hash, 0, sizeof(m_hash));
	m_l = 0;
	Initialize();
}

void drew::MD2::Transform(uint8_t *state, const uint8_t *block)
{
	uint8_t *csum = state + 48;
	uint8_t t = 0, l = csum[15];
	size_t i, j;

	for (i = 0; i < MD2_BLOCK_LENGTH; i++) {
		state[i + 32] = (state[i + 16] = block[i]) ^ state[i];
		l = (csum[i] ^= sbox[block[i] ^ l]);
	}

	for (i = 0; i < 18; i++) {
		for (j = 0; j < 48; j++)
			t = (state[j] ^= sbox[t]);
		t += i;
	}
}

/* This was copied from the RFC, since there was no other specification for it.
 * By law, simple facts are not copyrightable because there is no originality;
 * thus, this table is in the public domain.
 */
const uint8_t drew::MD2::sbox[] = {
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
  19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
  76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
  138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
  245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
  148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
  39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
  181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
  150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
  112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
  96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
  85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
  234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
  129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
  8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
  203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
  166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
  31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

void drew::MD2::Pad()
{
	size_t off = m_len[0] & 15;
	uint8_t val = 16 - off;
	uint8_t buf[16];

	memset(buf, val, val);
	Update(buf, val);
	/* We use MD2Update instead of MD2Transform because MD2Transform will update
	 * ctx->csum directly, which will break things.  MD2Update will instead copy
	 * into an intermediate buffer.
	 */
	Update(m_hash + 48, 16);
}
UNHIDE()
