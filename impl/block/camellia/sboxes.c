/* This file is designed to produce optimized forms of Camellia sboxes.  It is
 * not at all optimized, since this is expected to really only be run once.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const uint8_t sbox[256] = {
	112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
	 35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
	134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
	166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
	139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
	223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
	 20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
	254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
	170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
	 16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
	135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
	 82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
	233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
	120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
	114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
	 64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
};

uint64_t repl(uint8_t x)
{
	uint64_t r = 0;
	for (int i = 0; i < 8; i++) {
		r <<= 8;
		r |= x;
	}
	return r;
}

uint8_t rol(uint8_t x)
{
	return (x << 1) | (x >> 7);
}

uint8_t ror(uint8_t x)
{
	return (x >> 1) | (x << 7);
}

uint8_t s1(uint8_t x)
{
	return sbox[x];
}

uint8_t s2(uint8_t x)
{
	return rol(sbox[x]);
}

uint8_t s3(uint8_t x)
{
	return ror(sbox[x]);
}

uint8_t s4(uint8_t x)
{
	return sbox[rol(x)];
}

uint64_t sp1(uint8_t x)
{
	return repl(s1(x)) & 0xffffff00ff0000ff;
}

uint64_t sp2(uint8_t x)
{
	return repl(s2(x)) & 0x00ffffffffff0000;
}

uint64_t sp3(uint8_t x)
{
	return repl(s3(x)) & 0xff00ffff00ffff00;
}

uint64_t sp4(uint8_t x)
{
	return repl(s4(x)) & 0xffff00ff0000ffff;
}

uint64_t sp5(uint8_t x)
{
	return repl(s2(x)) & 0x00ffffff00ffffff;
}

uint64_t sp6(uint8_t x)
{
	return repl(s3(x)) & 0xff00ffffff00ffff;
}

uint64_t sp7(uint8_t x)
{
	return repl(s4(x)) & 0xffff00ffffff00ff;
}

uint64_t sp8(uint8_t x)
{
	return repl(s1(x)) & 0xffffff00ffffff00;
}

uint64_t (*ftbl[])(uint8_t) = {
	sp1, sp2, sp3, sp4, sp5, sp6, sp7, sp8
};

void print_table()
{
	printf("const uint64_t drew::Camellia::s[8][256] = {");
	for (int j = 0; j < 8; j++) {
		uint64_t (*algo)(uint8_t) = ftbl[j];
		printf("{\n");
		for (int i = 0; i < 256; i++) {
			if (!(i & 3))
				printf("\n\t");
			printf("0x%016llx, ", algo(i));
		}
		printf("},\n");
	}
	printf("\n};\n");
}

int main(void)
{
	print_table();
}
