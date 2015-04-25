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
/* This file is designed to produce the tables for GF(2^8) multiplication by 4,
 * 5, 6, and 7.  It is not at all optimized, since this is expected to really
 * only be run once.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Algorithm from http://www.cs.utsa.edu/~wagner/laws/FFM.html */
uint8_t ffmul(uint8_t a, uint8_t b, uint8_t poly)
{
	uint8_t r = 0, t;
	while (a) {
		if (a & 1)
			r ^= b;
		t = b & 0x80;
		b <<= 1;
		if (t)
			b ^= poly;
		a >>= 1;
	}
	return r;
}

void print_table(int multiplier)
{
	printf("const uint8_t mul%d[] = {", multiplier);
	for (int i = 0; i < 256; i++) {
		if (!(i & 7))
			printf("\n\t");
		printf("0x%02x, ", ffmul(i, multiplier, 0x1b));
	}
	printf("\n};\n");
}

int main(void)
{
	print_table(4);
	print_table(5);
	print_table(6);
	print_table(7);
}
