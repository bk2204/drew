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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void print_table(const char *name, const uint8_t *t)
{
	printf("const uint8_t drew::SAFER::%s[] = {", name);
	for (int i = 0; i < 256; i++) {
		if (!(i & 7))
			printf("\n\t");
		printf("0x%02x, ", t[i]);
	}
	printf("\n};\n");
}

void generate_tables(uint8_t *s, uint8_t *sinv)
{
	const uint8_t g = 45;
	s[0] = 1;
	sinv[1] = 0;

	for (int i = 1; i < 256; i++) {
		uint32_t t = s[i-1];
		t = t ? t : 256;
		t *= g;
		t %= 257;
		s[i] = t;
		sinv[(uint8_t)t] = i;
	}

	s[128] = 0;
	sinv[0] = 128;
}

int main(void)
{
	uint8_t s[256], sinv[256];
	generate_tables(s, sinv);
	print_table("s", s);
	print_table("sinv", sinv);
}
