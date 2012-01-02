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
#ifndef DREW_BIGNUM_INTERFACE_H
#define DREW_BIGNUM_INTERFACE_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <drew/drew.h>
#include <drew/param.h>
#include <drew/plugin.h>

/* The ABI version of the hash interface. */
#define DREW_BIGNUM_VERSION 0
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_BIGNUM_INTSIZE 1

/* This bit is a flag indicating that the new context should be copied into
 * already-existing memory at *newctx.
 */
#define DREW_BIGNUM_FIXED  1
/* This bit indicates that the operation should be performed on the absolute
 * value of these quantities.
 */
#define DREW_BIGNUM_ABS 2
/* This bit indicates that the clone operation should not create a new context
 * for the destination argument, but instead simply copy the value to an
 * already-existing context.
 */
#define DREW_BIGNUM_COPY 4

struct drew_bignum_s;
typedef struct drew_bignum_s drew_bignum_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_bignum_t *, int, const drew_loader_t *,
			const drew_param_t *);
	int (*clone)(drew_bignum_t *, const drew_bignum_t *, int);
	int (*fini)(drew_bignum_t *, int);
	int (*nbytes)(const drew_bignum_t *);
	// Also return sign.
	int (*bytes)(const drew_bignum_t *, uint8_t *, size_t);
	int (*setbytes)(drew_bignum_t *, const uint8_t *, size_t);
	int (*setzero)(drew_bignum_t *);
	int (*setsmall)(drew_bignum_t *, long);
	int (*negate)(drew_bignum_t *, const drew_bignum_t *);
	int (*abs)(drew_bignum_t *, const drew_bignum_t *);
	int (*compare)(const drew_bignum_t *, const drew_bignum_t *, int);
	// C++ uses "or", "bitor", "and", "bitand", and "xor" as operators, so we
	// can't use those names here.
	int (*bitwiseor)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*bitwiseand)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*bitwisexor)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*bitwisenot)(drew_bignum_t *, const drew_bignum_t *);
	int (*add)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*sub)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*mul)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*div)(drew_bignum_t *, drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*mulpow2)(drew_bignum_t *, const drew_bignum_t *, size_t);
	int (*divpow2)(drew_bignum_t *, drew_bignum_t *, const drew_bignum_t *,
			size_t);
	int (*shiftleft)(drew_bignum_t *, const drew_bignum_t *, size_t);
	int (*shiftright)(drew_bignum_t *, const drew_bignum_t *, size_t);
	int (*square)(drew_bignum_t *, const drew_bignum_t *);
	int (*mod)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*expsmall)(drew_bignum_t *, const drew_bignum_t *, unsigned long);
	int (*expmod)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*invmod)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*test)(void *, const drew_loader_t *);
} drew_bignum_functbl2_t;


typedef struct {
	int (*info)(int op, void *p);
	int (*info2)(const drew_bignum_t *, int, drew_param_t *,
			const drew_param_t *);
	int (*init)(drew_bignum_t *, int, const drew_loader_t *,
			const drew_param_t *);
	int (*clone)(drew_bignum_t *, const drew_bignum_t *, int);
	int (*fini)(drew_bignum_t *, int);
	int (*nbits)(const drew_bignum_t *);
	int (*nbytes)(const drew_bignum_t *);
	// Also return sign.
	int (*bytes)(const drew_bignum_t *, uint8_t *, size_t);
	int (*setbytes)(drew_bignum_t *, const uint8_t *, size_t);
	int (*setzero)(drew_bignum_t *);
	int (*setsmall)(drew_bignum_t *, long);
	int (*negate)(drew_bignum_t *, const drew_bignum_t *);
	int (*abs)(drew_bignum_t *, const drew_bignum_t *);
	int (*compare)(const drew_bignum_t *, const drew_bignum_t *, int);
	int (*comparesmall)(const drew_bignum_t *, long);
	// C++ uses "or", "bitor", "and", "bitand", and "xor" as operators, so we
	// can't use those names here.
	int (*bitwiseor)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*bitwiseand)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*bitwisexor)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*bitwisenot)(drew_bignum_t *, const drew_bignum_t *);
	int (*getbit)(const drew_bignum_t *, size_t);
	int (*setbit)(drew_bignum_t *, size_t, bool);
	int (*add)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*sub)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*mul)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*div)(drew_bignum_t *, drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*mulpow2)(drew_bignum_t *, const drew_bignum_t *, size_t);
	int (*divpow2)(drew_bignum_t *, drew_bignum_t *, const drew_bignum_t *,
			size_t);
	int (*shiftleft)(drew_bignum_t *, const drew_bignum_t *, size_t);
	int (*shiftright)(drew_bignum_t *, const drew_bignum_t *, size_t);
	int (*square)(drew_bignum_t *, const drew_bignum_t *);
	int (*mod)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*expsmall)(drew_bignum_t *, const drew_bignum_t *, unsigned long);
	int (*squaremod)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*addmod)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*mulmod)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*expmod)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*invmod)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*gcd)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*test)(void *, const drew_loader_t *);
} drew_bignum_functbl3_t;

typedef drew_bignum_functbl2_t drew_bignum_functbl0_t;
typedef drew_bignum_functbl2_t drew_bignum_functbl1_t;
typedef drew_bignum_functbl3_t drew_bignum_functbl_t;

struct drew_bignum_s {
	void *ctx;
	const drew_bignum_functbl_t *functbl;
	void *priv; // unused
};

#endif
