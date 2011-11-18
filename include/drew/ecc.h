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
#ifndef DREW_ECC_INTERFACE_H
#define DREW_ECC_INTERFACE_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <drew/drew.h>
#include <drew/param.h>
#include <drew/plugin.h>

/* The ABI version of the hash interface. */
#define DREW_ECC_VERSION 0
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_ECC_INTSIZE 1

/* This bit is a flag indicating that the new context should be copied into
 * already-existing memory at *newctx.
 */
#define DREW_ECC_FIXED  1

/* Whether the value is the x coordinate, the y coordinate, or a serialized
 * point representation specified in the SEC format.
 */
#define DREW_ECC_POINT_NONE				0
#define DREW_ECC_POINT_X				1
#define DREW_ECC_POINT_Y				2
#define DREW_ECC_POINT_SEC				3
#define DREW_ECC_POINT_SEC_COMPRESSED	4

struct drew_ecc_s;
typedef struct drew_ecc_s drew_ecc_t;

struct drew_ecc_point_s;
typedef struct drew_ecc_point_s drew_ecc_point_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*info2)(const drew_ecc_t *, int, drew_param_t *,
			const drew_param_t *);
	int (*init)(drew_ecc_t *, int, const drew_loader_t *,
			const drew_param_t *);
	int (*clone)(drew_ecc_t *, const drew_ecc_t *, int);
	int (*fini)(drew_ecc_t *, int);
	int (*setcurvename)(drew_ecc_t *, const char *);
	int (*curvename)(drew_ecc_t *, const char **);
	int (*setval)(drew_ecc_t *, const char *, const uint8_t *, size_t, int);
	int (*val)(const drew_ecc_t *, const char *, uint8_t *, size_t, int);
	int (*valsize)(const drew_ecc_t *, const char *, int);
	int (*setvalbignum)(drew_ecc_t *, const char *, const drew_bignum_t *, int);
	int (*valbignum)(const drew_ecc_t *, const char *, drew_bignum_t *, int);
	int (*setvalpoint)(drew_ecc_t *, const char *, const drew_ecc_point_t *);
	int (*valpoint)(const drew_ecc_t *, const char *, drew_ecc_point_t *);
	int (*point)(const drew_ecc_t *, drew_ecc_point_t *);
	int (*test)(void *, const drew_loader_t *);
} drew_ecc_functbl3_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*info2)(const drew_ecc_point_t *, int, drew_param_t *,
			const drew_param_t *);
	int (*init)(drew_ecc_point_t *, int, const drew_loader_t *,
			const drew_param_t *);
	int (*clone)(drew_ecc_point_t *, const drew_ecc_point_t *, int);
	int (*fini)(drew_ecc_point_t *, int);
	int (*setinf)(drew_ecc_point_t *, bool);
	int (*isinf)(const drew_ecc_point_t *);
	int (*compare)(const drew_ecc_point_t *, const drew_ecc_point_t *);
	int (*setcoordbytes)(drew_ecc_point_t *, const uint8_t *, size_t, int);
	int (*coordbytes)(const drew_ecc_point_t *, uint8_t *, size_t, int);
	int (*ncoordbytes)(const drew_ecc_point_t *, int);
	int (*setcoordbignum)(drew_ecc_point_t *, const drew_bignum_t *, int);
	int (*coordbignum)(const drew_ecc_point_t *, drew_bignum_t *, int);
	int (*inv)(drew_ecc_point_t *, const drew_ecc_point_t *);
	int (*add)(drew_ecc_point_t *, const drew_ecc_point_t *,
			const drew_ecc_point_t *);
	int (*mul)(drew_ecc_point_t *, const drew_ecc_point_t *,
			const drew_bignum_t *);
	int (*mul2)(drew_ecc_point_t *, const drew_ecc_point_t *,
			const drew_bignum_t *, const drew_ecc_point_t *,
			const drew_bignum_t *);
	int (*dbl)(drew_ecc_point_t *, const drew_ecc_point_t *);
	int (*test)(void *, const drew_loader_t *);
} drew_ecc_point_functbl3_t;

typedef drew_ecc_functbl3_t drew_ecc_functbl_t;

typedef drew_ecc_point_functbl3_t drew_ecc_point_functbl_t;

struct drew_ecc_s {
	void *ctx;
	const drew_ecc_functbl_t *functbl;
	void *priv; // unused
};

struct drew_ecc_point_s {
	void *ctx;
	const drew_ecc_point_functbl_t *functbl;
	void *priv; // unused
};

#endif
