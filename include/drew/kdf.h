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
/* This implements key derivation functions, password-based key derivation
 * functions, and pseudo-random functions.
 */
#ifndef DREW_KDF_INTERFACE_H
#define DREW_KDF_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include <drew/drew.h>
#include <drew/param.h>
#include <drew/plugin.h>

/* The ABI version of the hash interface. */
#define DREW_KDF_VERSION 0
/* The length of the final KDF in bytes. */
#define DREW_KDF_SIZE 1 /* Not implemented in version 3 and above. */
/* The size of the block in bytes. */
#define DREW_KDF_BLKSIZE 2 /* Not implemented in version 3 and above. */
/* The endianness of this KDF algorithm.  4321 is big-endian and 1234 is
 * little-endian.
 */
#define DREW_KDF_ENDIAN 3
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_KDF_INTSIZE 4
#define DREW_KDF_SIZE_CTX 5
#define DREW_KDF_BLKSIZE_CTX 6

/* This bit is a flag indicating that the new context should be copied into
 * already-existing memory at *newctx.
 */
#define DREW_KDF_FIXED  1

struct drew_kdf_s;
typedef struct drew_kdf_s drew_kdf_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_kdf_t *, int, const drew_loader_t *, const drew_param_t *);
	int (*clone)(drew_kdf_t *, const drew_kdf_t *, int);
	int (*reset)(drew_kdf_t *);
	int (*fini)(drew_kdf_t *, int);
	int (*setkey)(drew_kdf_t *, const uint8_t *, size_t);
	int (*setsalt)(drew_kdf_t *, const uint8_t *, size_t);
	int (*setcount)(drew_kdf_t *, size_t);
	int (*generate)(drew_kdf_t *, uint8_t *, size_t, const uint8_t *, size_t);
	int (*test)(void *, const drew_loader_t *);
} drew_kdf_functbl2_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*info2)(const drew_kdf_t *, int, drew_param_t *, const drew_param_t *);
	int (*init)(drew_kdf_t *, int, const drew_loader_t *, const drew_param_t *);
	int (*clone)(drew_kdf_t *, const drew_kdf_t *, int);
	int (*reset)(drew_kdf_t *);
	int (*fini)(drew_kdf_t *, int);
	int (*setkey)(drew_kdf_t *, const uint8_t *, size_t);
	int (*setsalt)(drew_kdf_t *, const uint8_t *, size_t);
	int (*setcount)(drew_kdf_t *, size_t);
	int (*generate)(drew_kdf_t *, uint8_t *, size_t, const uint8_t *, size_t);
	int (*test)(void *, const drew_loader_t *);
} drew_kdf_functbl3_t;

typedef drew_kdf_functbl2_t drew_kdf_functbl0_t;
typedef drew_kdf_functbl2_t drew_kdf_functbl1_t;
typedef drew_kdf_functbl3_t drew_kdf_functbl_t;

struct drew_kdf_s {
	void *ctx;
	const drew_kdf_functbl_t *functbl;
	void *priv; // unused
};

#endif
