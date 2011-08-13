/*-
 * Copyright © 2010-2011 brian m. carlson
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
#ifndef DREW_MAC_INTERFACE_H
#define DREW_MAC_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include <drew/drew.h>
#include <drew/param.h>
#include <drew/plugin.h>

/* The ABI version of the hash interface. */
#define DREW_MAC_VERSION 0 /* Not implemented. */
/* The length of the final MAC in bytes. */
#define DREW_MAC_SIZE 1
/* The size of the block in bytes. */
#define DREW_MAC_BLKSIZE 2
/* The endianness of this hash algorithm.  4321 is big-endian and 1234 is
 * little-endian.
 */
#define DREW_MAC_ENDIAN 3 /* Not implemented. */
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_MAC_INTSIZE 4

/* This bit is a flag indicating that the new context should be copied into
 * already-existing memory at *newctx.
 */
#define DREW_MAC_FIXED  1

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(void **, void *, int, drew_loader_t *, const drew_param_t *);
	int (*clone)(void **, void *, int);
	int (*fini)(void **, int);
	int (*setkey)(void *, const uint8_t *, size_t);
	int (*update)(void *, const uint8_t *, size_t);
	int (*final)(void *, uint8_t *, int);
	int (*test)(void *, drew_loader_t *);
} drew_mac_functbl0_t;
typedef drew_mac_functbl0_t drew_mac_functbl1_t;

struct drew_mac_s;
typedef struct drew_mac_s drew_mac_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_mac_t *, int, const drew_loader_t *, const drew_param_t *);
	int (*clone)(drew_mac_t *, const drew_mac_t *, int);
	int (*reset)(drew_mac_t *);
	int (*fini)(drew_mac_t *, int);
	int (*setkey)(drew_mac_t *, const uint8_t *, size_t);
	int (*update)(drew_mac_t *, const uint8_t *, size_t);
	int (*updatefast)(drew_mac_t *, const uint8_t *, size_t);
	int (*final)(drew_mac_t *, uint8_t *, int);
	int (*test)(void *, const drew_loader_t *);
} drew_mac_functbl2_t;
typedef drew_mac_functbl2_t drew_mac_functbl_t;

struct drew_mac_s {
	void *ctx;
	const drew_mac_functbl_t *functbl;
	void *priv; // unused
};

#endif
