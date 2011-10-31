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
#ifndef DREW_MODE_INTERFACE_H
#define DREW_MODE_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include <drew/block.h>
#include <drew/drew.h>
#include <drew/param.h>
#include <drew/plugin.h>

#define DREW_MODE_ALIGNMENT 16
#if DREW_BLOCK_ALIGNMENT != DREW_MODE_ALIGNMENT
#error "mismatched alignment values"
#endif

/* The ABI version of the mode interface. */
#define DREW_MODE_VERSION 0
/* The number of bytes per quantum. */
#define DREW_MODE_QUANTUM 1 /* Not implemented in version 3 and later. */
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_MODE_INTSIZE 2
/* The number of bytes to pass as input to the final method instead of to the
 * normal one.
 */
#define DREW_MODE_FINAL_INSIZE 3
/* The number of bytes required for output from the final method. */
#define DREW_MODE_FINAL_OUTSIZE 4

/* This bit indicates that the ctx member of drew_mode_t is externally
 * allocated and sufficiently large.
 */
#define DREW_MODE_FIXED 1

typedef struct {
	int (*info)(int op, void *p);
	void (*init)(void **, drew_loader_t *, const drew_param_t *);
	int (*setpad)(void *, const char *, void *);
	int (*setblock)(void *, const char *, void *);
	int (*setiv)(void *, const uint8_t *, size_t);
	void (*encrypt)(void *, uint8_t *, const uint8_t *, size_t);
	void (*decrypt)(void *, uint8_t *, const uint8_t *, size_t);
	int (*test)(void *);
	void (*fini)(void **);
	int (*clone)(void **, void *, int);
} drew_mode_functbl0_t;

struct drew_mode_s;
typedef struct drew_mode_s drew_mode_t;

/* This is temporary. */
typedef void drew_pad_t;

/* This is version 2.  Version 1 never ended up being developed and it has been
 * skipped for compatibility with other interfaces.
 */
typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_mode_t *, int, const drew_loader_t *,
			const drew_param_t *);
	int (*clone)(drew_mode_t *, const drew_mode_t *, int);
	int (*reset)(drew_mode_t *);
	int (*fini)(drew_mode_t *, int);
	int (*setpad)(drew_mode_t *, const drew_pad_t *);
	int (*setblock)(drew_mode_t *, const drew_block_t *);
	int (*setiv)(drew_mode_t *, const uint8_t *, size_t);
	int (*encrypt)(drew_mode_t *, uint8_t *, const uint8_t *, size_t);
	int (*decrypt)(drew_mode_t *, uint8_t *, const uint8_t *, size_t);
	int (*encryptfast)(drew_mode_t *, uint8_t *, const uint8_t *, size_t);
	int (*decryptfast)(drew_mode_t *, uint8_t *, const uint8_t *, size_t);
	int (*setdata)(drew_mode_t *, const uint8_t *, size_t);
	int (*encryptfinal)(drew_mode_t *, uint8_t *, size_t, const uint8_t *,
			size_t);
	int (*decryptfinal)(drew_mode_t *, uint8_t *, size_t, const uint8_t *,
			size_t);
	int (*test)(void *, const drew_loader_t *);
} drew_mode_functbl2_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*info2)(int op, void *, const void *);
	int (*init)(drew_mode_t *, int, const drew_loader_t *,
			const drew_param_t *);
	int (*clone)(drew_mode_t *, const drew_mode_t *, int);
	int (*reset)(drew_mode_t *);
	int (*fini)(drew_mode_t *, int);
	int (*setblock)(drew_mode_t *, const drew_block_t *);
	int (*setiv)(drew_mode_t *, const uint8_t *, size_t);
	int (*resync)(drew_mode_t *);
	int (*encrypt)(drew_mode_t *, uint8_t *, const uint8_t *, size_t);
	int (*decrypt)(drew_mode_t *, uint8_t *, const uint8_t *, size_t);
	int (*encryptfast)(drew_mode_t *, uint8_t *, const uint8_t *, size_t);
	int (*decryptfast)(drew_mode_t *, uint8_t *, const uint8_t *, size_t);
	int (*setdata)(drew_mode_t *, const uint8_t *, size_t);
	int (*encryptfinal)(drew_mode_t *, uint8_t *, size_t, const uint8_t *,
			size_t);
	int (*decryptfinal)(drew_mode_t *, uint8_t *, size_t, const uint8_t *,
			size_t);
	int (*test)(void *, const drew_loader_t *);
} drew_mode_functbl3_t;

typedef drew_mode_functbl2_t drew_mode_functbl_t;

struct drew_mode_s {
	void *ctx;
	const drew_mode_functbl_t *functbl;
	void *priv; // unused.
};

#endif
