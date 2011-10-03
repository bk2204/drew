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
#ifndef DREW_STREAM_INTERFACE_H
#define DREW_STREAM_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include <drew/drew.h>
#include <drew/param.h>
#include <drew/plugin.h>

/* The ABI version of the hash interface. */
#define DREW_STREAM_VERSION 0 /* Not implemented. */
/* The size of the key in bytes.  If an algorithm has more than one value here,
 * passing the last returned value in *p (an int*) will produce the next largest
 * valid value.  If there are no more valid values, the function will return 0.
 * The first time using this method *p should be 0.
 */
#define DREW_STREAM_KEYSIZE 1
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_STREAM_INTSIZE 2  /* Not implemented. */
/* The size of the IV or nonce in bytes.  The values produced here are handled
 * exactly the same way as for DREW_STREAM_KEYSIZE.  If the algorithm does not
 * permit a nonce, an error will be returned.
 */
#define DREW_STREAM_IVSIZE 3
/* The amount of data processed at once in bytes. */
#define DREW_STREAM_BLKSIZE 4

/* This bit is a flag to the clone function indicating that the new context
 * should be copied into already-existing memory at *newctx.
 */
#define DREW_STREAM_FIXED 1
/* These values are passed to setkey to determine the potential usage of the
 * context.  Set bit 0 to disable decryption and set bit 1 to disable
 * encryption.
 */
#define DREW_STREAM_MODE_BOTH 0
#define DREW_STREAM_MODE_ENCRYPT 1
#define DREW_STREAM_MODE_DECRYPT 2

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(void **, void *, int, drew_loader_t *, const drew_param_t *);
	int (*clone)(void **, void *, int);
	int (*fini)(void **, int);
	int (*setiv)(void *, const uint8_t *, size_t);
	int (*setkey)(void *, const uint8_t *, size_t, int);
	int (*encrypt)(void *, uint8_t *, const uint8_t *, size_t);
	int (*decrypt)(void *, uint8_t *, const uint8_t *, size_t);
	int (*test)(void *, drew_loader_t *);
} drew_stream_functbl1_t;

typedef drew_stream_functbl1_t drew_stream_functbl0_t;

struct drew_stream_s;
typedef struct drew_stream_s drew_stream_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_stream_t *,  int, const drew_loader_t *,
			const drew_param_t *);
	int (*clone)(drew_stream_t *, const drew_stream_t *, int);
	int (*reset)(drew_stream_t *);
	int (*fini)(drew_stream_t *, int);
	int (*setiv)(drew_stream_t *, const uint8_t *, size_t);
	int (*setkey)(drew_stream_t *, const uint8_t *, size_t, int);
	int (*encrypt)(drew_stream_t *, uint8_t *, const uint8_t *, size_t);
	int (*decrypt)(drew_stream_t *, uint8_t *, const uint8_t *, size_t);
	int (*encryptfast)(drew_stream_t *, uint8_t *, const uint8_t *, size_t);
	int (*decryptfast)(drew_stream_t *, uint8_t *, const uint8_t *, size_t);
	int (*test)(void *, const drew_loader_t *);
} drew_stream_functbl2_t;

typedef drew_stream_functbl2_t drew_stream_functbl_t;

struct drew_stream_s {
	void *ctx;
	const drew_stream_functbl_t *functbl;
	void *priv; // unused
};

#endif
