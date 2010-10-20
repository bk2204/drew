#ifndef DREW_STREAM_INTERFACE_H
#define DREW_STREAM_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "param.h"
#include "plugin.h"

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

/* This bit is a flag to the clone function indicating that the new context
 * should be copied into already-existing memory at *newctx.
 */
#define DREW_STREAM_INIT_FIXED 1
#define DREW_STREAM_CLONE_FIXED 1
#define DREW_STREAM_FINI_NO_DEALLOC 1
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
	int (*setkey)(void *, const uint8_t *, size_t, int);
	int (*encrypt)(void *, uint8_t *, const uint8_t *, size_t);
	int (*decrypt)(void *, uint8_t *, const uint8_t *, size_t);
	int (*test)(void *, drew_loader_t *);
} drew_stream_functbl1_t;

typedef drew_stream_functbl1_t drew_stream_functbl0_t;
typedef drew_stream_functbl1_t drew_stream_functbl_t;

#endif
