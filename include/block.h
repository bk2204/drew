#ifndef DREW_BLOCK_INTERFACE_H
#define DREW_BLOCK_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "param.h"
#include "plugin.h"

/* The ABI version of the hash interface. */
#define DREW_BLOCK_VERSION 0 /* Not implemented. */
/* The number of bytes per quantum. */
#define DREW_BLOCK_QUANTUM 1 /* Not implemented. */
/* The size of the block in bytes. */
#define DREW_BLOCK_BLKSIZE 2
/* The size of the key in bytes.  If an algorithm has more than one value here,
 * passing the last returned value in *p (an int*) will produce the next largest
 * valid value.  If there are no more valid values, the function will return 0.
 * The first time using this method *p should be 0.
 */
#define DREW_BLOCK_KEYSIZE 3
/* The endianness of this block cipher.  0x1234 is big-endian and 0x4321 is
 * little-endian.
 */
#define DREW_BLOCK_ENDIAN 4 /* Not implemented. */
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_BLOCK_INTSIZE 5  /* Not implemented. */

/* This bit is a flag to the clone function indicating that the new context
 * should be copied into already-existing memory at *newctx.
 */
#define DREW_BLOCK_CLONE_FIXED 1

typedef struct {
	int (*info)(int op, void *p);
	void (*init)(void **, drew_loader_t *, const drew_param_t *);
	int (*setkey)(void *, const uint8_t *, size_t);
	void (*encrypt)(void *, uint8_t *, const uint8_t *);
	void (*decrypt)(void *, uint8_t *, const uint8_t *);
	int (*test)(void *);
	void (*fini)(void **);
	int (*clone)(void **, void *, int);
} drew_block_functbl_t;

#endif
