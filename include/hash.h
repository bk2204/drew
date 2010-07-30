#ifndef DREW_HASH_INTERFACE_H
#define DREW_HASH_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "param.h"
#include "plugin.h"

/* The ABI version of the hash interface. */
#define DREW_HASH_VERSION 0 /* Not implemented. */
/* The number of bytes per quantum. */
#define DREW_HASH_QUANTUM 1
/* The length of the final hash in bytes. */
#define DREW_HASH_SIZE 2
/* The size of the block in bytes. */
#define DREW_HASH_BLKSIZE 3
/* The size of the internal variables in bytes.  Note that this includes only
 * the variables that make up the state passed to Transform functions.  It does
 * not include other data stored in the context.
 */
#define DREW_HASH_BUFSIZE 4 /* Not implemented. */
/* The endianness of this hash algorithm.  0x1234 is big-endian and 0x4321 is
 * little-endian.
 */
#define DREW_HASH_ENDIAN 5 /* Not implemented. */

typedef struct {
	int (*info)(int op, void *p);
	void (*init)(void **, drew_loader_t *, const drew_param_t *);
	void (*update)(void *, const uint8_t *, size_t);
	void (*pad)(void *);
	void (*final)(void *, uint8_t *);
	void (*transform)(void *, void *, const uint8_t *);
	int (*test)(void *);
	void (*fini)(void **);
} drew_hash_functbl_t;

#endif
