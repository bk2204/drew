#ifndef DREW_PRNG_INTERFACE_H
#define DREW_PRNG_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "param.h"
#include "plugin.h"

/* The ABI version of the hash interface. */
#define DREW_PRNG_VERSION 0 /* Not implemented. */
/* The size of the internal state in bytes.  This is not guaranteed to be
 * available.
 */
#define DREW_PRNG_BLKSIZE 1
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_PRNG_INTSIZE 2
/* This value is true if the generator must be seeded before use. */
#define DREW_PRNG_SEEDABLE 3
/* This value is true if the generator blocks when entropy is exhausted. */
#define DREW_PRNG_BLOCKING 4
/* The number of *bits* of entropy remaining in the pool, if available. */
#define DREW_PRNG_ENTROPY 5

/* This bit is a flag indicating that the new context should be copied into
 * already-existing memory at *newctx.
 */
#define DREW_PRNG_INIT_FIXED  1
#define DREW_PRNG_CLONE_FIXED 1
/* This bit is a flag indicating that the memory storing the context should not
 * be freed because the context was created with INIT_FIXED or CLONE_FIXED.
 */
#define DREW_PRNG_FINI_NO_DEALLOC 1

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(void **, void *, int, drew_loader_t *, const drew_param_t *);
	int (*clone)(void **, void *, int);
	int (*fini)(void **, int);
	int (*seed)(void *, const uint8_t *, size_t, size_t);
	int (*bytes)(void *, uint8_t *, size_t);
	int (*test)(void *, drew_loader_t *);
} drew_prng_functbl0_t;
typedef drew_prng_functbl0_t drew_prng_functbl1_t;
typedef drew_prng_functbl1_t drew_prng_functbl_t;

#endif
