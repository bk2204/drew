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
/* The endianness of this hash algorithm.  4321 is big-endian and 1234 is
 * little-endian.
 */
#define DREW_HASH_ENDIAN 5 /* Not implemented. */
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_HASH_INTSIZE 6

/* This bit indicates that the ctx member of drew_hash_t is externally
 * allocated and sufficiently large.
 */
#define DREW_HASH_FIXED 1
/* This bit is a flag indicating that the context has already been padded and so
 * pad should not be called again.
 */
#define DREW_HASH_NO_PAD 2

typedef struct {
	int (*info)(int op, void *p);
	void (*init)(void **, drew_loader_t *, const drew_param_t *);
	void (*update)(void *, const uint8_t *, size_t);
	void (*pad)(void *);
	void (*final)(void *, uint8_t *);
	void (*transform)(void *, void *, const uint8_t *);
	int (*test)(void *);
	void (*fini)(void **);
	int (*clone)(void **, void *, int);
} drew_hash_functbl0_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(void **, void *, int, drew_loader_t *, const drew_param_t *);
	int (*clone)(void **, void *, int);
	int (*fini)(void **, int);
	int (*update)(void *, const uint8_t *, size_t);
	int (*pad)(void *);
	int (*final)(void *, uint8_t *, int);
	int (*transform)(void *, void *, const uint8_t *);
	int (*test)(void *, drew_loader_t *);
} drew_hash_functbl1_t;

struct drew_hash_s;
typedef struct drew_hash_s drew_hash_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_hash_t *, int, const drew_loader_t *,
			const drew_param_t *);
	int (*clone)(drew_hash_t *, const drew_hash_t *, int);
	int (*fini)(drew_hash_t *, int);
	int (*update)(drew_hash_t *, const uint8_t *, size_t);
	int (*updatefast)(drew_hash_t *, const uint8_t *, size_t);
	int (*pad)(drew_hash_t *);
	int (*final)(drew_hash_t *, uint8_t *, int);
	int (*transform)(const drew_hash_t *, void *, const uint8_t *);
	int (*test)(void *, const drew_loader_t *);
} drew_hash_functbl2_t;

typedef drew_hash_functbl2_t drew_hash_functbl_t;

struct drew_hash_s {
	void *ctx;
	const drew_hash_functbl_t *functbl;
	void *priv;  // unused
};

#endif
