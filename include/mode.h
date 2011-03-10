#ifndef DREW_MODE_INTERFACE_H
#define DREW_MODE_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "block.h"
#include "param.h"
#include "plugin.h"

/* The ABI version of the hash interface. */
#define DREW_MODE_VERSION 0 /* Not implemented. */
/* The number of bytes per quantum. */
#define DREW_MODE_QUANTUM 1 /* Not implemented. */
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_MODE_INTSIZE 2 /* Not implemented. */

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
	int (*fini)(drew_mode_t *, int);
	int (*setpad)(drew_mode_t *, const drew_pad_t *);
	int (*setblock)(drew_mode_t *, const drew_block_t *);
	int (*setiv)(drew_mode_t *, const void *, size_t);
	int (*encrypt)(drew_mode_t *, void *, const void *, size_t);
	int (*decrypt)(drew_mode_t *, void *, const void *, size_t);
	int (*encryptfast)(drew_mode_t *, void *, const void *, size_t);
	int (*decryptfast)(drew_mode_t *, void *, const void *, size_t);
	int (*test)(void *, const drew_loader_t *);
} drew_mode_functbl2_t;

typedef drew_mode_functbl2_t drew_mode_functbl_t;

struct drew_mode_s {
	void *ctx;
	const drew_mode_functbl_t *functbl;
	void *priv; // unused.
};

#endif
