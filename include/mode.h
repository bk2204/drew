#ifndef DREW_MODE_INTERFACE_H
#define DREW_MODE_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "param.h"
#include "plugin.h"

/* The ABI version of the hash interface. */
#define DREW_MODE_VERSION 0 /* Not implemented. */
/* The number of bytes per quantum. */
#define DREW_MODE_QUANTUM 1 /* Not implemented. */

/* This bit is a flag to the clone function indicating that the new context
 * should be copied into already-existing memory at *newctx.
 */
#define DREW_MODE_CLONE_FIXED 1

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
} drew_mode_functbl_t;

#endif
