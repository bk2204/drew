/* This implements key derivation functions, password-based key derivation
 * functions, and pseudo-random functions.
 */
#ifndef DREW_KDF_INTERFACE_H
#define DREW_KDF_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "param.h"
#include "plugin.h"

/* The ABI version of the hash interface. */
#define DREW_KDF_VERSION 0 /* Not implemented. */
/* The length of the final KDF in bytes. */
#define DREW_KDF_SIZE 1
/* The size of the block in bytes. */
#define DREW_KDF_BLKSIZE 2
/* The endianness of this KDF algorithm.  4321 is big-endian and 1234 is
 * little-endian.
 */
#define DREW_KDF_ENDIAN 3 /* Not implemented. */
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_KDF_INTSIZE 4

/* This bit is a flag indicating that the new context should be copied into
 * already-existing memory at *newctx.
 */
#define DREW_KDF_FIXED  1

struct drew_kdf_s;
typedef struct drew_kdf_s drew_kdf_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_kdf_t *, int, const drew_loader_t *, const drew_param_t *);
	int (*clone)(drew_kdf_t *, const drew_kdf_t *, int);
	int (*reset)(drew_kdf_t *);
	int (*fini)(drew_kdf_t *, int);
	int (*setkey)(drew_kdf_t *, const uint8_t *, size_t);
	int (*setsalt)(drew_kdf_t *, const uint8_t *, size_t);
	int (*setcount)(drew_kdf_t *, size_t);
	int (*generate)(drew_kdf_t *, uint8_t *, size_t, const uint8_t *, size_t);
	int (*test)(void *, const drew_loader_t *);
} drew_kdf_functbl2_t;
typedef drew_kdf_functbl2_t drew_kdf_functbl0_t;
typedef drew_kdf_functbl2_t drew_kdf_functbl1_t;
typedef drew_kdf_functbl2_t drew_kdf_functbl_t;

struct drew_kdf_s {
	void *ctx;
	const drew_kdf_functbl_t *functbl;
	void *priv; // unused
};

#endif
