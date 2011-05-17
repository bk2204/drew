#ifndef DREW_BLOCK_INTERFACE_H
#define DREW_BLOCK_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "param.h"
#include "plugin.h"

#define DREW_BLOCK_ALIGNMENT 16

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

/* This bit indicates that the ctx member of drew_block_t is externally
 * allocated and sufficiently large.
 */
#define DREW_BLOCK_FIXED 1
/* These values are passed to setkey to determine the potential usage of the
 * context.  Set bit 0 to disable decryption and set bit 1 to disable
 * encryption.
 */
#define DREW_BLOCK_MODE_BOTH 0
#define DREW_BLOCK_MODE_ENCRYPT 1
#define DREW_BLOCK_MODE_DECRYPT 2

typedef struct {
	int (*info)(int op, void *p);
	void (*init)(void **, drew_loader_t *, const drew_param_t *);
	int (*setkey)(void *, const uint8_t *, size_t);
	void (*encrypt)(void *, uint8_t *, const uint8_t *);
	void (*decrypt)(void *, uint8_t *, const uint8_t *);
	int (*test)(void *);
	void (*fini)(void **);
	int (*clone)(void **, void *, int);
} drew_block_functbl0_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(void **, void *, int, drew_loader_t *, const drew_param_t *);
	int (*clone)(void **, void *, int);
	int (*fini)(void **, int);
	int (*setkey)(void *, const uint8_t *, size_t, int);
	int (*encrypt)(void *, uint8_t *, const uint8_t *);
	int (*decrypt)(void *, uint8_t *, const uint8_t *);
	int (*test)(void *, drew_loader_t *);
} drew_block_functbl1_t;

struct drew_block_s;
typedef struct drew_block_s drew_block_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_block_t *, int,
			const drew_loader_t *, const drew_param_t *);
	int (*clone)(drew_block_t *, const drew_block_t *, int);
	int (*reset)(drew_block_t *);
	int (*fini)(drew_block_t *, int);
	int (*setkey)(drew_block_t *, const uint8_t *, size_t, int);
	int (*encrypt)(const drew_block_t *, uint8_t *, const uint8_t *);
	int (*decrypt)(const drew_block_t *, uint8_t *, const uint8_t *);
	int (*encryptfast)(const drew_block_t *, uint8_t *, const uint8_t *,
			size_t);
	int (*decryptfast)(const drew_block_t *, uint8_t *, const uint8_t *,
			size_t);
	int (*test)(void *, const drew_loader_t *);
} drew_block_functbl2_t;

typedef drew_block_functbl2_t drew_block_functbl_t;

struct drew_block_s {
	void *ctx;
	const drew_block_functbl_t *functbl;
	void *priv; // unused
};

#endif
