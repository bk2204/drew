#ifndef DREW_PKENC_INTERFACE_H
#define DREW_PKENC_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "param.h"
#include "plugin.h"
#include "bignum.h"

/* The ABI version of the hash interface. */
#define DREW_PKENC_VERSION 0
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_PKENC_INTSIZE 1
/* The number of bignums that make up a plaintext message.  */
#define DREW_PKENC_PLAIN_BIGNUMS 2
/* The number of bignums that make up a ciphertext message.  */
#define DREW_PKENC_CIPHER_BIGNUMS 3

/* This bit indicates that the ctx member of drew_pkenc_t is externally
 * allocated and sufficiently large.
 */
#define DREW_PKENC_FIXED 1

#define DREW_PKENC_MODE_ENCRYPT 1
#define DREW_PKENC_MODE_DECRYPT 2

struct drew_pkenc_s;
typedef struct drew_pkenc_s drew_pkenc_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_pkenc_t *, int,
			const drew_loader_t *, const drew_param_t *);
	int (*clone)(drew_pkenc_t *, const drew_pkenc_t *, int);
	int (*fini)(drew_pkenc_t *, int);
	int (*generate)(drew_pkenc_t *, const drew_param_t *);
	int (*setmode)(drew_pkenc_t *, int);
	int (*setval)(drew_pkenc_t *, const char *, const uint8_t *, size_t);
	int (*val)(const drew_pkenc_t *, const char *, uint8_t *, size_t);
	int (*valsize)(const drew_pkenc_t *, const char *);
	int (*encrypt)(const drew_pkenc_t *, drew_bignum_t *,
			const drew_bignum_t *);
	int (*decrypt)(const drew_pkenc_t *, drew_bignum_t *,
			const drew_bignum_t *);
	int (*test)(void *, const drew_loader_t *);
} drew_pkenc_functbl2_t;

typedef drew_pkenc_functbl2_t drew_pkenc_functbl0_t;
typedef drew_pkenc_functbl2_t drew_pkenc_functbl1_t;
typedef drew_pkenc_functbl2_t drew_pkenc_functbl_t;

struct drew_pkenc_s {
	void *ctx;
	const drew_pkenc_functbl_t *functbl;
	void *priv; // unused
};

#endif
