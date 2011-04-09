#ifndef DREW_PKSIG_INTERFACE_H
#define DREW_PKSIG_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "bignum.h"
#include "param.h"
#include "plugin.h"

/* The ABI version of the pksig interface. */
#define DREW_PKSIG_VERSION 0 /* Not implemented. */
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_PKSIG_INTSIZE 1  /* Not implemented. */
/* The number of bignums that make up a plaintext message.  */
#define DREW_PKSIG_PLAIN_BIGNUMS 2
/* The number of bignums that make up a ciphertext message.  */
#define DREW_PKSIG_CIPHER_BIGNUMS 3

/* This bit indicates that the ctx member of drew_pksig_t is externally
 * allocated and sufficiently large.
 */
#define DREW_PKSIG_FIXED 1

#define DREW_PKSIG_MODE_SIGN 1
#define DREW_PKSIG_MODE_VERIFY 2

struct drew_pksig_s;
typedef struct drew_pksig_s drew_pksig_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_pksig_t *, int,
			const drew_loader_t *, const drew_param_t *);
	int (*clone)(drew_pksig_t *, const drew_pksig_t *, int);
	int (*fini)(drew_pksig_t *, int);
	int (*generate)(drew_pksig_t *, const drew_param_t *);
	int (*setmode)(drew_pksig_t *, int);
	int (*setval)(drew_pksig_t *, const char *, const uint8_t *, size_t);
	int (*val)(const drew_pksig_t *, const char *, uint8_t *, size_t);
	int (*valsize)(const drew_pksig_t *, const char *);
	int (*sign)(const drew_pksig_t *, drew_bignum_t *, const drew_bignum_t *);
	int (*verify)(const drew_pksig_t *, drew_bignum_t *, const drew_bignum_t *);
	int (*test)(void *, const drew_loader_t *);
} drew_pksig_functbl2_t;

typedef drew_pksig_functbl2_t drew_pksig_functbl0_t;
typedef drew_pksig_functbl2_t drew_pksig_functbl1_t;
typedef drew_pksig_functbl2_t drew_pksig_functbl_t;

struct drew_pksig_s {
	void *ctx;
	const drew_pksig_functbl_t *functbl;
	void *priv; // unused
};

#endif
