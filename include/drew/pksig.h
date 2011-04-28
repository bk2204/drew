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

#define DREW__PKSIG_COMBINE(b) DREW__PKSIG_ ## b
#define DREW__PKSIG_VAL(sv, io, type) \
	(DREW__PKSIG_PSTART | \
	 DREW__PKSIG_COMBINE(sv) | \
	 DREW__PKSIG_COMBINE(io) | \
	 DREW__PKSIG_COMBINE(type))
#define DREW__PKSIG_PSTART 16
#define DREW__PKSIG_SIGN 0
#define DREW__PKSIG_VERIFY 1
#define DREW__PKSIG_IN 0
#define DREW__PKSIG_OUT 2
#define DREW__PKSIG_COUNT 0
#define DREW__PKSIG_N2I 4
#define DREW__PKSIG_I2N 8

#define DREW_PKSIG_SIGN_IN DREW__PKSIG_VAL(SIGN, IN, COUNT)
#define DREW_PKSIG_SIGN_OUT DREW__PKSIG_VAL(SIGN, OUT, COUNT)
#define DREW_PKSIG_VERIFY_IN DREW__PKSIG_VAL(VERIFY, IN, COUNT)
#define DREW_PKSIG_VERIFY_OUT DREW__PKSIG_VAL(VERIFY, OUT, COUNT)
#define DREW_PKSIG_SIGN_IN_NAME_TO_INDEX DREW__PKSIG_VAL(SIGN, IN, N2I)
#define DREW_PKSIG_SIGN_OUT_NAME_TO_INDEX DREW__PKSIG_VAL(SIGN, OUT, N2I)
#define DREW_PKSIG_VERIFY_IN_NAME_TO_INDEX DREW__PKSIG_VAL(VERIFY, IN, N2I)
#define DREW_PKSIG_VERIFY_OUT_NAME_TO_INDEX DREW__PKSIG_VAL(VERIFY, OUT, N2I)
#define DREW_PKSIG_SIGN_IN_INDEX_TO_NAME DREW__PKSIG_VAL(SIGN, IN, I2N)
#define DREW_PKSIG_SIGN_OUT_INDEX_TO_NAME DREW__PKSIG_VAL(SIGN, OUT, I2N)
#define DREW_PKSIG_VERIFY_IN_INDEX_TO_NAME DREW__PKSIG_VAL(VERIFY, IN, I2N)
#define DREW_PKSIG_VERIFY_OUT_INDEX_TO_NAME DREW__PKSIG_VAL(VERIFY, OUT, I2N)

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
