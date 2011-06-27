#ifndef DREW_BIGNUM_INTERFACE_H
#define DREW_BIGNUM_INTERFACE_H

#include <errno.h>
#include <stdint.h>

#include "param.h"
#include "plugin.h"

/* The ABI version of the hash interface. */
#define DREW_BIGNUM_VERSION 0 /* Not implemented. */
/* The size of the underlying implementation's context.  This is useful for the
 * clone function if there's a need to copy the actual context into a given
 * block of memory, such as locked memory.
 */
#define DREW_BIGNUM_INTSIZE 1

/* This bit is a flag indicating that the new context should be copied into
 * already-existing memory at *newctx.
 */
#define DREW_BIGNUM_FIXED  1
/* This bit indicates that the operation should be performed on the absolute
 * value of these quantities.
 */
#define DREW_BIGNUM_ABS 2

struct drew_bignum_s;
typedef struct drew_bignum_s drew_bignum_t;

typedef struct {
	int (*info)(int op, void *p);
	int (*init)(drew_bignum_t *, int, const drew_loader_t *,
			const drew_param_t *);
	int (*clone)(drew_bignum_t *, const drew_bignum_t *, int);
	int (*fini)(drew_bignum_t *, int);
	int (*nbytes)(const drew_bignum_t *);
	// Also return sign.
	int (*bytes)(const drew_bignum_t *, uint8_t *, size_t);
	int (*setbytes)(drew_bignum_t *, const uint8_t *, size_t);
	int (*setzero)(drew_bignum_t *);
	int (*setsmall)(drew_bignum_t *, long);
	int (*negate)(drew_bignum_t *, const drew_bignum_t *);
	int (*abs)(drew_bignum_t *, const drew_bignum_t *);
	int (*compare)(const drew_bignum_t *, const drew_bignum_t *, int);
	// C++ uses "or", "bitor", "and", "bitand", and "xor" as operators, so we
	// can't use those names here.
	int (*bitwiseor)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*bitwiseand)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*bitwisexor)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*bitwisenot)(drew_bignum_t *, const drew_bignum_t *);
	int (*add)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*sub)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*mul)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*div)(drew_bignum_t *, drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*mulpow2)(drew_bignum_t *, const drew_bignum_t *, size_t);
	int (*divpow2)(drew_bignum_t *, drew_bignum_t *, const drew_bignum_t *,
			size_t);
	int (*shiftleft)(drew_bignum_t *, const drew_bignum_t *, size_t);
	int (*shiftright)(drew_bignum_t *, const drew_bignum_t *, size_t);
	int (*square)(drew_bignum_t *, const drew_bignum_t *);
	int (*mod)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *);
	int (*expsmall)(drew_bignum_t *, const drew_bignum_t *, unsigned long);
	int (*expmod)(drew_bignum_t *, const drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*invmod)(drew_bignum_t *, const drew_bignum_t *,
			const drew_bignum_t *);
	int (*test)(void *, const drew_loader_t *);
} drew_bignum_functbl2_t;

typedef drew_bignum_functbl2_t drew_bignum_functbl0_t;
typedef drew_bignum_functbl2_t drew_bignum_functbl1_t;
typedef drew_bignum_functbl2_t drew_bignum_functbl_t;

struct drew_bignum_s {
	void *ctx;
	const drew_bignum_functbl_t *functbl;
	void *priv; // unused
};

#endif
