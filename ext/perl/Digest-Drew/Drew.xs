#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <stdint.h>

#include "src/drew.c"

MODULE = Digest::Drew		PACKAGE = Digest::Drew		

PROTOTYPES: ENABLE

drew_hash_t *
ctx_new(algoname)
	char *algoname

void
ctx_destroy(ctx)
	drew_hash_t *ctx

drew_hash_t *
ctx_clone(ctx)
	drew_hash_t *ctx

void
add(self)
	SV *self
PREINIT:
	int i;
	uint8_t *buf;
	STRLEN len;
	drew_hash_t *ctx;
PPCODE:
	ctx = (drew_hash_t *)SvIV(SvRV(SvRV(self)));
	for (i = 1; i < items; i++) {
		buf = (uint8_t *)SvPV(ST(i), len);
		ctx->functbl->update(ctx, buf, len);
	}
	XSRETURN(1);
