#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "src/drew.c"

MODULE = Digest::Drew		PACKAGE = Digest::Drew		

drew_hash_t *
ctx_new(algoname)
	char *algoname

void
ctx_destroy(ctx)
	drew_hash_t *ctx

drew_hash_t *
ctx_clone(ctx)
	drew_hash_t *ctx
