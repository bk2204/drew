#ifndef SIG_H
#define SIG_H

#include "internal.h"

#include <drew/drew.h>
#include <drew/hash.h>
#include <drew/plugin.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/key.h>
#include <drew-opgp/parser.h>

#define PREFS_CIPHER	0
#define PREFS_HASH		1
#define PREFS_COMPRESS	2

struct drew_opgp_prefs_s {
	uint8_t type;
	size_t len;
	uint8_t vals[16];
};

struct drew_opgp_self_sig_s {
	int keyflags;
	bool primary;
	time_t keyexp;
	drew_opgp_prefs_t prefs[3];
};

struct drew_opgp_s {
	const drew_loader_t *ldr;
	drew_prng_t prng;
	int64_t standards;
};

typedef struct drew_opgp_self_sig_s selfsig_t;

typedef struct drew_opgp_signature_s csig_t;
typedef struct drew_opgp_key_s ckey_t;
typedef struct drew_opgp_uid_s cuid_t;

#define MAX_BLOCK_BLKSIZE 16
#define MAX_BLOCK_KEYSIZE 32

#define MAX_DIGEST_SIZE (512/8)
#define MAX_HASHES 12

#endif
