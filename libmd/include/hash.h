/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements generic hash contexts.  This implementation
 * requires ANSI C.
 */

#ifndef BMC_HASH_H
#define BMC_HASH_H

#include <stddef.h>
#include <stdint.h>

#define HASH_MAX_DIGEST_LENGTH 32
#define HASH_MAX_BLOCK_LENGTH 64

typedef struct
{
	uint32_t hash[HASH_MAX_DIGEST_LENGTH/sizeof(uint32_t)];
	uint32_t len[2]; /* length in bytes */
	uint8_t buf[HASH_MAX_BLOCK_LENGTH];
	size_t off;
} hash_ctx_t;

#endif
