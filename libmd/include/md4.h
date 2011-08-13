/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements the MD4 message digest algorithm.  It is compatible with
 * RSA's implementation, as well as OpenBSD's implementation.  The size of the
 * MD4_CTX struct is not guaranteed compatible, however.  This implementation
 * requires ANSI C.
 */

#ifndef BMC_MD4_H
#define BMC_MD4_H

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include "hash.h"

#define MD4_DIGEST_LENGTH 16
#define MD4_DIGEST_STRING_LENGTH (MD4_DIGEST_LENGTH*2+1)
#define MD4_BLOCK_LENGTH 64

DREW_LIBMD_HASH_STRUCT(MD4_CTX, uint32_t, MD4_DIGEST_LENGTH, MD4_BLOCK_LENGTH);

DREW_SYM_PUBLIC
void MD4Init(MD4_CTX *ctx);
DREW_SYM_PUBLIC
void MD4Update(MD4_CTX *ctx, const uint8_t *data, size_t len);
DREW_SYM_PUBLIC
void MD4Pad(MD4_CTX *ctx);
DREW_SYM_PUBLIC
void MD4Final(uint8_t digest[MD4_DIGEST_LENGTH], MD4_CTX *ctx);
DREW_SYM_PUBLIC
void MD4Transform(uint32_t state[4], const uint8_t block[MD4_BLOCK_LENGTH]);

DREW_SYM_PUBLIC
char *MD4End(MD4_CTX *ctx, char *buf);
DREW_SYM_PUBLIC
char *MD4File(const char *filename, char *buf);
DREW_SYM_PUBLIC
char *MD4FileChunk(const char *filename, char *buf, off_t off, off_t len);
DREW_SYM_PUBLIC
char *MD4Data(const uint8_t *data, size_t len, char *buf);

#endif
