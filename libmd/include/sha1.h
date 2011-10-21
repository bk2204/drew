/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements the SHA1 message digest algorithm.  It is compatible
 * with OpenBSD's implementation.  The size of the SHA1_CTX struct is not
 * guaranteed compatible, however.  This implementation requires ANSI C.
 */

#ifndef BMC_SHA1_H
#define BMC_SHA1_H

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include "hash.h"

#define SHA1_DIGEST_LENGTH 20
#define SHA1_DIGEST_STRING_LENGTH (SHA1_DIGEST_LENGTH*2+1)
#define SHA1_BLOCK_LENGTH 64

DREW_LIBMD_HASH_STRUCT(SHA1_CTX, uint32_t, SHA1_DIGEST_LENGTH, SHA1_BLOCK_LENGTH);

DREW_SYM_PUBLIC
void SHA1Init(SHA1_CTX *ctx);
DREW_SYM_PUBLIC
void SHA1Update(SHA1_CTX *ctx, const uint8_t *data, size_t len);
DREW_SYM_PUBLIC
void SHA1Pad(SHA1_CTX *ctx);
DREW_SYM_PUBLIC
void SHA1Final(uint8_t digest[SHA1_DIGEST_LENGTH], SHA1_CTX *ctx);
DREW_SYM_PUBLIC
void SHA1Transform(uint32_t state[5], const uint8_t block[SHA1_BLOCK_LENGTH]);

DREW_SYM_PUBLIC
char *SHA1End(SHA1_CTX *ctx, char *buf);
DREW_SYM_PUBLIC
char *SHA1File(const char *filename, char *buf);
DREW_SYM_PUBLIC
char *SHA1FileChunk(const char *filename, char *buf, off_t off, off_t len);
DREW_SYM_PUBLIC
char *SHA1Data(const uint8_t *data, size_t len, char *buf);

#endif
