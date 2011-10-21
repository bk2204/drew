/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements the MD5 message digest algorithm.  It is compatible with
 * RSA's implementation, as well as OpenBSD's implementation.  The size of the
 * MD5_CTX struct is not guaranteed compatible, however.  This implementation
 * requires ANSI C.
 */

#ifndef BMC_MD5_H
#define BMC_MD5_H

#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "hash.h"

#define MD5_DIGEST_LENGTH 16
#define MD5_DIGEST_STRING_LENGTH (MD5_DIGEST_LENGTH*2+1)
#define MD5_BLOCK_LENGTH 64

DREW_LIBMD_HASH_STRUCT(MD5_CTX, uint32_t, MD5_DIGEST_LENGTH, MD5_BLOCK_LENGTH);

DREW_SYM_PUBLIC
void MD5Init(MD5_CTX *ctx);
DREW_SYM_PUBLIC
void MD5Update(MD5_CTX *ctx, const uint8_t *data, size_t len);
DREW_SYM_PUBLIC
void MD5Pad(MD5_CTX *ctx);
DREW_SYM_PUBLIC
void MD5Final(uint8_t digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx);
DREW_SYM_PUBLIC
void MD5Transform(uint32_t state[4], const uint8_t block[MD5_BLOCK_LENGTH]);

DREW_SYM_PUBLIC
char *MD5End(MD5_CTX *ctx, char *buf);
DREW_SYM_PUBLIC
char *MD5File(const char *filename, char *buf);
DREW_SYM_PUBLIC
char *MD5FileChunk(const char *filename, char *buf, off_t off, off_t len);
DREW_SYM_PUBLIC
char *MD5Data(const uint8_t *data, size_t len, char *buf);

#endif
