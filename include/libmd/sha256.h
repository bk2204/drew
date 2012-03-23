/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements the SHA256 and SHA224 message digest algorithms.  It is
 * compatible with OpenBSD's implementation.  The size of the SHA2_CTX struct
 * is not guaranteed compatible, however.  This implementation requires ANSI C.
 */

#ifndef BMC_SHA256_H
#define BMC_SHA256_H

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include "hash.h"

#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_STRING_LENGTH (SHA256_DIGEST_LENGTH*2+1)
#define SHA256_BLOCK_LENGTH 64

DREW_LIBMD_HASH_STRUCT(SHA2_CTX, uint32_t, SHA256_DIGEST_LENGTH, SHA256_BLOCK_LENGTH);
typedef SHA2_CTX SHA256_CTX;

DREW_SYM_PUBLIC
void SHA256Init(SHA2_CTX *ctx);
DREW_SYM_PUBLIC
void SHA256Update(SHA2_CTX *ctx, const uint8_t *data, size_t len);
DREW_SYM_PUBLIC
void SHA256Pad(SHA2_CTX *ctx);
DREW_SYM_PUBLIC
void SHA256Final(uint8_t digest[SHA256_DIGEST_LENGTH], SHA2_CTX *ctx);
DREW_SYM_PUBLIC
void SHA256Transform(uint32_t *state, const uint8_t block[SHA256_BLOCK_LENGTH]);

DREW_SYM_PUBLIC
char *SHA256End(SHA2_CTX *ctx, char *buf);
DREW_SYM_PUBLIC
char *SHA256File(const char *filename, char *buf);
DREW_SYM_PUBLIC
char *SHA256FileChunk(const char *filename, char *buf, off_t off, off_t len);
DREW_SYM_PUBLIC
char *SHA256Data(const uint8_t *data, size_t len, char *buf);

DREW_SYM_PUBLIC
void SHA256_Init(SHA256_CTX *ctx);
DREW_SYM_PUBLIC
void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
DREW_SYM_PUBLIC
void SHA256_Pad(SHA256_CTX *ctx);
DREW_SYM_PUBLIC
void SHA256_Final(uint8_t digest[SHA256_DIGEST_LENGTH], SHA256_CTX *ctx);
DREW_SYM_PUBLIC
void SHA256_Transform(uint32_t *state,
		const uint8_t block[SHA256_BLOCK_LENGTH]);

DREW_SYM_PUBLIC
char *SHA256_End(SHA256_CTX *ctx, char *buf);
DREW_SYM_PUBLIC
char *SHA256_File(const char *filename, char *buf);
DREW_SYM_PUBLIC
char *SHA256_FileChunk(const char *filename, char *buf, off_t off, off_t len);
DREW_SYM_PUBLIC
char *SHA256_Data(const uint8_t *data, size_t len, char *buf);

#endif
