/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements the RIPEMD-160 message digest algorithm.  It is
 * compatible with OpenBSD's implementation.  The size of the RMD160_CTX struct
 * is not guaranteed compatible, however.  This implementation requires ANSI C.
 */

#ifndef BMC_RMD160_H
#define BMC_RMD160_H

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include "hash.h"

#define RMD160_DIGEST_LENGTH 20
#define RMD160_DIGEST_STRING_LENGTH (RMD160_DIGEST_LENGTH*2+1)
#define RMD160_BLOCK_LENGTH 64

#define RIPEMD160_DIGEST_LENGTH RMD160_DIGEST_LENGTH
#define RIPEMD160_DIGEST_STRING_LENGTH RMD160_DIGEST_LENGTH
#define RIPEMD160_BLOCK_LENGTH RMD160_BLOCK_LENGTH

DREW_LIBMD_HASH_STRUCT(RMD160_CTX, uint32_t, RMD160_DIGEST_LENGTH, RMD160_BLOCK_LENGTH);
typedef RMD160_CTX RIPEMD160_CTX;

DREW_SYM_PUBLIC
void RMD160Init(RMD160_CTX *ctx);
DREW_SYM_PUBLIC
void RMD160Update(RMD160_CTX *ctx, const uint8_t *data, size_t len);
DREW_SYM_PUBLIC
void RMD160Pad(RMD160_CTX *ctx);
DREW_SYM_PUBLIC
void RMD160Final(uint8_t digest[RMD160_DIGEST_LENGTH], RMD160_CTX *ctx);
DREW_SYM_PUBLIC
void RMD160Transform(uint32_t state[5],
		const uint8_t block[RMD160_BLOCK_LENGTH]);

DREW_SYM_PUBLIC
char *RMD160End(RMD160_CTX *ctx, char *buf);
DREW_SYM_PUBLIC
char *RMD160File(const char *filename, char *buf);
DREW_SYM_PUBLIC
char *RMD160FileChunk(const char *filename, char *buf, off_t off, off_t len);
DREW_SYM_PUBLIC
char *RMD160Data(const uint8_t *data, size_t len, char *buf);

void RIPEMD160_Init(RIPEMD160_CTX *ctx);
DREW_SYM_PUBLIC
void RIPEMD160_Update(RIPEMD160_CTX *ctx, const uint8_t *data, size_t len);
DREW_SYM_PUBLIC
void RIPEMD160_Pad(RIPEMD160_CTX *ctx);
DREW_SYM_PUBLIC
void RIPEMD160_Final(uint8_t digest[RIPEMD160_DIGEST_LENGTH],
		RIPEMD160_CTX *ctx);
DREW_SYM_PUBLIC
void RIPEMD160_Transform(uint32_t state[5],
		const uint8_t block[RIPEMD160_BLOCK_LENGTH]);

DREW_SYM_PUBLIC
char *RIPEMD160_End(RIPEMD160_CTX *ctx, char *buf);
DREW_SYM_PUBLIC
char *RIPEMD160_File(const char *filename, char *buf);
DREW_SYM_PUBLIC
char *RIPEMD160_FileChunk(const char *filename, char *buf, off_t off,
		off_t len);
DREW_SYM_PUBLIC
char *RIPEMD160_Data(const uint8_t *data, size_t len, char *buf);

#endif
