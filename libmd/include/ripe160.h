/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
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

typedef hash_ctx_t RMD160_CTX;

void RMD160Init(RMD160_CTX *ctx);
void RMD160Update(RMD160_CTX *ctx, const uint8_t *data, size_t len);
void RMD160Pad(RMD160_CTX *ctx);
void RMD160Final(uint8_t digest[RMD160_DIGEST_LENGTH], RMD160_CTX *ctx);
void RMD160Transform(uint32_t state[5],
		const uint8_t block[RMD160_BLOCK_LENGTH]);

char *RMD160End(RMD160_CTX *ctx, char *buf);
char *RMD160File(const char *filename, char *buf);
char *RMD160FileChunk(const char *filename, char *buf, off_t off, off_t len);
char *RMD160Data(const uint8_t *data, size_t len, char *buf);

#endif
