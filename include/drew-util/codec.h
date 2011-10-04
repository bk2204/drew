#ifndef DREW_UTIL_CODEC_H
#define DREW_UTIL_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <drew/drew.h>

struct drew_util_codec_s;

typedef struct drew_util_codec_s *drew_util_codec_t;

#define DREW_UTIL_CODEC_CAT_UNKNOWN		0
#define DREW_UTIL_CODEC_CAT_OPENPGP		1
#define DREW_UTIL_CODEC_CAT_X509		2
#define DREW_UTIL_CODEC_CAT_SECSH		3

#define DREW_UTIL_CODEC_UNENCODED		0

#define DREW_UTIL_CODEC_ENC_X509_PEM	1
#define DREW_UTIL_CODEC_ENC_X509_NET	2

#define DREW_UTIL_CODEC_TYPE_PUBKEY		1
#define DREW_UTIL_CODEC_TYPE_PRIVKEY	2

#define DREW_UTIL_CODEC_TYPE_X509_CERT	DREW_UTIL_CODEC_TYPE_PUBKEY

DREW_SYM_PUBLIC
int drew_util_codec_init(drew_util_codec_t *ctx);
DREW_SYM_PUBLIC
int drew_util_codec_fini(drew_util_codec_t *ctx);
/* len must always be at least 64.  Returns 0 on successful detection, 1 on
 * failure.
 */
DREW_SYM_PUBLIC
int drew_util_codec_detect(drew_util_codec_t ctx, int *cat, int *type, int *enc,
		const uint8_t *data, size_t len);
DREW_SYM_PUBLIC
int drew_util_codec_decode_all(drew_util_codec_t ctx, uint8_t *out,
		size_t outlen, const uint8_t *in, size_t inlen);

#endif
