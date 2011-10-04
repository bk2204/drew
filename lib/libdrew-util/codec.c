#include "internal.h"

#include <errno.h>
#include <string.h>

#include <drew/drew.h>
#include <drew/mem.h>
#include <drew-util/drew-util.h>
#include <drew-util/codec.h>

struct drew_util_codec_s {
	int cat;
	int type;
	int enc;
	int (*encode)(drew_util_codec_t, uint8_t *, size_t, const uint8_t *,
			size_t);
	int (*decode)(drew_util_codec_t, uint8_t *, size_t, const uint8_t *,
			size_t);
	void *codec;
};

int drew_util_codec_init(drew_util_codec_t *ctx)
{
	drew_util_codec_t codec;
	
	codec = drew_mem_malloc(sizeof(*codec));
	if (!codec)
		return -ENOMEM;

	memset(codec, 0, sizeof(*codec));
	*ctx = codec;
	return 0;
}

int drew_util_codec_fini(drew_util_codec_t *ctx)
{
	if (!ctx)
		return -DREW_ERR_INVALID;
	drew_mem_free(*ctx);
	return 0;
}

static int pem_encode(drew_util_codec_t ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	return -DREW_ERR_NOT_IMPL;
}

static inline int b64_char(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	if (c == '=')
		return -2;
	if (c == '\r' || c == '\n')
		return -3;
	if (c == '-')
		return -4;
	return -1;
}

/* This parser is extremely liberal in what it accepts.  A little stricter might
 * be better.
 */
static int pem_decode(drew_util_codec_t ctx, uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen)
{
	const uint8_t *line = in, *eol;
	uint8_t *dest = out;
	const uint8_t *end = out + outlen;
	int enc[4];
	int *p = enc;

	// Skip the first line.
	eol = memchr(in, '\n', inlen);
	if (!eol)
		return -DREW_ERR_INVALID;
	line = eol + 1;
	if (line >= in + inlen)
		return -DREW_ERR_INVALID;

	const uint8_t *cur = line;
	while (cur - in < inlen) {
		if (dest >= end)
			break;
		bool done = false;
		int val = b64_char(*cur++);
		if (val == -4)
			break;
		else if (val == -3)
			continue;
		else if (val == -2) {
			memset(p, 0, 4 - (p - enc));
			done = true;
		}
		else if (val == -1)
			return -DREW_ERR_INVALID;
		*p++ = val;
		if (p == enc + 4 || done) {
			dest[0] = (enc[0] << 2) | (enc[1] >> 4);
			if (dest + 1 < end)
				dest[1] = (enc[1] << 4) | (enc[2] >> 2);
			if (dest + 2 < end)
				dest[2] = (enc[2] << 6) | enc[3];
			p = enc;
			dest += 3;
			if (done)
				break;
		}
	}
	return dest - out;
}

struct codecs {
	int cat;
	int type;
	int enc;
	const char *fixed;
	int (*detect)(const uint8_t *, size_t len);
	int (*encode)(drew_util_codec_t, uint8_t *, size_t, const uint8_t *,
			size_t);
	int (*decode)(drew_util_codec_t, uint8_t *, size_t, const uint8_t *,
			size_t);
};

static const struct codecs codecs[] = {
	{
		DREW_UTIL_CODEC_CAT_X509,
		DREW_UTIL_CODEC_TYPE_X509_CERT,
		DREW_UTIL_CODEC_ENC_X509_PEM,
		"-----BEGIN CERTIFICATE-----", NULL, pem_encode, pem_decode
	}
};

/* len must always be at least 64. */
int drew_util_codec_detect(drew_util_codec_t ctx, int *cat, int *type, int *enc,
		const uint8_t *data, size_t len)
{
	if (cat)
		*cat = 0;
	if (type)
		*type = 0;
	if (enc)
		*enc = 0;

	for (size_t i = 0; i < DIM(codecs); i++) {
		if (codecs[i].fixed &&
				!memcmp(codecs[i].fixed, data, strlen(codecs[i].fixed))) {
			ctx->cat = codecs[i].cat;
			if (cat)
				*cat = ctx->cat;
			ctx->type = codecs[i].type;
			if (type)
				*type = ctx->type;
			ctx->enc = codecs[i].enc;
			if (enc)
				*enc = ctx->enc;
			ctx->encode = codecs[i].encode;
			ctx->decode = codecs[i].decode;
			return 0;
		}
	}

	return 1;
}

int drew_util_codec_set_type(drew_util_codec_t ctx, int cat, int type, int enc)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_util_codec_decode_all(drew_util_codec_t ctx, uint8_t *out,
		size_t outlen, const uint8_t *in, size_t inlen)
{
	return ctx->decode(ctx, out, outlen, in, inlen);
}
