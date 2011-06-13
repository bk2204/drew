#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <drew/drew.h>
#include <drew-util/asn1.h>

struct drew_util_asn1_s {
	int encoding;
	int flags;
};

int drew_util_asn1_init(drew_util_asn1_t *asnp)
{
	drew_util_asn1_t asn;
	
	asn = malloc(sizeof(*asn));
	if (!asn)
		return -ENOMEM;

	memset(asn, 0, sizeof(*asn));
	*asnp = asn;
	return 0;
}

int drew_util_asn1_fini(drew_util_asn1_t *asnp)
{
	if (!asnp)
		return -DREW_ERR_INVALID;
	free(*asnp);
	return 0;
}

int drew_util_asn1_set_encoding(drew_util_asn1_t asn, int encoding)
{
	if (encoding != DREW_UTIL_ASN1_ENC_DER)
		return -DREW_ERR_NOT_IMPL;
	asn->encoding = encoding;
	return 0;
}

int drew_util_asn1_set_flags(drew_util_asn1_t asn, int flags)
{
	asn->flags = flags;
	return 0;
}

int drew_util_asn1_parse_value(drew_util_asn1_t asn, const uint8_t *data,
		size_t len, drew_util_asn1_value_t *enc)
{
	size_t off = 1;

	if (len < 2)
		return -DREW_ERR_MORE_INFO;

	// identifier
	enc->tagclass = *data >> 6;
	enc->constructed = *data & 0x20;
	if ((*data & 0x1f) != 0x1f)
		enc->tag = *data & 0x1f;
	else {
		enc->tag = 0;
		if (!(data[1] & 0x7f))
			return -DREW_ERR_INVALID;
		for (size_t i = 1; i < len; i++, off++) {
			enc->tag <<= 7;
			enc->tag |= data[i];
			if (!(data[i] & 0x80)) {
				off++;
				break;
			}
		}
	}
	if (off == len)
		return -DREW_ERR_MORE_INFO;

	// length
	if (data[off] & 0x80)
		enc->length = data[off++] & 0x7f;
	else {
		size_t lenoflen = data[off++] & 0x7f;
		enc->length = 0;
		for (size_t i = 0; i < lenoflen && off < len; i++, off++) {
			enc->length <<= 8;
			enc->length |= data[off];
		}
	}

	if (off + enc->length >= len)
		return -DREW_ERR_MORE_INFO;

	if (asn->flags & DREW_UTIL_ASN1_CLONE_DATA) {
		uint8_t *p;
		if (!(p = malloc(enc->length)))
			return -ENOMEM;
		memcpy(p, data+off, enc->length);
		enc->data = p;
	}
	else
		enc->data = data + off;
	return off + enc->length;
}
