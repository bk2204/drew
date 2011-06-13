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

static int validate(const drew_util_asn1_value_t *val, int tclass,
		bool constructed, size_t tag)
{
	if ((val->tagclass != tclass) || (val->constructed != constructed) ||
			(val->tag != tag))
		return -DREW_ERR_INVALID;
	return 0;
}

int drew_util_asn1_parse_boolean(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, bool *b)
{
	uint8_t value;

	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 1));

	if (!val->length)
		return -DREW_ERR_INVALID;
	value = *val->data;
	if ((asn->encoding & DREW_UTIL_ASN1_ENC_RESTRICTED) && (value != 0x00) &&
			(value != 0xff))
		return -DREW_ERR_INVALID;
	*b = value;
	return 0;
}

int drew_util_asn1_parse_small_integer(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, ssize_t *i)
{
	ssize_t value = 0;

	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 2));

	if (!val->length || val->length > sizeof(value))
		return -DREW_ERR_INVALID;

	// Must use the shortest possible encoding.
	if (val->length > 1 && ((val->data[0] == 0xff && val->data[1] & 0x80) ||
				(val->data[0] == 0x00 && !(val->data[1] & 0x80))))
		return -DREW_ERR_INVALID;

	for (size_t i = 0; i < val->length; i++) {
		value <<= 8;
		value |= val->data[i];
	}
	*i = value;
	return 0;
}

// buf must be NULL, or at least val->length bytes long.
int drew_util_asn1_parse_large_integer(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, uint8_t *buf, size_t *nbytes)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 2));

	if (!val->length)
		return -DREW_ERR_INVALID;

	// Must use the shortest possible encoding.
	if (val->length > 1 && ((val->data[0] == 0xff && val->data[1] & 0x80) ||
				(val->data[0] == 0x00 && !(val->data[1] & 0x80))))
		return -DREW_ERR_INVALID;

	*nbytes = val->length;
	if (buf)
		memcpy(buf, val->data, val->length);
	return 0;
}

// buf must be NULL, or at least val->length bytes long.
int drew_util_asn1_parse_bitstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, uint8_t *buf, size_t *nbits)
{
	unsigned trailing;
	int res = 0;

	res = validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 3);
	if (asn->flags & DREW_UTIL_ASN1_ENC_RESTRICTED)
		RETFAIL(res);
	else if (res) {
		RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, true, 3));
		// We don't yet support the constructed encoding, which is only allowed
		// in BER (not CER or DER).
		return -DREW_ERR_NOT_IMPL;
	}

	if (!val->length)
		return -DREW_ERR_INVALID;

	trailing = *val->data;
	if (trailing >= 8)
		return -DREW_ERR_INVALID;

	if (val->length == 1) {
		if (trailing != 0)
			return -DREW_ERR_INVALID;
		*nbits = 0;
		return 0;
	}

	*nbits = ((val->length - 1) * 8) - trailing;
	if (buf)
		memcpy(buf, val->data+1, val->length-1);
	return 0;
}

// buf must be NULL, or at least val->length bytes long.
int drew_util_asn1_parse_octetstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, uint8_t *buf, size_t *nbits)
{
	int res = 0;

	res = validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 4);
	if (asn->flags & DREW_UTIL_ASN1_ENC_RESTRICTED)
		RETFAIL(res);
	else if (res) {
		RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, true, 4));
		// We don't yet support the constructed encoding, which is only allowed
		// in BER (not CER or DER).
		return -DREW_ERR_NOT_IMPL;
	}

	if (buf)
		memcpy(buf, val->data, val->length);
	return 0;
}

int drew_util_asn1_parse_null(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 5));

	if (val->length)
		return -DREW_ERR_INVALID;
	return 0;
}

int drew_util_asn1_parse_oid(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, drew_util_asn1_oid_t *oid)
{
	size_t cnt = 1;
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 6));

	if (!val->length)
		return -DREW_ERR_INVALID;

	// Two-pass algorithm.
	for (size_t i = 0; i < val->length; i++)
		if (!(val->data[i] & 0x80))
			cnt++;

	if (!(oid->values = calloc(cnt, sizeof(*oid->values))))
		return -ENOMEM;

	for (size_t i = 0, j = 1; i < val->length; i++) {
		oid->values[j] <<= 7;
		oid->values[j] |= val->data[i] & 0x7f;
		if (!(val->data[i] & 0x80))
			j++;
	}

	// Now handle the special case of the first encoded value.
	size_t encoded = oid->values[1], t = encoded / 40;
	switch (t) {
		case 0:
		case 1:
			oid->values[0] = t;
			oid->values[1] = encoded % 40;
			break;
		default:
			oid->values[0] = 2;
			oid->values[1] = encoded - 80;
			break;
	}
	
	oid->length = cnt;
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
