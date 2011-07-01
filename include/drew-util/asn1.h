#ifndef DREW_UTIL_ASN1_H
#define DREW_UTIL_ASN1_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct drew_util_asn1_s;

typedef struct drew_util_asn1_s *drew_util_asn1_t;

typedef struct {
	uint8_t tagclass;
	bool constructed;
	size_t tag;
	size_t length;
	const uint8_t *data;
} drew_util_asn1_value_t;

typedef struct {
	size_t *values;
	size_t length;
} drew_util_asn1_oid_t;

#define DREW_UTIL_ASN1_ENC_BER			1
#define DREW_UTIL_ASN1_ENC_CER			2
#define DREW_UTIL_ASN1_ENC_DER			3

/* A bit mask for CER and DER, which have restrictions on permissible BER
 * encodings.
 */
#define DREW_UTIL_ASN1_ENC_RESTRICTED	2

#define DREW_UTIL_ASN1_TC_UNIVERSAL		0
#define DREW_UTIL_ASN1_TC_APPLICATION	1
#define DREW_UTIL_ASN1_TC_CONTEXT		2
#define DREW_UTIL_ASN1_TC_PRIVATE		3

/* If set, when parsing data into a drew_util_asn1_value_t, the parser should
 * allocate memory and copy the data into a separate block of memory instead of
 * simply pointing to the existing buffer.
 */
#define DREW_UTIL_ASN1_CLONE_DATA	1

int drew_util_asn1_init(drew_util_asn1_t *asnp);
int drew_util_asn1_fini(drew_util_asn1_t *asnp);
int drew_util_asn1_set_encoding(drew_util_asn1_t asn, int encoding);
int drew_util_asn1_set_flags(drew_util_asn1_t asn, int flags);
int drew_util_asn1_parse_boolean(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, bool *b);
int drew_util_asn1_parse_small_integer(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, ssize_t *i);
// buf must be NULL, or at least val->length bytes long.
int drew_util_asn1_parse_large_integer(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, uint8_t *buf, size_t *nbytes);
// buf must be NULL, or at least val->length bytes long.
int drew_util_asn1_parse_bitstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, uint8_t *buf, size_t *nbits);
// buf must be NULL, or at least val->length bytes long.
int drew_util_asn1_parse_octetstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, uint8_t *buf, size_t *nbits);
int drew_util_asn1_parse_null(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val);
int drew_util_asn1_parse_oid(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, drew_util_asn1_oid_t *oid);
/* This function parses the string, however it may be encoded internally, into
 * a valid encoding of UTF-8 (or if the encoding is not valid, returns -EILSEQ).
 * *sp is malloced and must be freed by the user.  *slen is the string length a
 * la strlen(); the character at that index has value 0.
 */
int drew_util_asn1_parse_string_utf8(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, uint8_t **sp, size_t *slen);
/* This function works exactly like the UTF-8 version, except it converts the
 * text to a native encoding of 32-bit wchar_ts.  If your wchar_t is not 32
 * bits, your system is broken, and this will not work for you.
 */
int drew_util_asn1_parse_string_unicode(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, wchar_t **sp, size_t *slen);
int drew_util_asn1_parse_generalizedtime(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, struct tm *t, int *secoff);
int drew_util_asn1_parse_utctime(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, struct tm *t, int *secoff);
int drew_util_asn1_parse_time(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, struct tm *t, int *secoff);
int drew_util_asn1_parse_sequence(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, drew_util_asn1_value_t **encp,
		size_t *nencp);

int drew_util_asn1_parse(drew_util_asn1_t asn, const uint8_t *data,
		size_t len, drew_util_asn1_value_t *enc);

#endif
