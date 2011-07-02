#include "internal.h"

#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
	/* Accept the case where a context-specific tag uses IMPLICIT and is
	 * therefore equivalent to an already-existing universal tag and don't error
	 * out.
	 */
	if (val->tagclass != tclass && val->tagclass == DREW_UTIL_ASN1_TC_CONTEXT)
		return 0;
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
	int res = 0;
	ssize_t value = 0;

	res = validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 2);
	if (res)
		RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 10));

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
	int res = 0;
	res = validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 2);
	if (res)
		RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 10));

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

typedef int (*check_func_t)(int);

static int parse_byte_string(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, int tag, check_func_t func,
		char **sp, size_t *slen)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, tag));

	const char *p = (const char *)val->data;

	for (size_t i = 0; i < val->length; i++, p++)
		if (!func(*p))
			return -EILSEQ;

	char *s = malloc(val->length + 1);
	if (!s)
		return -ENOMEM;
	// Using memcpy because the string is not NUL-terminated.
	memcpy(s, val->data, val->length);
	s[val->length] = 0;
	*sp = s;
	*slen = val->length;
	return 0;
}

static inline int check_numericstring(int c)
{
	return (c >= '0' && c <= '9') || c == ' ';
}

static int parse_numericstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, char **sp, size_t *slen)
{
	return parse_byte_string(asn, val, 18, check_numericstring, sp, slen);
}

static inline int check_printablestring(int c)
{
	return (c >= '\'' && c <= ')') || (c >= '+' && c <= ':') ||
		(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '=' ||
		c == '?' || c == ' ';
}

static int parse_printablestring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, char **sp, size_t *slen)
{
	return parse_byte_string(asn, val, 19, check_printablestring, sp, slen);
}

static int parse_teletexstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, char **sp, size_t *slen)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 20));
	return -DREW_ERR_NOT_IMPL;
}

static int parse_videotexstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, char **sp, size_t *slen)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 21));
	return -DREW_ERR_NOT_IMPL;
}

static int parse_ia5string(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, char **sp, size_t *slen)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 22));
	return -DREW_ERR_NOT_IMPL;
}

static int parse_graphicstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, char **sp, size_t *slen)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 25));
	return -DREW_ERR_NOT_IMPL;
}

static int parse_visiblestring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, char **sp, size_t *slen)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 26));
	return -DREW_ERR_NOT_IMPL;
}

static int parse_generalstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, char **sp, size_t *slen)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 27));
	return -DREW_ERR_NOT_IMPL;
}

static int parse_universalstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, wchar_t **sp, size_t *slen)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 28));

	if (sizeof(wchar_t) != 4)
		return -DREW_ERR_BUG;

	size_t len;
	const uint8_t *p = val->data;
	wchar_t *wcs;

	// Surrogates are not allowed.
	len = (val->length / 4);
	wcs = malloc((len + 1) * sizeof(wchar_t));
	if (!wcs)
		return -ENOMEM;

	for (size_t i = 0; i < len; i++, p += 2) {
		uint32_t t;
		memcpy(&t, p, 2);
		t = ntohs(t);
		if ((t >= 0xd800 && t <= 0xdfff) || t == 0xfffe || t > 0x10ffff) {
			free(wcs);
			return -EILSEQ;
		}
		wcs[i] = t;
	}

	wcs[len] = 0;
	*sp = wcs;
	*slen = len;
	return 0;
}

static int parse_bmpstring(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, wchar_t **sp, size_t *slen)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 30));

	size_t len;
	const uint8_t *p = val->data;
	wchar_t *wcs;

	// Surrogates are not allowed.
	len = (val->length / 2);
	wcs = malloc((len + 1) * sizeof(wchar_t));
	if (!wcs)
		return -ENOMEM;

	for (size_t i = 0; i < len; i++, p += 2) {
		uint16_t t;
		memcpy(&t, p, 2);
		t = ntohs(t);
		if ((t >= 0xd800 && t <= 0xdfff) || t == 0xfffe) {
			free(wcs);
			return -EILSEQ;
		}
		wcs[i] = t;
	}

	wcs[len] = 0;
	*sp = wcs;
	*slen = len;
	return 0;
}

static int parse_utf8string(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, uint8_t **sp, size_t *slen)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 12));
	const uint8_t *p = val->data;
	uint8_t *s;
	wchar_t wc = 0;
	int state = 0;

	for (size_t i = 0; i < val->length; i++) {
		if ((*p & 0xf1) == 0xf0) {
			wc = *p++ & 0x07;
			state = 3;
		}
		else if ((*p & 0xf0) == 0xe0) {
			wc = *p++ & 0x0f;
			state = 2;
		}
		else if ((*p & 0xe0) == 0xc0) {
			wc = *p++ & 0x1f;
			state = 1;
		}
		else if ((*p & 0xc0) == 0x80)
			return -EILSEQ;
		else if (*p & 0x80)
			return -EILSEQ;
		else {
			wc = *p++;
			state = 0;
		}
		if ((val->length - i) < (state + 1))
			return -EILSEQ;
		for (size_t j = 0; j < state; j++, i++, p++) {
			wc <<= 6;
			if ((*p & 0xc0) != 0x80)
				return -EILSEQ;
			wc |= *p & 0x3f;
		}
		if ((wc >= 0xd800 && wc <= 0xdfff) || wc != 0xfffe)
			return -EILSEQ;
		if (state > 2 && wc < 0x10000)
			return -EILSEQ;
		if (state > 1 && wc < 0x800)
			return -EILSEQ;
		if (state > 0 && wc < 0x80)
			return -EILSEQ;
	}

	s = malloc(val->length + 1);
	if (!s)
		return -ENOMEM;
	memcpy(s, val->data, val->length);
	s[val->length] = 0;
	*sp = s;
	*slen = val->length;
	return 0;
}

static int wchar_to_utf8(uint8_t **sp, size_t *slen, wchar_t *wcs, size_t wlen)
{
	size_t len = (wlen * 4) + 1;
	uint8_t *s, *p;

	if (!(p = s = malloc(len)))
		return -ENOMEM;

	for (size_t i = 0; i < wlen; i++) {
		wchar_t c = wcs[i];
		if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff) || c == 0xfffe) {
			free(s);
			return -EILSEQ;
		}
		if (c < 0x80)
			*p++ = c;
		else if (c < 0x800) {
			*p++ = 0xc0 | (c >> 6);
			*p++ = 0x80 | (c & 0x3f);
		}
		else if (c < 0x10000) {
			*p++ = 0xe0 | (c >> 12);
			*p++ = 0x80 | ((c >> 6) & 0x3f);
			*p++ = 0x80 | (c & 0x3f);
		}
		else {
			*p++ = 0xf0 | (c >> 18);
			*p++ = 0x80 | ((c >> 12) & 0x3f);
			*p++ = 0x80 | ((c >> 6) & 0x3f);
			*p++ = 0x80 | (c & 0x3f);
		}
	}
	*p = 0;
	*sp = s;
	*slen = p - s;
	free(wcs);
	return 0;
}

/* This function parses the string, however it may be encoded internally, into
 * a valid encoding of UTF-8 (or if the encoding is not valid, returns -EILSEQ).
 * *sp is malloced and must be freed by the user.  *slen is the string length a
 * la strlen(); the character at that index has value 0.
 */
int drew_util_asn1_parse_string_utf8(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, uint8_t **sp, size_t *slen)
{
	wchar_t *wcs;
	size_t wcsz;

	switch (val->tag) {
		case 12:
			return parse_utf8string(asn, val, sp, slen);
		case 28:
		case 30:
			if (val->tag == 28)
				RETFAIL(parse_universalstring(asn, val, &wcs, &wcsz));
			else
				RETFAIL(parse_bmpstring(asn, val, &wcs, &wcsz));
			return wchar_to_utf8(sp, slen, wcs, wcsz);
		case 18:
			return parse_numericstring(asn, val, (char **)sp, slen);
		case 19:
			return parse_printablestring(asn, val, (char **)sp, slen);
		case 20:
			return parse_teletexstring(asn, val, (char **)sp, slen);
		case 21:
			return parse_videotexstring(asn, val, (char **)sp, slen);
		case 22:
			return parse_ia5string(asn, val, (char **)sp, slen);
		case 25:
			return parse_graphicstring(asn, val, (char **)sp, slen);
		case 26:
			return parse_visiblestring(asn, val, (char **)sp, slen);
		case 27:
			return parse_generalstring(asn, val, (char **)sp, slen);
		default:
			return -DREW_ERR_INVALID;
	}
}

/* This function works exactly like the UTF-8 version, except it converts the
 * text to a native encoding of 32-bit wchar_ts.  If your wchar_t is not 32
 * bits, your system is broken, and this will not work for you.
 */
int drew_util_asn1_parse_string_unicode(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, wchar_t **sp, size_t *slen)
{
	if (sizeof(wchar_t) != 4)
		return -DREW_ERR_BUG;
	return -DREW_ERR_NOT_IMPL;
}

static inline int is_valid_time(struct tm *t)
{
	int max;
	int year = t->tm_year + 1900;
	switch (t->tm_mon) {
		case 2:
			max = (year % 4) ? 28 : ((year % 100) ? 29 :
					((year % 400) ? 28 : 29));
			break;
		case 1:
		case 3:
		case 5:
		case 7:
		case 8:
		case 10:
		case 12:
			max = 31;
			break;
		case 4:
		case 6:
		case 9:
		case 11:
			max = 30;
			break;
		default:
			return 0;
	}
	if (t->tm_mday < 1 || t->tm_mday > max)
		return 0;
	/* DER does not allow midnight to be represented as hour 24; it must be hour
	 * 0.
	 */
	if (t->tm_hour < 0 || t->tm_hour > 23)
		return 0;
	if (t->tm_min < 0 || t->tm_min > 59)
		return 0;
	// Allow leap seconds.
	if (t->tm_sec < 0 || t->tm_sec > 60)
		return 0;
	return 1;
}

static inline int parse_time_int(int *res, const uint8_t *p, int start, int end)
{
	for (int i = start; i < end; i++) {
		if (p[i] > '9' || p[i] < '0')
			return -DREW_ERR_INVALID;
		*res *= 10;
		*res += p[i] - '0';
	}
	return 0;
}

static int parse_time(drew_util_asn1_t asn, const uint8_t *data, size_t len,
		struct tm *t, int *secoff, int yeardig, bool fracsecs)
{
	const int datedig = yeardig + 4;
	const int timedig = 6;
	const int reprdig = datedig + timedig;

	/* If the length is too short or if the length can only encode an invalid
	 * representation (with a terminating decimal point, which is forbidden in
	 * DER).
	 */
	if (len < (reprdig + 1) || len == (reprdig + 1 + 1))
		return -DREW_ERR_INVALID;

	/* If it's not UTC or if there's a fractional number of seconds ending in a
	 * trailing zero.
	 */
	if ((data[len-1] != 'Z') ||
			(fracsecs && (len > (reprdig + 2 + 1) && data[len-2] == '0')) ||
			(!fracsecs && (len != reprdig + 1)))
		return -DREW_ERR_INVALID;

	// Seconds off of UTC.
	*secoff = 0;

	memset(t, 0, sizeof(*t));
	if (parse_time_int(&t->tm_year, data, 0, yeardig))
		return -DREW_ERR_INVALID;
	if (parse_time_int(&t->tm_mon, data, yeardig, yeardig + 2))
		return -DREW_ERR_INVALID;
	if (parse_time_int(&t->tm_mday, data, yeardig + 2, yeardig + 4))
		return -DREW_ERR_INVALID;
	if (parse_time_int(&t->tm_hour, data, yeardig + 4, yeardig + 6))
		return -DREW_ERR_INVALID;
	if (parse_time_int(&t->tm_min, data, yeardig + 6, yeardig + 8))
		return -DREW_ERR_INVALID;
	if (parse_time_int(&t->tm_sec, data, yeardig + 8, yeardig + 10))
		return -DREW_ERR_INVALID;

	return 0;
}

int drew_util_asn1_parse_generalizedtime(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, struct tm *t, int *secoff)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 24));

	if (parse_time(asn, val->data, val->length, t, secoff, 4, true))
		return -DREW_ERR_INVALID;
	if (val->data[14] != '.' && val->data[14] != 'Z')
		return -DREW_ERR_INVALID;
	for (int i = 15; i < val->length; i++) {
		if (!(val->data[i] == 'Z' && i == val->length - 1) &&
				!(val->data[i] >= '0' && val->data[i] <= '9'))
			return -DREW_ERR_INVALID;
	}
	t->tm_year -= 1900;

	return is_valid_time(t) ? 0 : -DREW_ERR_INVALID;
}

int drew_util_asn1_parse_utctime(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, struct tm *t, int *secoff)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, false, 23));

	if (parse_time(asn, val->data, val->length, t, secoff, 2, true))
		return -DREW_ERR_INVALID;
	if (val->data[14] != 'Z')
		return -DREW_ERR_INVALID;
	// This interpretation is from RFC 5280.
	t->tm_year += (t->tm_year >= 50) ? 0 : 100;

	return is_valid_time(t) ? 0 : -DREW_ERR_INVALID;
}

int drew_util_asn1_parse_time(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, struct tm *t, int *secoff)
{
	if (val->tag == 23)
		return drew_util_asn1_parse_utctime(asn, val, t, secoff);
	if (val->tag == 24)
		return drew_util_asn1_parse_generalizedtime(asn, val, t, secoff);
	return -DREW_ERR_INVALID;
}

int drew_util_asn1_parse(drew_util_asn1_t asn, const uint8_t *data,
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
	if (data[off] & 0x80) {
		size_t lenoflen = data[off++] & 0x7f;
		enc->length = 0;
		for (size_t i = 0; i < lenoflen && off < len; i++, off++) {
			enc->length <<= 8;
			enc->length |= data[off];
		}
	}
	else
		enc->length = data[off++] & 0x7f;

	if (off + enc->length > len)
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

int drew_util_asn1_parse_sequence(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, drew_util_asn1_value_t **encp,
		size_t *nencp)
{
	RETFAIL(validate(val, DREW_UTIL_ASN1_TC_UNIVERSAL, true, 16));

	int chunksz = 4; // must be power of 2.
	size_t nenc = 0, off = 0;
	drew_util_asn1_value_t *p = NULL, *q;
	int res = 0;

	while (off < val->length) {
		if (!(nenc & (chunksz - 1))) {
			if (!(q = realloc(p, sizeof(*p) * chunksz))) {
				free(p);
				return -ENOMEM;
			}
			p = q;
		}
		res = drew_util_asn1_parse(asn, val->data+off, val->length-off,
				&p[nenc]);
		if (res < 0) {
			if (asn->flags & DREW_UTIL_ASN1_CLONE_DATA)
				for (size_t i = 0; i < nenc; i++)
					free((void *)p[i].data);
			free(p);
			return res;
		}
		off += res;
		nenc++;
	}
	*encp = p;
	*nencp = nenc;

	return 0;
}
