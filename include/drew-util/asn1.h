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


#define DREW_UTIL_ASN1_ENC_DER		1
#define DREW_UTIL_ASN1_ENC_CER		2
#define DREW_UTIL_ASN1_ENC_BER		3

/* If set, when parsing data into a drew_util_asn1_value_t, the parser should
 * allocate memory and copy the data into a separate block of memory instead of
 * simply pointing to the existing buffer.
 */
#define DREW_UTIL_ASN1_CLONE_DATA	1

#endif
