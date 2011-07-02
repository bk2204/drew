#ifndef DREW_UTIL_X509_H
#define DREW_UTIL_X509_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <drew-util/asn1.h>

typedef struct drew_util_x509_sig_s {
	drew_util_asn1_oid_t algo;
	uint8_t *data;
	size_t nbits;
} drew_util_x509_sig_t;

typedef struct drew_util_x509_cert_s {
	int version;
	drew_util_x509_sig_t sig;
	time_t not_before;
	time_t not_after;
	int flags[8];
} drew_util_x509_cert_t;

int drew_util_x509_parse_certificate(drew_util_asn1_t asn,
		const uint8_t *data, size_t len, drew_util_x509_cert_t *cert);

#endif
