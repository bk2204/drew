#ifndef DREW_UTIL_X509_H
#define DREW_UTIL_X509_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <drew/drew.h>
#include <drew/param.h>
#include <drew-util/asn1.h>

typedef struct {
	drew_util_asn1_oid_t algo;
	drew_param_t *param;
} drew_util_x509_sig_algo_t;

typedef struct drew_util_x509_sig_s {
	drew_util_x509_sig_algo_t algo;
	drew_util_asn1_bitstring_t value;
} drew_util_x509_sig_t;

typedef struct drew_util_x509_cert_s {
	int version;
	drew_util_x509_sig_t sig;
	int64_t not_before;
	int64_t not_after;
	int flags[8];
} drew_util_x509_cert_t;

/* Flags for flags[0] in drew_util_x509_cert_t. */
#define DREW_UTIL_X509_CERT_MISPARSE_VERSION		(1 << 0)
#define DREW_UTIL_X509_CERT_DEFAULT_VERSION			(1 << 1)

DREW_SYM_PUBLIC
int drew_util_x509_parse_certificate(drew_util_asn1_t asn,
		const uint8_t *data, size_t len, drew_util_x509_cert_t *cert);

#endif
