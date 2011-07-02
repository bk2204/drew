#include "internal.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <drew/drew.h>
#include <drew-util/drew-util.h>
#include <drew-util/asn1.h>
#include <drew-util/x509.h>

int drew_util_asn1_x509_parse_version(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, int *version)
{
	int res = 0;
	ssize_t ver = 0;
	bool old = false;
	drew_util_asn1_value_t tmp;
	const drew_util_asn1_value_t *p = &tmp;
	if (val->tagclass == DREW_UTIL_ASN1_TC_UNIVERSAL && val->tag == 2) {
		old = true;
		p = val;
	}
	else if (val->tagclass != DREW_UTIL_ASN1_TC_CONTEXT || val->tag != 0)
		return -DREW_ERR_INVALID;
	else if ((res = drew_util_asn1_parse(asn, val->data, val->length, &tmp)) < 0)
		return res;
	res = drew_util_asn1_parse_small_integer(asn, p, &ver);
	if (res == -DREW_UTIL_ERR_BAD_INTEGER && old && val->length > 1) {
		/* Version 1 certificates make the version field optional, for some
		 * idiotic reason.  In this case, we presume it's omitted, knowing that
		 * things will implode in an orderly fashion later if the certificate is
		 * actually corrupt.
		 */
		ver = 0;
	}
	else if (res)
		return res;
	if (ver < 0)
		return -DREW_ERR_INVALID;
	*version = ver + 1;
	return 0;
}

int drew_util_x509_parse_certificate(drew_util_asn1_t asn,
		const uint8_t *data, size_t len, drew_util_x509_cert_t *cert)
{
	int res = 0;
	uint8_t *p;
	size_t ncertvals, nvals, nsigvals;
	drew_util_asn1_value_t certificate, *certvals, *sigvals, *vals;

	memset(cert, 0, sizeof(*cert));

	// FIXME: remove memory leaks.
	res = drew_util_asn1_parse(asn, data, len, &certificate);
	if (res < 0)
		return res;

	RETFAIL(drew_util_asn1_parse_sequence(asn, &certificate, &certvals,
				&ncertvals));
	if (ncertvals != 3)
		return -DREW_ERR_INVALID;

	// FIXME: parse the entire certificate.
	RETFAIL(drew_util_asn1_parse_sequence(asn, &certvals[0], &vals, &nvals));
	RETFAIL(drew_util_asn1_x509_parse_version(asn, &vals[0], &cert->version));
	if (vals[0].tagclass == DREW_UTIL_ASN1_TC_UNIVERSAL && vals[0].tag == 2) {
		if (cert->version >= 3)
			cert->flags[0] |= DREW_UTIL_X509_CERT_MISPARSE_VERSION;
		else if (cert->version == 1 && vals[0].length > 1)
			cert->flags[0] |= DREW_UTIL_X509_CERT_DEFAULT_VERSION;
	}

	RETFAIL(drew_util_asn1_parse_sequence(asn, &certvals[1], &sigvals,
				&nsigvals));
	RETFAIL(drew_util_asn1_parse_oid(asn, sigvals, &cert->sig.algo));

	if (!(p = malloc(certvals[2].length)))
		return -ENOMEM;
	cert->sig.data = p;
	RETFAIL(drew_util_asn1_parse_bitstring(asn, &certvals[2], p,
				&cert->sig.nbits));

	return res;
}
