#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <drew/drew.h>
#include <drew-util/drew-util.h>
#include <drew-util/asn1.h>
#include <drew-util/x509.h>

int drew_util_x509_parse_version(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, int *version, int *flags)
{
	int res = 0;
	ssize_t ver = 0;
	bool old = false;
	drew_util_asn1_value_t tmp;
	const drew_util_asn1_value_t *p = &tmp;
	if (val->tagclass == DREW_UTIL_ASN1_TC_UNIVERSAL && val->tag == 2) {
		old = true;
		p = val;
		flags[0] |= DREW_UTIL_X509_CERT_DEFAULT_VERSION;
	}
	else if (val->tagclass != DREW_UTIL_ASN1_TC_CONTEXT || val->tag != 0)
		return -DREW_ERR_INVALID;
	else if ((res = drew_util_asn1_parse(asn, val->data, val->length, &tmp)) < 0)
		return res;
	if (old) {
		/* Version 1 certificates make the version field optional, for some
		 * idiotic reason.  In this case, we presume it's omitted, knowing that
		 * things will implode in an orderly fashion later if the certificate is
		 * actually corrupt.
		 */
		ver = 0;
	}
	else
		RETFAIL(drew_util_asn1_parse_small_integer(asn, p, &ver));
	if (ver < 0)
		return -DREW_ERR_INVALID;
	*version = ver + 1;
	if (val->tagclass == DREW_UTIL_ASN1_TC_UNIVERSAL && val->tag == 2 &&
			*version >= 3)
		flags[0] |= DREW_UTIL_X509_CERT_MISPARSE_VERSION;
	return 0;
}

static int parse_name(drew_util_asn1_t asn, const drew_util_asn1_value_t *val,
		drew_util_x509_rdn_t **rdnp, size_t *rdnlenp)
{
	drew_util_asn1_value_t *sequence;
	drew_util_x509_rdn_t *rdn;
	size_t rdnlen;

	RETFAIL(drew_util_asn1_parse_sequence(asn, val, &sequence, &rdnlen));
	rdn = malloc(rdnlen * sizeof(*rdn));
	for (size_t i = 0; i < rdnlen; i++) {
		drew_util_asn1_value_t *set, *seq;
		size_t nitems;
		RETFAIL(drew_util_asn1_parse_set(asn, &sequence[i], &set, &nitems));
		RETFAIL(drew_util_asn1_parse_sequence(asn, set, &seq, &nitems));
		if (nitems != 2)
			return -DREW_ERR_INVALID;
		RETFAIL(drew_util_asn1_parse_oid(asn, &seq[0], &rdn[i].type));
		RETFAIL(drew_util_asn1_parse_string_utf8(asn, &seq[1], &rdn[i].string,
					&rdn[i].len));
	}
	*rdnp = rdn;
	*rdnlenp = rdnlen;
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
	// Check to make sure that the sequence contains at least one field so we
	// can determine the version number.
	if (!nvals)
		return -DREW_ERR_INVALID;
	RETFAIL(drew_util_x509_parse_version(asn, &vals[0], &cert->version,
				cert->flags));
	size_t valoff = 1;
	if (cert->flags[0] & DREW_UTIL_X509_CERT_DEFAULT_VERSION)
		valoff = 0;
	// A certificate has six fields excluding the version number.
	if (nvals < (6 + valoff))
		return -DREW_ERR_INVALID;
	RETFAIL(parse_name(asn, &vals[2+valoff], &cert->issuer, &cert->issuer_len));

	RETFAIL(drew_util_asn1_parse_sequence(asn, &certvals[1], &sigvals,
				&nsigvals));
	RETFAIL(drew_util_asn1_parse_oid(asn, sigvals, &cert->sig.algo.algo));

	if (!(p = malloc(certvals[2].length)))
		return -ENOMEM;
	cert->sig.value.data = p;
	RETFAIL(drew_util_asn1_parse_bitstring(asn, &certvals[2], p,
				&cert->sig.value.nbits));

	return res;
}
