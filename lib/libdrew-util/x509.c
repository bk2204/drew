#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <drew/drew.h>
#include <drew/mem.h>
#include <drew/hash.h>
#include <drew/plugin.h>
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

static int parse_time(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, int64_t *t)
{
	struct tm tms;
	int secoff;

	RETFAIL(drew_util_asn1_parse_time(asn, val, &tms, &secoff));
	if ((*t = mktime(&tms)) == (time_t)-1)
		return -DREW_UTIL_ERR_BAD_TIME;
	return 0;
}

static int parse_validity(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, drew_util_x509_cert_t *cert)
{
	drew_util_asn1_value_t *sequence;
	size_t len;

	RETFAIL(drew_util_asn1_parse_sequence(asn, val, &sequence, &len));
	if (len != 2)
		return -DREW_ERR_INVALID;
	RETFAIL(parse_time(asn, &sequence[0], &cert->not_before));
	RETFAIL(parse_time(asn, &sequence[1], &cert->not_after));
	return 0;
}

static int parse_extensions(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, drew_util_x509_cert_t *cert)
{
	drew_util_asn1_value_t *seq1, *seq2;
	size_t len1, len2;

	if (val->tagclass != DREW_UTIL_ASN1_TC_CONTEXT || val->tag != 3)
		return -DREW_ERR_INVALID;

	RETFAIL(drew_util_asn1_parse_sequence(asn, val, &seq1, &len1));
	RETFAIL(drew_util_asn1_parse_sequence(asn, &seq1[0], &seq2, &len2));
	cert->extensions_len = len2;
	cert->extensions = calloc(sizeof(*cert->extensions), len2);
	for (size_t i = 0; i < len2; i++) {
		drew_util_x509_extension_t *p = cert->extensions + i;
		drew_util_asn1_value_t *seq;
		size_t slen;

		RETFAIL(drew_util_asn1_parse_sequence(asn, &seq2[i], &seq, &slen));
		if (slen < 2)
			return -DREW_ERR_INVALID;
		RETFAIL(drew_util_asn1_parse_oid(asn, &seq[0], &p->oid));
		if (slen == 3) {
			p->value = malloc(p->len = seq[2].length);
			RETFAIL(drew_util_asn1_parse_boolean(asn, &seq[1], &p->critical));
			RETFAIL(drew_util_asn1_parse_octetstring(asn, &seq[2], p->value));
		}
		else if (slen == 2) {
			p->critical = false;
			p->value = malloc(p->len = seq[1].length);
			RETFAIL(drew_util_asn1_parse_octetstring(asn, &seq[1], p->value));
		}
		else
			return -DREW_ERR_INVALID;
	}
	return 0;
}

struct algooids {
	const char *mdalgo;
	const char *pkalgo;
	size_t nvals;
	size_t vals[9];
};

static const struct algooids oids[] = {
	{"MD2", "RSA", 7, {1, 2, 840, 113549, 1, 1, 2}},
	{"MD4", "RSA", 7, {1, 2, 840, 113549, 1, 1, 3}},
	{"MD5", "RSA", 7, {1, 2, 840, 113549, 1, 1, 4}},
	{"SHA-1", "RSA", 7, {1, 2, 840, 113549, 1, 1, 5}},
	{"SHA-224", "RSA", 7, {1, 2, 840, 113549, 1, 1, 14}},
	{"SHA-256", "RSA", 7, {1, 2, 840, 113549, 1, 1, 11}},
	{"SHA-384", "RSA", 7, {1, 2, 840, 113549, 1, 1, 12}},
	{"SHA-512", "RSA", 7, {1, 2, 840, 113549, 1, 1, 13}},
	{"SHA-1", "DSA", 6, {1, 2, 840, 10040, 4, 3}},
	{"SHA-224", "DSA", 9, {2, 16, 840, 1, 101, 3, 4, 3, 1}},
	{"SHA-256", "DSA", 9, {2, 16, 840, 1, 101, 3, 4, 3, 2}},
	{"SHA-224", "ECDSA", 7, {1, 2, 840, 10045, 4, 3, 1}},
	{"SHA-256", "ECDSA", 7, {1, 2, 840, 10045, 4, 3, 2}},
	{"SHA-384", "ECDSA", 7, {1, 2, 840, 10045, 4, 3, 3}},
	{"SHA-512", "ECDSA", 7, {1, 2, 840, 10045, 4, 3, 4}},
};

static void fill_in_sig_fields(drew_util_x509_cert_sig_t *certsig)
{
	const drew_util_asn1_oid_t *p = &certsig->algo.oid;

	certsig->mdalgo = NULL;
	certsig->pkalgo = NULL;

	for (size_t i = 0; i < DIM(oids); i++) {
		if (p->length != oids[i].nvals)
			continue;
		if (!memcmp(oids[i].vals, p->values, p->length * sizeof(size_t))) {
			certsig->mdalgo = oids[i].mdalgo;
			certsig->pkalgo = oids[i].pkalgo;
		}
	}
}

int parse_signature(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, drew_util_x509_cert_sig_t *certsig)
{
	drew_util_asn1_value_t *sigvals;
	size_t nsigvals;

	RETFAIL(drew_util_asn1_parse_sequence(asn, val, &sigvals,
				&nsigvals));
	RETFAIL(drew_util_asn1_parse_oid(asn, sigvals, &certsig->algo.oid));
	fill_in_sig_fields(certsig);

	return 0;
}

static int parse_pki_dsa(drew_util_asn1_t asn, drew_util_asn1_value_t *s,
		const drew_util_asn1_value_t *algoid, drew_util_x509_pubkey_t *pubkey)
{
	return -DREW_ERR_NOT_IMPL;
}

static int parse_pki_rsa(drew_util_asn1_t asn, const drew_util_asn1_value_t *s,
		const drew_util_asn1_value_t *algoid, drew_util_x509_pubkey_t *pubkey)
{
	drew_util_asn1_value_t encoded, *pki;
	size_t nbytes = 0, npkis, dummy;
	uint8_t *encodedseq;
	int ret = 0;

	if (s->constructed || s->tag != 3)
		return -DREW_ERR_INVALID;
	if (!(encodedseq = drew_mem_malloc(s->length)))
		return -ENOMEM;
	RETFAIL(drew_util_asn1_parse_bitstring(asn, s, encodedseq, &dummy));
	if ((ret = drew_util_asn1_parse(asn, encodedseq, s->length, &encoded)) < 0)
		return ret;

	RETFAIL(drew_util_asn1_parse_sequence(asn, &encoded, &pki, &npkis));

	if (npkis != 2)
		return -DREW_ERR_INVALID;

	// Two integers, n and e.
	for (size_t i = 0; i < 2; i++) {
		RETFAIL(drew_util_asn1_parse_large_integer(asn, pki+i, NULL, &nbytes));
		if (nbytes != (uint16_t)nbytes)
			return -DREW_ERR_INVALID;

		if (!(pubkey->mpis[i].data = drew_mem_malloc(nbytes)))
			return -ENOMEM;
		RETFAIL(drew_util_asn1_parse_large_integer(asn, pki+i,
					pubkey->mpis[i].data, &nbytes));
		pubkey->mpis[i].len = nbytes;
	}

	return 0;
}

static int parse_pki(drew_util_asn1_t asn,
		const drew_util_asn1_value_t *val, drew_util_x509_pubkey_t *pubkey)
{
	drew_util_asn1_value_t *sequence, *algoid;
	size_t nitems, nalgoid;
	const size_t rsavals[7] = {
		1, 2, 840, 113549, 1, 1, 1
	};
	const size_t dsavals[6] = {
		1, 2, 840, 10040, 4, 1
	};
	const size_t ecdsavals[] = {
		1, 2, 840, 10045, 2, 1
	};

	RETFAIL(drew_util_asn1_parse_sequence(asn, val, &sequence, &nitems));
	if (nitems != 2)
		return -DREW_ERR_INVALID;

	RETFAIL(drew_util_asn1_parse_sequence(asn, sequence, &algoid, &nalgoid));

	if (nalgoid < 1)
		return -DREW_ERR_INVALID;

	RETFAIL(drew_util_asn1_parse_oid(asn, algoid, &pubkey->oid));

	if (pubkey->oid.length == DIM(rsavals) &&
			!memcmp(rsavals, pubkey->oid.values, sizeof(rsavals)))
		return parse_pki_rsa(asn, sequence+1, algoid, pubkey);
	else if (pubkey->oid.length == DIM(dsavals) &&
			!memcmp(dsavals, pubkey->oid.values, sizeof(dsavals)))
		return parse_pki_dsa(asn, sequence+1, algoid, pubkey);
	else if (pubkey->oid.length == DIM(ecdsavals) &&
			!memcmp(ecdsavals, pubkey->oid.values, sizeof(ecdsavals)))
		return -DREW_ERR_NOT_IMPL;
	return -DREW_ERR_NOT_IMPL;
}

int drew_util_x509_parse_certificate(drew_util_asn1_t asn,
		const uint8_t *data, size_t len, drew_util_x509_cert_t *cert,
		drew_loader_t *ldr)
{
	int res = 0;
	uint8_t *p;
	size_t ncertvals, nvals;
	drew_util_asn1_value_t certificate, *certvals, *vals;

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
	RETFAIL(parse_validity(asn, &vals[3+valoff], cert));
	RETFAIL(parse_name(asn, &vals[4+valoff], &cert->subject,
				&cert->subject_len));
	res = parse_pki(asn, &vals[5+valoff], &cert->pubkey);
	// Don't completely error out if we just don't understand the public key
	// type.  We can still get useful information about the certificate.
	if (res < 0 && res != -DREW_ERR_NOT_IMPL)
		return res;
	// We don't really care about the unique IDs.  Other than fodder for the
	// hash, they have no significance.  On to the extensions!
	if (cert->version == 3) {
		for (size_t i = 5+valoff; i < nvals; i++) {
			if (vals[i].tagclass != DREW_UTIL_ASN1_TC_CONTEXT ||
					vals[i].tag != 3)
				continue;
			RETFAIL(parse_extensions(asn, &vals[i], cert));
			// Don't allow multiple sets of extensions.
			break;
		}
	}

	RETFAIL(parse_signature(asn, &certvals[1], &cert->sig));

	if (!(p = malloc(certvals[2].length)))
		return -ENOMEM;
	cert->sig.value.data = p;
	RETFAIL(drew_util_asn1_parse_bitstring(asn, &certvals[2], p,
				&cert->sig.value.nbits));

	if (ldr && cert->sig.mdalgo) {
		drew_hash_t hash;
		int id, ret;
		size_t len;

		if ((id = drew_loader_lookup_by_name(ldr, cert->sig.mdalgo, 0, -1)) < 0)
			return id;
		if ((ret = drew_loader_get_functbl(ldr, id,
						(const void **)&hash.functbl)) < 0)
			return ret;
		RETFAIL(hash.functbl->init(&hash, 0, ldr, NULL));
		len = hash.functbl->info2(&hash, DREW_HASH_SIZE_CTX, NULL, NULL);
		hash.functbl->update(&hash, certvals[0].data, certvals[0].length);
		hash.functbl->final(&hash, cert->sig.digest, len, 0);
		hash.functbl->fini(&hash, 0);
	}

	return res;
}
