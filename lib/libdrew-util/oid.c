#include "internal.h"

#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <drew/drew.h>
#include <drew-util/drew-util.h>
#include <drew-util/asn1.h>

struct pksig_oids {
	const char *name;
	const char *hash;
	const char *pkalgo;
	size_t length;
	size_t vals[9];
};


static const struct pksig_oids s_pksig_oids[] = {
	{"md2WithRSAEncryption", "MD2", "RSA", 7, {1, 2, 840, 113549, 1, 1, 2}},
	{"md4WithRSAEncryption", "MD4", "RSA", 7, {1, 2, 840, 113549, 1, 1, 3}},
	{"md5WithRSAEncryption", "MD5", "RSA", 7, {1, 2, 840, 113549, 1, 1, 4}},
	{"sha1WithRSAEncryption", "SHA-1", "RSA", 7, {1, 2, 840, 113549, 1, 1, 5}},
	{"sha224WithRSAEncryption","SHA-224", "RSA", 7,
		{1, 2, 840, 113549, 1, 1, 14}},
	{"sha256WithRSAEncryption","SHA-256", "RSA", 7,
		{1, 2, 840, 113549, 1, 1, 11}},
	{"sha384WithRSAEncryption","SHA-384", "RSA", 7,
		{1, 2, 840, 113549, 1, 1, 12}},
	{"sha512WithRSAEncryption","SHA-512", "RSA", 7,
		{1, 2, 840, 113549, 1, 1, 13}},
	{"id-dsa-with-sha1", "SHA-1", "DSA", 6, {1, 2, 840, 10040, 4, 3}},
	{"id-dsa-with-sha224", "SHA-224", "DSA", 9,
		{2, 16, 840, 1, 101, 3, 4, 3, 1}},
	{"id-dsa-with-sha256", "SHA-256", "DSA", 9,
		{2, 16, 840, 1, 101, 3, 4, 3, 2}},
	{"ecdsa-with-SHA224", "SHA-224", "ECDSA", 7, {1, 2, 840, 10045, 4, 3, 1}},
	{"ecdsa-with-SHA256", "SHA-256", "ECDSA", 7, {1, 2, 840, 10045, 4, 3, 2}},
	{"ecdsa-with-SHA384", "SHA-384", "ECDSA", 7, {1, 2, 840, 10045, 4, 3, 3}},
	{"ecdsa-with-SHA512", "SHA-512", "ECDSA", 7, {1, 2, 840, 10045, 4, 3, 4}},
};

int drew_util_asn1_oid_lookup_pksig_algo(const drew_util_asn1_oid_t *oid,
		const char **name, const char **pkalgo, const char **hash,
		const char **transform, void **params)
{
	if (!oid->values)
		return -DREW_ERR_INVALID;

	for (size_t i = 0; i < DIM(s_pksig_oids); i++) {
		const struct pksig_oids *item = s_pksig_oids + i;
		if (oid->length != item->length)
			continue;
		if (!memcmp(oid->values, item->vals,
					item->length * sizeof(*item->vals))) {
			if (name)
				*name = item->name;
			if (pkalgo)
				*pkalgo = item->pkalgo;
			if (hash)
				*hash = item->hash;
			if (transform)
				*transform = NULL;
			if (params)
				*params = NULL;
			return 0;
		}
	}
	return -DREW_ERR_NONEXISTENT;
}
