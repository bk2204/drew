#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <drew/drew.h>
#include <drew/mem.h>
#include <drew/plugin.h>
#include <drew-util/asn1.h>
#include <drew-util/codec.h>
#include <drew-util/x509.h>

#define DIM(x) (sizeof(x)/sizeof(x[0]))

#define FAILCODE(code, expr) \
	do { \
		int result_code = 0; \
		if ((result_code = (expr)) < 0) { \
			fprintf(stderr, "Failed with error %d (%d with offset).\n" \
					"Exiting with code %d.\n", \
					-result_code, (-result_code) >= 0x10000 ? \
					(-result_code % 0x10000) : (-result_code), code); \
			return code; \
		} \
	} while (0)

struct oids {
	const char *name;
	size_t nvals;
	size_t vals[9];
} oids[] = {
	{"md2WithRSAEncryption", 7, {1, 2, 840, 113549, 1, 1, 2}},
	{"md4WithRSAEncryption", 7, {1, 2, 840, 113549, 1, 1, 3}},
	{"md5WithRSAEncryption", 7, {1, 2, 840, 113549, 1, 1, 4}},
	{"sha1WithRSAEncryption", 7, {1, 2, 840, 113549, 1, 1, 5}},
	{"sha224WithRSAEncryption", 7, {1, 2, 840, 113549, 1, 1, 14}},
	{"sha256WithRSAEncryption", 7, {1, 2, 840, 113549, 1, 1, 11}},
	{"sha384WithRSAEncryption", 7, {1, 2, 840, 113549, 1, 1, 12}},
	{"sha512WithRSAEncryption", 7, {1, 2, 840, 113549, 1, 1, 13}},
	{"id-dsa-with-sha1", 6, {1, 2, 840, 10040, 4, 3}},
	{"id-dsa-with-sha224", 9, {2, 16, 840, 1, 101, 3, 4, 3, 1}},
	{"id-dsa-with-sha256", 9, {2, 16, 840, 1, 101, 3, 4, 3, 2}},
	{"ecdsa-with-SHA224", 7, {1, 2, 840, 10045, 4, 3, 1}},
	{"ecdsa-with-SHA256", 7, {1, 2, 840, 10045, 4, 3, 2}},
	{"ecdsa-with-SHA384", 7, {1, 2, 840, 10045, 4, 3, 3}},
	{"ecdsa-with-SHA512", 7, {1, 2, 840, 10045, 4, 3, 4}},
};

struct oids attr_types[] = {
	{"emailAddress", 7, {1, 2, 840, 113549, 1, 9, 1}},
	{"cn", 4, {2, 5, 4, 3}},
	{"serialNumber", 4, {2, 5, 4, 5}},
	{"c", 4, {2, 5, 4, 6}},
	{"l", 4, {2, 5, 4, 7}},
	{"st", 4, {2, 5, 4, 8}},
	{"o", 4, {2, 5, 4, 10}},
	{"u", 4, {2, 5, 4, 11}},
};

struct oids key_types[] = {
	{"RSA", 7, {1, 2, 840, 113549, 1, 1, 1}},
	{"DSA", 6, {1, 2, 840, 10040, 4, 1}},
	{"ECDSA", 6, {1, 2, 840, 10045, 2, 1}},
};

const char *get_oidname(const struct oids *oidp, size_t noids,
		const drew_util_asn1_oid_t *oid)
{
	for (size_t i = 0; i < noids; i++) {
		if (oid->length != oidp[i].nvals)
			continue;
		if (!memcmp(oidp[i].vals, oid->values, oid->length * sizeof(size_t)))
			return oidp[i].name;
	}
	return "unknown";
}

const char *get_signame(const drew_util_asn1_oid_t *oid)
{
	return get_oidname(oids, DIM(oids), oid);
}

const char *get_attrname(const drew_util_asn1_oid_t *oid)
{
	return get_oidname(attr_types, DIM(attr_types), oid);
}

const char *get_key_type(const drew_util_asn1_oid_t *oid)
{
	return get_oidname(key_types, DIM(key_types), oid);
}

int get_digest_length(const drew_util_x509_cert_t *cert)
{
	if (!strncmp("MD", cert->sig.mdalgo, 2))
		return 16;
	else if (!strcmp("SHA-1", cert->sig.mdalgo))
		return 20;
	else if (!strcmp("SHA-224", cert->sig.mdalgo))
		return 28;
	else if (!strcmp("SHA-256", cert->sig.mdalgo))
		return 32;
	else if (!strcmp("SHA-384", cert->sig.mdalgo))
		return 48;
	else if (!strcmp("SHA-512", cert->sig.mdalgo))
		return 64;
	else
		return 0;
}

int main(int argc, char **argv)
{
	drew_util_asn1_t parser;
	drew_util_x509_cert_t cert;
	drew_util_codec_t codec;
	uint8_t *p, *decdata = NULL;
	int fd;
	int ret = 0, digestlen;
	size_t len = 0;
	struct stat st;
	drew_loader_t *ldr;

	if ((fd = open(argv[1], O_RDONLY)) < 0)
		return 2;
	if (fstat(fd, &st))
		return 3;
	if ((p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) ==
			MAP_FAILED)
		return 4;

	drew_loader_new(&ldr);
	drew_loader_load_plugin(ldr, NULL, NULL);

	printf("Parsing certificate from %s.\n", argv[1]);
	FAILCODE(5, drew_util_asn1_init(&parser));
	FAILCODE(5, drew_util_codec_init(&codec));
	FAILCODE(6, drew_util_asn1_set_encoding(parser, DREW_UTIL_ASN1_ENC_DER));
	FAILCODE(7, drew_util_asn1_set_flags(parser, 0));
	ret = drew_util_codec_detect(codec, NULL, NULL, NULL, p, st.st_size);
	if (ret < 0)
		FAILCODE(10, ret);
	else if (ret) {
		/* Probably unencoded. */
		decdata = p;
		len = st.st_size;
	}
	else {
		decdata = drew_mem_malloc(st.st_size);
		if ((ret = drew_util_codec_decode_all(codec, decdata, st.st_size, p,
						st.st_size)) < 0) {
			drew_mem_free(decdata);
			FAILCODE(11, ret);
		}
		len = ret;
	}
	if ((ret = drew_util_x509_parse_certificate(parser, decdata, len, &cert,
				ldr)) && ret != -DREW_ERR_NOT_IMPL)
		FAILCODE(8, ret);
	printf("Certificate is version %d.\nSignature OID is ", cert.version);
	for (size_t i = 0; i < cert.sig.algo.oid.length; i++)
		printf("%zu%s", cert.sig.algo.oid.values[i],
				(i == cert.sig.algo.oid.length-1) ? "" : ".");
	printf(" (%s).\n", get_signame(&cert.sig.algo.oid));
	printf("Public key algorithm is %s; hash algorithm is %s.\n",
			cert.sig.pkalgo ? cert.sig.pkalgo : "unknown",
			cert.sig.mdalgo ? cert.sig.mdalgo : "unknown");
	digestlen = get_digest_length(&cert);
	printf("Digest is ");
	for (size_t i = 0; i < digestlen; i++)
		printf("%02x", cert.sig.digest[i]);
	printf(".\nIssuer is:\n");
	for (size_t i = 0; i < cert.issuer_len; i++) {
		printf("\t");
		for (size_t j = 0; j < cert.issuer[i].type.length; j++)
			printf("%zu%s", cert.issuer[i].type.values[j],
					(j == cert.issuer[i].type.length-1) ? "" : ".");
		printf(" (%s): %s\n", get_attrname(&cert.issuer[i].type),
				cert.issuer[i].string);
	}
	printf("Subject is:\n");
	for (size_t i = 0; i < cert.subject_len; i++) {
		printf("\t");
		for (size_t j = 0; j < cert.subject[i].type.length; j++)
			printf("%zu%s", cert.subject[i].type.values[j],
					(j == cert.subject[i].type.length-1) ? "" : ".");
		printf(" (%s): %s\n", get_attrname(&cert.subject[i].type),
				cert.subject[i].string);
	}
	time_t tt;
	char *tp;
	// Two printf statements because of static buffer.
	tt = cert.not_before;
	tp = asctime(gmtime(&tt));
	tp[24] = 0;
	printf("Subject is:\n\tNot Before: %s UTC\n", tp);
	tt = cert.not_after;
	tp = asctime(gmtime(&tt));
	tp[24] = 0;
	printf("\tNot After: %s UTC\n", tp);
	if (cert.flags[0]) {
		printf("Certificate has the following peculiarities:\n");
		if (cert.flags[0] & DREW_UTIL_X509_CERT_MISPARSE_VERSION)
			printf("\tVersion encoding was a naked integer.\n");
		if (cert.flags[0] & DREW_UTIL_X509_CERT_DEFAULT_VERSION)
			printf("\tVersion was omitted.\n");
	}
	printf("Extensions are%s\n", cert.extensions_len ? ":" : "absent.");
	for (size_t i = 0; i < cert.extensions_len; i++) {
		drew_util_x509_extension_t *ext = cert.extensions + i;
		printf("\t");
		for (size_t j = 0; j < ext->oid.length; j++)
			printf("%zu%s", ext->oid.values[j],
					(j == ext->oid.length-1) ? "" : ".");
		printf(" (%scritical): ", ext->critical ? "" : "not ");
		for (size_t j = 0; j < ext->len; j++)
			printf("%02x", ext->value[j]);
		printf("\n");
	}
	const char *ktype = get_key_type(&cert.pubkey.oid);
	printf("Key type is %s (", ktype ? ktype : "unknown");
	for (size_t i = 0; i < cert.pubkey.oid.length; i++)
		printf("%zu%s", cert.pubkey.oid.values[i],
				(i == cert.pubkey.oid.length-1) ? "" : ".");
	printf(")");
	if (ktype) {
		printf(":\n");
		for (size_t i = 0; i < DREW_UTIL_X509_MAX_MPIS; i++) {
			if (cert.pubkey.mpis[i].data) {
				printf("MPI %zu: ", i);
				for (size_t j = 0; j < cert.pubkey.mpis[i].len; j++)
					printf("%02x", cert.pubkey.mpis[i].data[j]);
				printf("\n");
			}
		}
	}
	printf("\n");
	if (decdata != p)
		drew_mem_free(decdata);
	printf("Bye.\n");
	FAILCODE(9, drew_util_asn1_fini(&parser));
	FAILCODE(9, drew_util_codec_fini(&codec));
	drew_loader_free(&ldr);
}
