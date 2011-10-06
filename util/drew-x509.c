#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <drew/drew.h>
#include <drew/mem.h>
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
					(-result_code - 0x10000) : (-result_code), code); \
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

const char *get_signame(const drew_util_asn1_oid_t *oid)
{

	for (size_t i = 0; i < DIM(oids); i++) {
		if (oid->length != oids[i].nvals)
			continue;
		if (!memcmp(oids[i].vals, oid->values, oid->length * sizeof(size_t)))
			return oids[i].name;
	}
	return "unknown";
}

int main(int argc, char **argv)
{
	drew_util_asn1_t parser;
	drew_util_x509_cert_t cert;
	drew_util_codec_t codec;
	uint8_t *p, *decdata = NULL;
	int fd;
	int ret = 0;
	size_t len = 0;
	struct stat st;

	if ((fd = open(argv[1], O_RDONLY)) < 0)
		return 2;
	if (fstat(fd, &st))
		return 3;
	if ((p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) ==
			MAP_FAILED)
		return 4;

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
	FAILCODE(8, drew_util_x509_parse_certificate(parser, decdata, len, &cert));
	printf("Certificate is version %d.\nSignature OID is ", cert.version);
	for (size_t i = 0; i < cert.sig.algo.algo.length; i++)
		printf("%zu%s", cert.sig.algo.algo.values[i],
				(i == cert.sig.algo.algo.length-1) ? "" : ".");
	printf(" (%s).\n", get_signame(&cert.sig.algo.algo));
	if (cert.flags[0]) {
		printf("Certificate has the following peculiarities:\n");
		if (cert.flags[0] & DREW_UTIL_X509_CERT_MISPARSE_VERSION)
			printf("\tVersion encoding was a naked integer.\n");
		if (cert.flags[0] & DREW_UTIL_X509_CERT_DEFAULT_VERSION)
			printf("\tVersion was omitted.\n");
	}
	if (decdata != p)
		drew_mem_free(decdata);
	printf("Bye.\n");
	FAILCODE(9, drew_util_asn1_fini(&parser));
	FAILCODE(9, drew_util_codec_fini(&codec));
}
