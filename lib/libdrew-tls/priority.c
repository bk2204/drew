#include "internal.h"

#include <drew-tls/priority.h>

struct mapping {
	int val;					// The value used in the enumeration.
	int assoc_val;				// The value of an associated constant.
	int bytesize;
	const char *drew_algo;		// The name drew uses for this algorithm.
	const char *gnutls_algo;	// The name gnutls uses.
	const char *openssl_algo;	// The name openssl uses.
};

static const struct mapping ciphers[] = {
	{cipher_aes128,      mode_cbc,    16, "AES128", "AES-128-CBC", ""},
	{cipher_aes256,      mode_cbc,    32, "AES256", "AES-256-CBC", ""},
	{cipher_aes128,      mode_gcm,    16, "AES128", "", ""},
	{cipher_aes256,      mode_gcm,    32, "AES256", "", ""},
	{cipher_camellia128, mode_cbc,    16, "Camellia", "CAMELLIA-128-CBC", ""},
	{cipher_camellia256, mode_cbc,    32, "Camellia", "CAMELLIA-256-CBC", ""},
	{cipher_rc4,         mode_stream, 16, "RC4", "ARCFOUR-128", ""},
	{cipher_rc4_40,      mode_stream,  5, "RC4", "ARCFOUR-40", ""},
	{cipher_3des,        mode_cbc,    24, "DESede", "3DES-CBC", ""},
	{cipher_rc2_40,      mode_cbc,     5, "RC2", "", ""},
	{cipher_idea,        mode_cbc,    16, "IDEA", "", ""},
	{cipher_des,         mode_cbc,     8, "DES", "", ""},
	{cipher_des_40,      mode_cbc,     5, "DES", "", ""},
	{cipher_seed,        mode_cbc,    16, "SEED", "", ""},
	{cipher_aria128,     mode_cbc,    16, "ARIA", "", ""},
	{cipher_aria256,     mode_cbc,    32, "ARIA", "", ""},
	{cipher_aria128,     mode_gcm,    16, "ARIA", "", ""},
	{cipher_aria256,     mode_gcm,    32, "ARIA", "", ""}
};

static const struct mapping keyex[] = {
	{keyex_rsa, 0, "RSA", "RSA", ""},
};

int drew_tls_priority_init(drew_tls_priority_t *prio)
{
}

int drew_tls_priority_fini(drew_tls_priority_t *prio)
{
}

int drew_tls_priority_set_string(drew_tls_priority_t prio, const char *s)
{
}
