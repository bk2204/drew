#include "internal.h"
#include "structs.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <drew/drew.h>
#include <drew/hash.h>
#include <drew/plugin.h>
#include <drew/pksig.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/key.h>
#include <drew-opgp/parser.h>

int drew_opgp_sig_new(drew_opgp_sig_t *sig)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_free(drew_opgp_sig_t *sig)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_set_digest_algorithm(drew_opgp_sig_t sig, int algo)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_get_digest_algorithm(drew_opgp_sig_t sig, const char **name)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_set_version(drew_opgp_sig_t sig, int version)
{
	if (version < 2 || version > 4)
		return -DREW_ERR_INVALID;
	sig->flags = 0;
	sig->ver = version;
	return 0;
}

int drew_opgp_sig_get_version(drew_opgp_sig_t sig)
{
	return sig->ver;
}

int drew_opgp_sig_get_type(drew_opgp_sig_t sig)
{
	return sig->type;
}

int drew_opgp_sig_get_sig_expiration_time(drew_opgp_sig_t sig, time_t *exp)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_set_sig_expiration_time(drew_opgp_sig_t sig, time_t exp)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_is_self_signature(drew_opgp_sig_t sig)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_make_self_signature(drew_opgp_sig_t sig)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_get_cipher_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t *prefs)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_set_cipher_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t prefs)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_get_hash_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t *prefs)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_set_hash_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t prefs)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_get_compress_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t *prefs)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_set_compress_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t prefs)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_get_key_expiration_time(drew_opgp_sig_t sig, time_t *exp)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_set_key_expiration_time(drew_opgp_sig_t sig, time_t exp)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_get_revocable(drew_opgp_sig_t sig)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_set_revocable(drew_opgp_sig_t sig, bool export)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_get_exportable(drew_opgp_sig_t sig)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_set_exportable(drew_opgp_sig_t sig, bool export)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_get_key_flags(drew_opgp_sig_t sig, int *flags, size_t sz)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_set_key_flags(drew_opgp_sig_t sig, int *flags)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_synchronize(drew_opgp_sig_t sig)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Generate a signature over the given data of the given type. */
int drew_opgp_sig_generate_data(drew_opgp_sig_t sig, drew_opgp_key_t key,
		int type, int mdalgo, const uint8_t *data, size_t len)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Verify a signature over the given data. */
int drew_opgp_sig_verify_data(drew_opgp_sig_t sig, drew_opgp_key_t key,
		const uint8_t *data, size_t len)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_generate_hash(drew_opgp_key_t key, int type, int mdalgo,
		const uint8_t *hash, size_t len)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_verify_hash(drew_opgp_key_t key, int type, int mdalgo,
		const uint8_t *hash, size_t len)
{
	return -DREW_ERR_NOT_IMPL;
}
