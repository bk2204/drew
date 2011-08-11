#ifndef DREW_OPGP_SIG_H
#define DREW_OPGP_SIG_H

#include <drew-opgp/key.h>

int drew_opgp_sig_get_flags(drew_opgp_sig_t sig, int *flags, size_t nflags);
int drew_opgp_sig_get_issuer(drew_opgp_sig_t sig, drew_opgp_keyid_t keyid);
int drew_opgp_sig_new(drew_opgp_sig_t *sig);
int drew_opgp_sig_free(drew_opgp_sig_t *sig);
int drew_opgp_sig_set_digest_algorithm(drew_opgp_sig_t sig, int algo);
int drew_opgp_sig_get_digest_algorithm(drew_opgp_sig_t sig, const char **name);
int drew_opgp_sig_set_version(drew_opgp_sig_t sig, int version);
int drew_opgp_sig_get_flags(drew_opgp_sig_t sig, int *flags, size_t nflags);
int drew_opgp_sig_get_issuer(drew_opgp_sig_t sig, drew_opgp_keyid_t keyid);
int drew_opgp_sig_get_version(drew_opgp_sig_t sig);
int drew_opgp_sig_get_type(drew_opgp_sig_t sig);
int drew_opgp_sig_get_sig_expiration_time(drew_opgp_sig_t sig, time_t *exp);
int drew_opgp_sig_set_sig_expiration_time(drew_opgp_sig_t sig, time_t exp);
int drew_opgp_sig_is_self_signature(drew_opgp_sig_t sig);
int drew_opgp_make_self_signature(drew_opgp_sig_t sig);
int drew_opgp_sig_get_cipher_prefs(drew_opgp_sig_t sig,
		drew_opgp_prefs_t *prefs);
int drew_opgp_set_cipher_prefs(drew_opgp_sig_t sig,
		const drew_opgp_prefs_t *prefs);
int drew_opgp_sig_get_hash_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t *prefs);
int drew_opgp_set_hash_prefs(drew_opgp_sig_t sig,
		const drew_opgp_prefs_t *prefs);
int drew_opgp_sig_get_compress_prefs(drew_opgp_sig_t sig,
		drew_opgp_prefs_t *prefs);
int drew_opgp_set_compress_prefs(drew_opgp_sig_t sig,
		const drew_opgp_prefs_t *prefs);
int drew_opgp_sig_get_key_expiration_time(drew_opgp_sig_t sig, time_t *exp);
int drew_opgp_sig_set_key_expiration_time(drew_opgp_sig_t sig, time_t exp);
int drew_opgp_sig_get_irrevocable(drew_opgp_sig_t sig);
int drew_opgp_sig_set_irrevocable(drew_opgp_sig_t sig, bool revoke);
int drew_opgp_sig_get_exportable(drew_opgp_sig_t sig);
int drew_opgp_sig_set_exportable(drew_opgp_sig_t sig, bool is_export);
int drew_opgp_sig_get_key_flags(drew_opgp_sig_t sig, int *flags, size_t sz);
int drew_opgp_sig_set_key_flags(drew_opgp_sig_t sig, int *flags);
int drew_opgp_sig_synchronize(drew_opgp_sig_t sig);
int drew_opgp_sig_generate_direct_key(drew_opgp_sig_t sig,
		int mdalgo, drew_opgp_key_t signer, drew_opgp_key_t signedk);
int drew_opgp_sig_verify_direct_key(drew_opgp_sig_t sig,
		drew_opgp_key_t signer, drew_opgp_key_t signedk);
int drew_opgp_sig_generate_data(drew_opgp_sig_t sig, drew_opgp_key_t key,
		int type, int mdalgo, const uint8_t *data, size_t len);
int drew_opgp_sig_verify_data(drew_opgp_sig_t sig, drew_opgp_key_t key,
		const uint8_t *data, size_t len);
int drew_opgp_sig_generate_hash(drew_opgp_sig_t sig, drew_opgp_key_t key,
		int type, int mdalgo, const uint8_t *hash, size_t len);
int drew_opgp_sig_verify_hash(drew_opgp_sig_t sig, drew_opgp_key_t key,
		int type, int mdalgo, const uint8_t *hash, size_t len);
int drew_opgp_sig_generate_standalone(drew_opgp_sig_t sig, drew_opgp_key_t key,
		int mdalgo);
int drew_opgp_sig_verify_standalone(drew_opgp_sig_t sig, drew_opgp_key_t key);

#endif
