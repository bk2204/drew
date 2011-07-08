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
	drew_opgp_sig_t p;
	if (!(p = malloc(sizeof(*p))))
		return -ENOMEM;

	memset(p, 0, sizeof(*p));
	*sig = p;
	return 0;
}

int drew_opgp_sig_free(drew_opgp_sig_t *sig)
{
	// FIXME: free all internal data structures and zero.
	free(*sig);
	return 0;
}

int drew_opgp_sig_set_digest_algorithm(drew_opgp_sig_t sig, int algo)
{
	sig->mdalgo = algo;
	return 0;
}

int drew_opgp_sig_get_digest_algorithm(drew_opgp_sig_t sig, const char **name)
{
	return sig->mdalgo;
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
	*exp = sig->etime;
	return 0;
}

int drew_opgp_sig_set_sig_expiration_time(drew_opgp_sig_t sig, time_t exp)
{
	sig->etime = exp;
	return 0;
}

int drew_opgp_is_self_signature(drew_opgp_sig_t sig)
{
	return !!(sig->flags & DREW_OPGP_SIGNATURE_SELF_SIG);
}

int drew_opgp_make_self_signature(drew_opgp_sig_t sig)
{
	if (sig->type < 0x10 || sig->type > 0x13)
		return -DREW_ERR_INVALID;
	sig->flags |= DREW_OPGP_SIGNATURE_SELF_SIG;
	return 0;
}

int drew_opgp_get_cipher_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t *prefs)
{
	if (!drew_opgp_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(prefs, sig->selfsig.prefs+PREFS_CIPHER, sizeof(*prefs));
	return 0;
}

int drew_opgp_set_cipher_prefs(drew_opgp_sig_t sig,
		const drew_opgp_prefs_t *prefs)
{
	if (!drew_opgp_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(sig->selfsig.prefs+PREFS_CIPHER, prefs, sizeof(*prefs));
	return 0;
}

int drew_opgp_get_hash_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t *prefs)
{
	if (!drew_opgp_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(prefs, sig->selfsig.prefs+PREFS_HASH, sizeof(*prefs));
	return 0;
}

int drew_opgp_set_hash_prefs(drew_opgp_sig_t sig,
		const drew_opgp_prefs_t *prefs)
{
	if (!drew_opgp_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(sig->selfsig.prefs+PREFS_HASH, prefs, sizeof(*prefs));
	return 0;
}

int drew_opgp_get_compress_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t *prefs)
{
	if (!drew_opgp_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(prefs, sig->selfsig.prefs+PREFS_COMPRESS, sizeof(*prefs));
	return 0;
}

int drew_opgp_set_compress_prefs(drew_opgp_sig_t sig,
		const drew_opgp_prefs_t *prefs)
{
	if (!drew_opgp_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(sig->selfsig.prefs+PREFS_COMPRESS, prefs, sizeof(*prefs));
	return 0;
}

int drew_opgp_sig_get_key_expiration_time(drew_opgp_sig_t sig, time_t *exp)
{
	if (!drew_opgp_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	*exp = sig->selfsig.keyexp;
	return 0;
}

int drew_opgp_sig_set_key_expiration_time(drew_opgp_sig_t sig, time_t exp)
{
	if (!drew_opgp_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	sig->selfsig.keyexp = exp;
	return 0;
}

int drew_opgp_sig_get_irrevocable(drew_opgp_sig_t sig)
{
	return !!(sig->flags & DREW_OPGP_SIGNATURE_IRREVOCABLE);
}

int drew_opgp_sig_set_irrevocable(drew_opgp_sig_t sig, bool revoke)
{
	if (revoke)
		sig->flags |= DREW_OPGP_SIGNATURE_IRREVOCABLE;
	else
		sig->flags &= ~DREW_OPGP_SIGNATURE_IRREVOCABLE;
	return 0;
}

int drew_opgp_sig_get_exportable(drew_opgp_sig_t sig)
{
	return !(sig->flags & DREW_OPGP_SIGNATURE_LOCAL);
}

int drew_opgp_sig_set_exportable(drew_opgp_sig_t sig, bool export)
{
	if (export)
		sig->flags &= ~DREW_OPGP_SIGNATURE_LOCAL;
	else
		sig->flags |= DREW_OPGP_SIGNATURE_LOCAL;
	return 0;
}

int drew_opgp_sig_get_key_flags(drew_opgp_sig_t sig, int *flags, size_t sz)
{
	if (!drew_opgp_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	if (sz > 0) {
		memset(flags, 0, sz * sizeof(*flags));
		*flags = sig->selfsig.keyflags;
	}
	return 0;
}

int drew_opgp_sig_set_key_flags(drew_opgp_sig_t sig, int *flags)
{
	if (!drew_opgp_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	sig->selfsig.keyflags = *flags;
	return 0;
}

static void sync_cipher_prefs(drew_opgp_sig_t sig)
{
	drew_opgp_prefs_t *prefs = sig->selfsig.prefs+PREFS_CIPHER;
	uint8_t exists[256];
	memset(exists, 0, sizeof(exists));
	prefs->len = 0;
	for (size_t i = 0; i < sizeof(prefs->vals); i++, prefs->len++) {
		// FIXME: make one place for this code to live.
loop:
		if (!prefs->vals[i]) {
			memset(prefs->vals+i, 0, sizeof(prefs->vals)-i);
			break;
		}
		else if (prefs->vals[i] == 5 || prefs->vals[i] > 13 ||
				exists[prefs->vals[i]]) {
			memmove(prefs->vals+i, prefs->vals+i+1, sizeof(prefs->vals)-i);
			prefs->vals[sizeof(prefs->vals)-1] = 0;
			goto loop;
		}
		exists[prefs->vals[i]] = 1;
	}
}

static void sync_compress_prefs(drew_opgp_sig_t sig)
{
	drew_opgp_prefs_t *prefs = sig->selfsig.prefs+PREFS_COMPRESS;
	uint8_t exists[256];
	memset(exists, 0, sizeof(exists));
	prefs->len = 0;
	for (size_t i = 0; i < sizeof(prefs->vals); i++, prefs->len++) {
		// FIXME: make one place for this code to live.
loop:
		if (!prefs->vals[i] && exists[prefs->vals[i]]) {
			memset(prefs->vals+i, 0, sizeof(prefs->vals)-i);
			break;
		}
		else if (prefs->vals[i] > 3 || exists[prefs->vals[i]]) {
			memmove(prefs->vals+i, prefs->vals+i+1, sizeof(prefs->vals)-i);
			prefs->vals[sizeof(prefs->vals)-1] = 0;
			goto loop;
		}
		exists[prefs->vals[i]] = 1;
	}
}

static void sync_hash_prefs(drew_opgp_sig_t sig)
{
	drew_opgp_prefs_t *prefs = sig->selfsig.prefs+PREFS_HASH;
	uint8_t exists[256];
	memset(exists, 0, sizeof(exists));
	prefs->len = 0;
	for (size_t i = 0; i < sizeof(prefs->vals); i++, prefs->len++) {
		// FIXME: make one place for this code to live.
loop:
		if (!prefs->vals[i]) {
			memset(prefs->vals+i, 0, sizeof(prefs->vals)-i);
			break;
		}
		else if (prefs->vals[i] > 11 || exists[prefs->vals[i]]) {
			memmove(prefs->vals+i, prefs->vals+i+1, sizeof(prefs->vals)-i);
			prefs->vals[sizeof(prefs->vals)-1] = 0;
			goto loop;
		}
		exists[prefs->vals[i]] = 1;
	}
}

int drew_opgp_sig_synchronize(drew_opgp_sig_t sig)
{
	if (sig->type < 0x10 || sig->type > 0x13)
		sig->flags &= ~DREW_OPGP_SIGNATURE_SELF_SIG;
	if (sig->flags & DREW_OPGP_SIGNATURE_SELF_SIG) {
		sync_hash_prefs(sig);
		sync_cipher_prefs(sig);
		sync_compress_prefs(sig);
	}
	else {
		memset(&sig->selfsig, 0, sizeof(sig->selfsig));
	}
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
