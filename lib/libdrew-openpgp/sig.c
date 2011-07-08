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

static void free_subpackets(drew_opgp_sig_t sig)
{
	for (size_t i = 0; i < sig->nhashed; i++)
		free(sig->hashed[i].data);
	free(sig->hashed);
	free(sig->hasheddata);
	sig->hashedlen = sig->nhashed = 0;
	sig->hashed = NULL;
	sig->hasheddata = NULL;
	for (size_t i = 0; i < sig->nunhashed; i++)
		free(sig->unhashed[i].data);
	free(sig->unhashed);
	free(sig->unhasheddata);
	sig->unhashedlen = sig->nunhashed = 0;
	sig->unhashed = NULL;
	sig->unhasheddata = NULL;
}

static int add_subpacket(drew_opgp_sig_t sig, uint8_t type, const uint8_t *data,
		size_t len)
{
	drew_opgp_subpacket_t *sp, *arr;
	uint8_t *p;

	if (len+1 >= 192)
		return -DREW_ERR_NOT_IMPL;
	arr = realloc(sig->hashed, sizeof(*sig->hashed) * (sig->nhashed + 1));
	if (!arr)
		return -ENOMEM;
	sig->hashed = arr;
	sp = arr+sig->nhashed;
	sp->type = type;
	sp->lenoflen = 1;
	sp->critical = false;
	sp->len = len;
	sp->data = malloc(sp->len);
	if (!sp->data) 
		return -ENOMEM;
	memcpy(sp->data, data, len);

	p = realloc(sig->hasheddata, sig->hashedlen + len + 2);
	if (!p)
		return -ENOMEM;
	sig->hasheddata = p;
	p += sig->hashedlen;
	p[0] = len + 1;
	p[1] = type;
	memcpy(p+2, data, len);
	sig->hashedlen += len + 2;
	return 0;
}

static int add_byte_subpacket(drew_opgp_sig_t sig, uint8_t type, uint8_t byte)
{
	return add_subpacket(sig, type, &byte, 1);
}

static int update_subpackets(drew_opgp_sig_t sig)
{
	selfsig_t *s = &sig->selfsig;
	size_t len;
	free_subpackets(sig);
	if (sig->flags & DREW_OPGP_SIGNATURE_IRREVOCABLE)
		RETFAIL(add_byte_subpacket(sig, 0x07, 0x00));
	if (sig->flags & DREW_OPGP_SIGNATURE_LOCAL)
		RETFAIL(add_byte_subpacket(sig, 0x04, 0x00));
	if ((len = s->prefs[PREFS_CIPHER].len))
		RETFAIL(add_subpacket(sig, 0x0b, s->prefs[PREFS_CIPHER].vals, len));
	if ((len = s->prefs[PREFS_HASH].len))
		RETFAIL(add_subpacket(sig, 0x15, s->prefs[PREFS_HASH].vals, len));
	if ((len = s->prefs[PREFS_COMPRESS].len))
		RETFAIL(add_subpacket(sig, 0x16, s->prefs[PREFS_COMPRESS].vals, len));
	if (s->keyflags)
		RETFAIL(add_byte_subpacket(sig, 0x2b, s->keyflags));
	return 0;
}

int drew_opgp_sig_synchronize(drew_opgp_sig_t sig)
{
	if (sig->type < 0x10 || sig->type > 0x13)
		sig->flags &= ~DREW_OPGP_SIGNATURE_SELF_SIG;
	if (sig->ver == 4 && sig->flags & DREW_OPGP_SIGNATURE_SELF_SIG) {
		sync_hash_prefs(sig);
		sync_cipher_prefs(sig);
		sync_compress_prefs(sig);
		sig->selfsig.keyflags &= 0xbf;
	}
	else
		memset(&sig->selfsig, 0, sizeof(sig->selfsig));
	if (sig->ver == 4)
		update_subpackets(sig);
	return 0;
}

int drew_opgp_sig_generate_direct_key(drew_opgp_sig_t sig,
		int mdalgo, drew_opgp_key_t signer, drew_opgp_key_t signedk)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_verify_direct_key(drew_opgp_sig_t sig,
		drew_opgp_key_t signer, drew_opgp_key_t signedk)
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

int drew_opgp_sig_generate_hash(drew_opgp_sig_t sig, drew_opgp_key_t key,
		int type, int mdalgo, const uint8_t *hash, size_t len)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_verify_hash(drew_opgp_sig_t sig, drew_opgp_key_t key,
		int type, int mdalgo, const uint8_t *hash, size_t len)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_generate_standalone(drew_opgp_sig_t sig, drew_opgp_key_t key,
		int mdalgo)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_sig_verify_standalone(drew_opgp_sig_t sig, drew_opgp_key_t key)
{
	return -DREW_ERR_NOT_IMPL;
}
