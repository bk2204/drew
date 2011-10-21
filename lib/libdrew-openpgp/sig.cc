#include "internal.h"
#include "structs.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <drew/drew.h>
#include <drew/hash.h>
#include <drew/mem.h>
#include <drew/plugin.h>
#include <drew/pksig.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/key.h>
#include <drew-opgp/parser.h>
#include <drew-opgp/sig.h>

#include "key.hh"

using namespace drew;

int drew_opgp_sig_new(drew_opgp_sig_t *sig)
{
	drew_opgp_sig_t p = new Signature;
	*sig = p;
	return 0;
}

int drew_opgp_sig_free(drew_opgp_sig_t *sig)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	delete s;
	return 0;
}

int drew_opgp_sig_set_digest_algorithm(drew_opgp_sig_t sig, int algo)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	s->SetDigestAlgorithm(algo);
	return 0;
}

int drew_opgp_sig_get_digest_algorithm(drew_opgp_sig_t sig, const char **name)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	return s->GetDigestAlgorithm();
}

int drew_opgp_sig_set_version(drew_opgp_sig_t sig, int version)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (version < 2 || version > 4)
		return -DREW_ERR_INVALID;
	s->GetFlags() = 0;
	s->SetVersion(version);
	return 0;
}

int drew_opgp_sig_get_flags(drew_opgp_sig_t sig, int *flags, size_t nflags)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!nflags)
		return 0;
	*flags = s->GetFlags();
	return 0;
}

int drew_opgp_sig_get_issuer(drew_opgp_sig_t sig, drew_opgp_keyid_t keyid)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	memcpy(keyid, s->GetKeyID(), sizeof(drew_opgp_keyid_t));
	return 0;
}

int drew_opgp_sig_get_version(drew_opgp_sig_t sig)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	return s->GetVersion();
}

int drew_opgp_sig_get_type(drew_opgp_sig_t sig)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	return s->GetType();
}

int drew_opgp_sig_get_sig_expiration_time(drew_opgp_sig_t sig, time_t *exp)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	*exp = s->GetExpirationTime();
	return 0;
}

int drew_opgp_sig_set_sig_expiration_time(drew_opgp_sig_t sig, time_t exp)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	s->SetExpirationTime(exp);
	return 0;
}

int drew_opgp_sig_is_self_signature(drew_opgp_sig_t sig)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	return s->IsSelfSignature();
}

int drew_opgp_make_self_signature(drew_opgp_sig_t sig)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (s->GetType() < 0x10 || s->GetType() > 0x13)
		return -DREW_ERR_INVALID;
	s->GetFlags() |= DREW_OPGP_SIGNATURE_SELF_SIG;
	return 0;
}

int drew_opgp_sig_get_cipher_prefs(drew_opgp_sig_t sig,
		drew_opgp_prefs_t *prefs)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!drew_opgp_sig_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(prefs, s->GetSelfSignature()->prefs+PREFS_CIPHER, sizeof(*prefs));
	return 0;
}

int drew_opgp_set_cipher_prefs(drew_opgp_sig_t sig,
		const drew_opgp_prefs_t *prefs)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!drew_opgp_sig_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(s->GetSelfSignature()->prefs+PREFS_CIPHER, prefs, sizeof(*prefs));
	return 0;
}

int drew_opgp_sig_get_hash_prefs(drew_opgp_sig_t sig, drew_opgp_prefs_t *prefs)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!drew_opgp_sig_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(prefs, s->GetSelfSignature()->prefs+PREFS_HASH, sizeof(*prefs));
	return 0;
}

int drew_opgp_set_hash_prefs(drew_opgp_sig_t sig,
		const drew_opgp_prefs_t *prefs)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!drew_opgp_sig_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(s->GetSelfSignature()->prefs+PREFS_HASH, prefs, sizeof(*prefs));
	return 0;
}

int drew_opgp_sig_get_compress_prefs(drew_opgp_sig_t sig,
		drew_opgp_prefs_t *prefs)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!drew_opgp_sig_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(prefs, s->GetSelfSignature()->prefs+PREFS_COMPRESS, sizeof(*prefs));
	return 0;
}

int drew_opgp_set_compress_prefs(drew_opgp_sig_t sig,
		const drew_opgp_prefs_t *prefs)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!drew_opgp_sig_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	memcpy(s->GetSelfSignature()->prefs+PREFS_COMPRESS, prefs, sizeof(*prefs));
	return 0;
}

int drew_opgp_sig_get_key_expiration_time(drew_opgp_sig_t sig, time_t *exp)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!drew_opgp_sig_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	*exp = s->GetSelfSignature()->keyexp;
	return 0;
}

int drew_opgp_sig_set_key_expiration_time(drew_opgp_sig_t sig, time_t exp)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!drew_opgp_sig_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	s->GetSelfSignature()->keyexp = exp;
	return 0;
}

int drew_opgp_sig_get_irrevocable(drew_opgp_sig_t sig)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	return !!(s->GetFlags() & DREW_OPGP_SIGNATURE_IRREVOCABLE);
}

int drew_opgp_sig_set_irrevocable(drew_opgp_sig_t sig, bool revoke)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (revoke)
		s->GetFlags() |= DREW_OPGP_SIGNATURE_IRREVOCABLE;
	else
		s->GetFlags() &= ~DREW_OPGP_SIGNATURE_IRREVOCABLE;
	return 0;
}

int drew_opgp_sig_get_exportable(drew_opgp_sig_t sig)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	return !(s->GetFlags() & DREW_OPGP_SIGNATURE_LOCAL);
}

int drew_opgp_sig_set_exportable(drew_opgp_sig_t sig, bool is_export)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (is_export)
		s->GetFlags() &= ~DREW_OPGP_SIGNATURE_LOCAL;
	else
		s->GetFlags() |= DREW_OPGP_SIGNATURE_LOCAL;
	return 0;
}

int drew_opgp_sig_get_key_flags(drew_opgp_sig_t sig, int *flags, size_t sz)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!drew_opgp_sig_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	if (sz > 0) {
		memset(flags, 0, sz * sizeof(*flags));
		*flags = s->GetSelfSignature()->keyflags;
	}
	return 0;
}

int drew_opgp_sig_set_key_flags(drew_opgp_sig_t sig, int *flags)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (!drew_opgp_sig_is_self_signature(sig))
		return -DREW_ERR_NOT_ALLOWED;
	s->GetSelfSignature()->keyflags = *flags;
	return 0;
}

static void sync_cipher_prefs(drew_opgp_sig_t sig)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	drew_opgp_prefs_t *prefs = s->GetSelfSignature()->prefs+PREFS_CIPHER;
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
	Signature *s = reinterpret_cast<Signature *>(sig);
	drew_opgp_prefs_t *prefs = s->GetSelfSignature()->prefs+PREFS_COMPRESS;
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
	Signature *s = reinterpret_cast<Signature *>(sig);
	drew_opgp_prefs_t *prefs = s->GetSelfSignature()->prefs+PREFS_HASH;
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

static void free_subpacket_group(drew_opgp_subpacket_group_t *spg)
{
	for (size_t i = 0; i < spg->nsubpkts; i++)
		drew_mem_free(spg->subpkts[i].data);
	drew_mem_free(spg->subpkts);
	drew_mem_free(spg->data);
	memset(spg, 0, sizeof(*spg));
}

static void free_subpackets(drew_opgp_sig_t sig)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	free_subpacket_group(&s->GetHashedSubpackets());
	free_subpacket_group(&s->GetUnhashedSubpackets());
}

static int add_subpacket(drew_opgp_sig_t sig, uint8_t type, const uint8_t *data,
		size_t len)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	drew_opgp_subpacket_group_t &hashed = s->GetHashedSubpackets();
	drew_opgp_subpacket_t *sp, *arr;
	uint8_t *p;

	if (len+1 >= 192)
		return -DREW_ERR_NOT_IMPL;
	arr = (drew_opgp_subpacket_t *)drew_mem_realloc(hashed.subpkts,
			sizeof(*hashed.subpkts) * (hashed.nsubpkts + 1));
	if (!arr)
		return -ENOMEM;
	hashed.subpkts = arr;
	sp = arr+hashed.nsubpkts;
	sp->type = type;
	sp->lenoflen = 1;
	sp->critical = false;
	sp->len = len;
	sp->data = (uint8_t *)drew_mem_malloc(sp->len);
	if (!sp->data) 
		return -ENOMEM;
	memcpy(sp->data, data, len);

	p = (uint8_t *)drew_mem_realloc(hashed.data, hashed.len + len + 2);
	if (!p)
		return -ENOMEM;
	hashed.data = p;
	p += hashed.len;
	p[0] = len + 1;
	p[1] = type;
	memcpy(p+2, data, len);
	hashed.len += len + 2;
	return 0;
}

static int add_byte_subpacket(drew_opgp_sig_t sig, uint8_t type, uint8_t byte)
{
	return add_subpacket(sig, type, &byte, 1);
}

static int update_subpackets(drew_opgp_sig_t sig)
{
	Signature *sigo = reinterpret_cast<Signature *>(sig);
	selfsig_t *s = sigo->GetSelfSignature();
	int &flags = sigo->GetFlags();
	size_t len;
	free_subpackets(sig);
	if (flags & DREW_OPGP_SIGNATURE_IRREVOCABLE)
		RETFAIL(add_byte_subpacket(sig, 0x07, 0x00));
	if (flags & DREW_OPGP_SIGNATURE_LOCAL)
		RETFAIL(add_byte_subpacket(sig, 0x04, 0x00));
	if (s && (len = s->prefs[PREFS_CIPHER].len))
		RETFAIL(add_subpacket(sig, 0x0b, s->prefs[PREFS_CIPHER].vals, len));
	if (s && (len = s->prefs[PREFS_HASH].len))
		RETFAIL(add_subpacket(sig, 0x15, s->prefs[PREFS_HASH].vals, len));
	if (s && (len = s->prefs[PREFS_COMPRESS].len))
		RETFAIL(add_subpacket(sig, 0x16, s->prefs[PREFS_COMPRESS].vals, len));
	if (s && s->keyflags)
		RETFAIL(add_byte_subpacket(sig, 0x2b, s->keyflags));
	return 0;
}

int drew_opgp_sig_synchronize(drew_opgp_sig_t sig)
{
	Signature *s = reinterpret_cast<Signature *>(sig);
	if (s->GetType() < 0x10 || s->GetType() > 0x13)
		s->GetFlags() &= ~DREW_OPGP_SIGNATURE_SELF_SIG;
	if (s->GetVersion() == 4 && s->GetFlags() & DREW_OPGP_SIGNATURE_SELF_SIG) {
		sync_hash_prefs(sig);
		sync_cipher_prefs(sig);
		sync_compress_prefs(sig);
		s->GetSelfSignature()->keyflags &= 0xbf;
	}
	else
		s->ClearSelfSignature();
	if (s->GetVersion() == 4)
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
