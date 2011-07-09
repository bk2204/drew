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

int drew_opgp_key_new(drew_opgp_key_t *key, const drew_loader_t *ldr)
{
	drew_opgp_key_t k;
	if (!(k = calloc(sizeof(*k), 1)))
		return -ENOMEM;
	k->ldr = ldr;
	*key = k;
	return 0;
}

int drew_opgp_key_free(drew_opgp_key_t *key)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Does secret material exist for this key, either in a dummy or usable form?
 * Returns 1 for true and 0 for false.
 */
int drew_opgp_key_has_secret(drew_opgp_key_t key)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Does usable secret material exist for this key? */
int drew_opgp_key_has_usable_secret(drew_opgp_key_t key)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Is the key physically capable of signing? */
int drew_opgp_key_can_sign(drew_opgp_key_t key)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Is the key physically capable of encrypting? */
int drew_opgp_key_can_encrypt(drew_opgp_key_t key)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Is the key revoked? */
int drew_opgp_key_is_revoked(drew_opgp_key_t key, int flags)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Is the key expired? */
int drew_opgp_key_is_expired(drew_opgp_key_t key, int flags)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Is the key permitted to perform all of the behaviors specified? */
int drew_opgp_key_can_do(drew_opgp_key_t key, int flags)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Returns the version of the key. */
int drew_opgp_key_get_version(drew_opgp_key_t key)
{
	return key->pub.ver;
}

int drew_opgp_key_get_type(drew_opgp_key_t key)
{
	return key->pub.algo;
}

/* Returns the number of subkeys placed in subkeys. */
int drew_opgp_key_get_subkeys(drew_opgp_key_t key, drew_opgp_key_t *subkeys)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Generate a key of type algo nbits long with order (e.g. DSA q) order bits
 * long that expires at the given time.
 */
int drew_opgp_key_generate(drew_opgp_key_t key, uint8_t algo, size_t nbits,
		size_t order, time_t expires)
{
	return -DREW_ERR_NOT_IMPL;
}

struct hash_algos {
	const char *algoname;
	size_t len;
	size_t prefixlen;
	const uint8_t prefix[32];
};

static struct hash_algos hashes[] = {
	{
		NULL, 0, 0, {}
	},
	{
		"MD5", 16, 18, {
			0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
			0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
			0x04, 0x10
		}
	},
	{
		"SHA-1", 20, 15, {
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
			0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
		}
	},
	{
		"RIPEMD-160", 20, 15, {
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24,
			0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14
		}
	},
	{
		NULL, 0, 0, {}
	},
	{
		"MD2", 16, 18, {
			0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
			0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00,
			0x04, 0x10
		}
	},
	{
		"Tiger", 24, 0, {}
	},
	{
		NULL, 0, 0, {}
	},
	{
		"SHA-256", 32, 19, {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
			0x00, 0x04, 0x20
		}
	},
	{
		"SHA-384", 32, 19, {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
			0x00, 0x04, 0x30
		}
	},
	{
		"SHA-512", 64, 19, {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
			0x00, 0x04, 0x40
		}
	},
	{
		"SHA-224", 28, 19, {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
			0x00, 0x04, 0x1c
		}
	}
};

static int make_bignum(const drew_loader_t *ldr, drew_bignum_t *bn)
{
	int id = 0, res = 0;
	const void *tbl = NULL;

	id = drew_loader_lookup_by_name(ldr, "Bignum", 0, -1);
	if (id < 0)
		return id;
	res = drew_loader_get_functbl(ldr, id, &tbl);
	if (res < 0)
		return res;
	bn->functbl = tbl;
	RETFAIL(bn->functbl->init(bn, 0, ldr, NULL));
	return 0;
}

static int make_pksig(const drew_loader_t *ldr, drew_pksig_t *pksig,
		const char *algoname)
{
	int id = 0, res = 0;
	const void *tbl = NULL;
	drew_param_t param;
	drew_bignum_t bn;

	id = drew_loader_lookup_by_name(ldr, algoname, 0, -1);
	if (id == -DREW_ERR_NONEXISTENT)
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	else if (id < 0)
		return id;
	res = drew_loader_get_functbl(ldr, id, &tbl);
	if (res < 0)
		return res;
	pksig->functbl = tbl;
	param.next = 0;
	param.name = "bignum";
	param.param.value = &bn;
	RETFAIL(make_bignum(ldr, &bn));
	RETFAIL(pksig->functbl->init(pksig, 0, ldr, &param));
	return 0;
}

static int verify_rsa(drew_opgp_key_t key, pubkey_t *pub, drew_pksig_t *pksig,
		drew_opgp_hash_t digest, size_t len, int hashalgo,
		const drew_opgp_mpi_t *mpi)
{
	drew_bignum_t bn[2];
	drew_bignum_t *c = bn+0, *m = bn+1;
	size_t nlen, mlen;
	int res = 0;

	if (hashalgo >= DIM(hashes) || !hashes[hashalgo].prefixlen)
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;

	if (!len)
		len = hashes[hashalgo].len;

	if (len != hashes[hashalgo].len)
		return -DREW_OPGP_ERR_BAD_SIGNATURE;

	for (size_t i = 0; i < DIM(bn); i++)
		RETFAIL(make_bignum(key->ldr, bn+i));

	nlen = (pub->mpi[0].len + 7) / 8;
	pksig->functbl->setval(pksig, "n", pub->mpi[0].data, nlen);
	pksig->functbl->setval(pksig, "e", pub->mpi[1].data, (pub->mpi[1].len+7)/8);
	c->functbl->setbytes(c, mpi[0].data, (mpi[0].len + 7)/8);

	pksig->functbl->verify(pksig, m, c);
	mlen = m->functbl->nbytes(m);
	if (mlen != nlen - 1)
		return -DREW_OPGP_ERR_BAD_SIGNATURE;
	uint8_t *buf = malloc(mlen);
	if (!buf)
		return -ENOMEM;
	m->functbl->bytes(m, buf, mlen);
	size_t soh = mlen - len, sop = soh - hashes[hashalgo].prefixlen;
	if (sop-1 - 1 < 8)
		res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	if (buf[0] != 0x01)
		res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	if (memcmp(buf+soh, digest, len))
		res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	if (memcmp(buf+sop, hashes[hashalgo].prefix, hashes[hashalgo].prefixlen))
		res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	if (buf[sop-1] != 0x00)
		res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	for (size_t i = 1; i < sop-1; i++)
		if (buf[i] != 0xff)
			res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	free(buf);
	return res;
}

static int verify_dsa(drew_opgp_key_t key, pubkey_t *pub, drew_pksig_t *pksig,
		drew_opgp_hash_t digest, size_t len, int hashalgo,
		const drew_opgp_mpi_t *mpi)
{
	drew_bignum_t bn[5];
	drew_bignum_t *r = bn+0, *s = bn+1, *h = bn+2, *v = bn+3, *z = bn+4;
	size_t qlen;
	int res = 0;

	if (hashalgo >= DIM(hashes) || !hashes[hashalgo].prefixlen)
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;

	if (!len)
		len = hashes[hashalgo].len;

	if (len != hashes[hashalgo].len)
		return -DREW_OPGP_ERR_BAD_SIGNATURE;

	// The hash must be at least as large as q.
	qlen = (pub->mpi[1].len + 7) / 8;
	if (len < qlen)
		return -DREW_OPGP_ERR_BAD_SIGNATURE;

	for (size_t i = 0; i < DIM(bn); i++)
		RETFAIL(make_bignum(key->ldr, bn+i));

	const char *names[] = {"p", "q", "g", "y"};
	for (size_t i = 0; i < 4; i++)
		pksig->functbl->setval(pksig, names[i], pub->mpi[i].data,
				(pub->mpi[i].len+7)/8);

	z->functbl->setzero(z);
	r->functbl->setbytes(r, mpi[0].data, (mpi[0].len + 7)/8);
	s->functbl->setbytes(s, mpi[1].data, (mpi[1].len + 7)/8);
	if (!r->functbl->compare(r, z, 0) || !s->functbl->compare(s, z, 0))
		return -DREW_OPGP_ERR_BAD_SIGNATURE;
	h->functbl->setbytes(s, digest, qlen);
	pksig->functbl->verify(pksig, v, bn);
	res = r->functbl->compare(r, v, 0) ? 0 : -DREW_OPGP_ERR_BAD_SIGNATURE;

	for (size_t i = 0; i < DIM(bn); i++)
		bn[i].functbl->fini(bn+i, 0);

	return res;
}

static int verify_sig(drew_opgp_key_t key, pubkey_t *pub,
		drew_opgp_hash_t digest, size_t len, int pkalgo, int hashalgo,
		const drew_opgp_mpi_t *mpi)
{
	drew_pksig_t xsa;
	const char *algoname = NULL;
	int (*verify)(drew_opgp_key_t, pubkey_t *, drew_pksig_t *, drew_opgp_hash_t,
			size_t, int, const drew_opgp_mpi_t *);

	if (pkalgo >= 1 && pkalgo <= 3) {
		algoname = "RSASignature";
		verify = verify_rsa;
	}
	else if (pkalgo == 17) {
		algoname = "DSA";
		verify = verify_dsa;
	}
	else if (pkalgo == 16 || pkalgo == 20)
		return -DREW_ERR_NOT_IMPL;
	else
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	RETFAIL(make_pksig(key->ldr, &xsa, algoname));
	return verify(key, pub, &xsa, digest, len, hashalgo, mpi);
}

static int make_hash(const drew_loader_t *ldr, drew_hash_t *hash, int algoid)
{
	int id = 0, res = 0;
	const void *tbl = NULL;

	if (algoid >= DIM(hashes))
		return -DREW_ERR_INVALID;
	if (!hashes[algoid].algoname)
		return -DREW_ERR_INVALID;

	id = drew_loader_lookup_by_name(ldr, hashes[algoid].algoname, 0, -1);
	if (id == -DREW_ERR_NONEXISTENT) {
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	}
	else if (id < 0)
		return id;	
	res = drew_loader_get_functbl(ldr, id, &tbl);
	if (res < 0)
		return res;
	hash->functbl = tbl;
	RETFAIL(hash->functbl->init(hash, 0, ldr, NULL));
	return 0;
}

inline static void hash_u8(drew_hash_t *hash, uint8_t x)
{
	hash->functbl->update(hash, &x, 1);
}

inline static void hash_u16(drew_hash_t *hash, uint16_t x)
{
	x = htons(x);
	hash->functbl->update(hash, (const uint8_t *)&x, 2);
}

inline static void hash_u32(drew_hash_t *hash, uint32_t x)
{
	x = htonl(x);
	hash->functbl->update(hash, (const uint8_t *)&x, 4);
}

static int make_sig_id(const drew_loader_t *ldr, csig_t *sig,
		drew_opgp_id_t id)
{
	drew_hash_t hash;
	RETFAIL(make_hash(ldr, &hash, DREW_OPGP_MDALGO_SHA256));
	uint16_t mpilen[DREW_OPGP_MAX_MPIS];
	size_t nmpis = 0;
	uint32_t totallen = 0;

	for (int i = 0; i < DREW_OPGP_MAX_MPIS && sig->mpi[i].data;
			i++, nmpis++)
		totallen += mpilen[i] = (sig->mpi[i].len + 7) / 8;

	/* By analogy with hashing the key, this is a v3 encoding of a signature
	 * packet with four-octet length (it might contain more than a two-octet
	 * length's worth of data).
	 */
	hash_u8(&hash, 0x8a);
	totallen += 1 + 1 + 1 + 1 + 4 + 2 + sig->hashedlen + 2 + sig->unhashedlen +
		(2 * nmpis);
	hash_u32(&hash, totallen);
	hash_u8(&hash, sig->ver);
	hash_u8(&hash, sig->type);
	hash_u8(&hash, sig->pkalgo);
	hash_u8(&hash, sig->mdalgo);
	hash_u32(&hash, sig->ctime);
	hash_u16(&hash, sig->hashedlen);
	hash.functbl->update(&hash, sig->hasheddata, sig->hashedlen);
	/* We include the unhashed data here because our interest is providing a
	 * unique ID for this signature and we want to distinguish between
	 * signatures that have different unhashed data (where the issuer key ID is
	 * usually placed.
	 */
	hash_u16(&hash, sig->unhashedlen);
	hash.functbl->update(&hash, sig->unhasheddata, sig->unhashedlen);
	for (size_t i = 0; i < nmpis; i++) {
		hash_u16(&hash, sig->mpi[i].len);
		hash.functbl->update(&hash, sig->mpi[i].data, mpilen[i]);
	}
	hash.functbl->final(&hash, id, 0);
	hash.functbl->fini(&hash, 0);
	return 0;
}

static int hash_key_data(pubkey_t *pub, drew_hash_t *hash)
{
	uint8_t buf[16];
	uint16_t mpilen[DREW_OPGP_MAX_MPIS];
	int nmpis = 0;
	uint16_t totallen = 0;

	buf[0] = 0x99;
	hash->functbl->update(hash, buf, 1);
	for (int i = 0; i < DREW_OPGP_MAX_MPIS && pub->mpi[i].data;
			i++, nmpis++)
		totallen += mpilen[i] = (pub->mpi[i].len + 7) / 8;

	uint16_t len = 1 + 4 + 1 + (2 * nmpis) + totallen;
	if (pub->ver < 4)
		len += 2;
	hash_u16(hash, len);
	hash_u8(hash, pub->ver);
	hash_u32(hash, pub->ctime);
	if (pub->ver < 4)
		hash_u16(hash, (pub->etime - pub->ctime) / 86400);
	hash_u8(hash, pub->algo);
	for (int i = 0; i < nmpis; i++) {
		hash_u16(hash, pub->mpi[i].len);
		hash->functbl->update(hash, pub->mpi[i].data, mpilen[i]);
	}
	return 0;
}

static int hash_key(const drew_loader_t *ldr, pubkey_t *pub, int algoid,
		drew_opgp_hash_t digest)
{
	drew_hash_t hash;
	RETFAIL(make_hash(ldr, &hash, algoid));

	hash_key_data(pub, &hash);
	return hash.functbl->final(&hash, digest, 0);
}

static int make_v3_fingerprint(const drew_loader_t *ldr, pubkey_t *pub,
		drew_opgp_hash_t digest)
{
	drew_hash_t hash;
	RETFAIL(make_hash(ldr, &hash, DREW_OPGP_MDALGO_MD5));

	// This is probably a v3 ElGamal key. Not implemented yet.
	if (pub->algo > 4)
		return -DREW_ERR_NOT_IMPL;

	for (size_t i = 0; i < DREW_OPGP_MAX_MPIS && pub->mpi[i].data; i++)
		hash.functbl->update(&hash, pub->mpi[i].data,
				(pub->mpi[i].len + 7) / 8);
	return hash.functbl->final(&hash, digest, 0);
}

int drew_opgp_key_get_fingerprint(drew_opgp_key_t key, drew_opgp_fp_t fp)
{
	size_t len = (key->pub.ver < 4) ? 16 : 20;
	memcpy(fp, key->pub.fp, len);
	return 0;
}

int drew_opgp_key_get_id(drew_opgp_key_t key, drew_opgp_id_t id)
{
	memcpy(id, key->pub.id, sizeof(drew_opgp_id_t));
	return 0;
}

int drew_opgp_key_get_keyid(drew_opgp_key_t key, drew_opgp_keyid_t keyid)
{
	memcpy(keyid, key->pub.keyid, sizeof(drew_opgp_keyid_t));
	return 0;
}

static int hash_sig(drew_hash_t *hash, csig_t *sig)
{
	if (sig->ver < 4) {
		hash_u8(hash, sig->type);
		hash_u32(hash, sig->ctime);
		return 0;
	}
	else {
		uint32_t len = 1 + 1 + 1 + 1 + 2 + sig->hashedlen;
		hash_u8(hash, sig->ver);
		hash_u8(hash, sig->type);
		hash_u8(hash, sig->pkalgo);
		hash_u8(hash, sig->mdalgo);
		hash_u16(hash, sig->hashedlen);
		hash->functbl->update(hash, sig->hasheddata, sig->hashedlen);
		// Trailer.
		hash_u16(hash, 0x04ff);
		hash_u32(hash, len);
	}
	return 0;
}

static int hash_uid_sig(drew_opgp_key_t key, cuid_t *uid, csig_t *sig,
		drew_opgp_hash_t digest)
{
	drew_hash_t hash;
	RETFAIL(make_hash(key->ldr, &hash, sig->mdalgo));
	hash_key_data(&key->pub, &hash);
	if (sig->ver == 4) {
		hash_u8(&hash, 0xb4);
		hash_u32(&hash, uid->len);
	}
	hash.functbl->update(&hash, (const uint8_t *)uid->s, uid->len);
	hash_sig(&hash, sig);
	return hash.functbl->final(&hash, digest, 0);
}

static int synchronize_pubkey(const drew_loader_t *ldr, pubkey_t *pub,
		pubkey_t *main, int flags)
{
	RETFAIL(hash_key(ldr, pub, DREW_OPGP_MDALGO_SHA256, pub->id));

	if (pub->ver < 2 || pub->ver > 4)
		return -DREW_OPGP_ERR_BAD_KEY_FORMAT;

	if (pub->ver < 4) {
		// v3 subkeys are not allowed.
		if (main)
			return -DREW_OPGP_ERR_BAD_KEY_FORMAT;
		size_t mpilen = (pub->mpi[0].len + 7) / 8;
		memcpy(pub->keyid, pub->mpi[0].data+mpilen-8, 8);
		/* The key ID is the bottom 64 bits of the modulus, which is a multiple
		 * of two odd primes.  Since the product of two odd numbers is odd,
		 * check to see that the key ID has the bottom bit set.
		 */
		if (!(pub->keyid[7] & 1))
			return -DREW_OPGP_ERR_CORRUPT_KEYID;
		RETFAIL(make_v3_fingerprint(ldr, pub, pub->fp));
	}
	else {
		RETFAIL(hash_key(ldr, pub, DREW_OPGP_MDALGO_SHA1, pub->fp));
		memcpy(pub->keyid, pub->fp+20-8, 8);
	}
	pub->parent = main;
	if (main) {
		if (pub->nuids)
			return -DREW_OPGP_ERR_BAD_KEY_FORMAT;
	}
	return 0;
}

static int synchronize_uid(drew_opgp_key_t key, cuid_t *uid, int flags)
{
	pubkey_t *pub = &key->pub;
	time_t latest = 0;
	size_t ssidx = 0;

	uid->nselfsigs = 0;
	free(uid->selfsigs);
	uid->theselfsig = NULL;

	for (size_t i = 0; i < uid->nsigs; i++)
		if (uid->sigs[i].flags & DREW_OPGP_SIGNATURE_SELF_SIG)
			uid->nselfsigs++;
	if (!(uid->selfsigs = malloc(uid->nselfsigs * sizeof(*uid->selfsigs))))
		return -ENOMEM;
	
	for (size_t i = 0; i < uid->nsigs; i++)
		if (uid->sigs[i].flags & DREW_OPGP_SIGNATURE_SELF_SIG) {
			uid->selfsigs[ssidx++] = uid->sigs+i;
			if (uid->sigs[i].ctime > latest) {
				latest = uid->sigs[i].ctime;
				uid->theselfsig = uid->sigs+i;
			}
		}
	return 0;
}

/* TODO: don't rehash the key and uid each time; use one context for each hash
 * algorithm and clone it.
 */
static int synchronize_uid_sig(drew_opgp_key_t key, cuid_t *uid, csig_t *sig,
		int flags)
{
	int res = 0;
	pubkey_t *pub = &key->pub;
	if (sig->ver < 2 || sig->ver > 4)
		sig->flags |= DREW_OPGP_SIGNATURE_IGNORED;
	if (sig->type == 0x30) {
		// FIXME: implement.
		sig->flags |= DREW_OPGP_SIGNATURE_IGNORED;
	}
	else if ((sig->type & ~3) != 0x10) {
		// Wherever this signature belongs, it's not here.
		sig->flags |= DREW_OPGP_SIGNATURE_IGNORED;
	}
	if (flags & (DREW_OPGP_SYNCHRONIZE_HASH_SIGS |
				DREW_OPGP_SYNCHRONIZE_VALIDATE_SELF_SIGNATURES)) {
		memset(sig->hash, 0, sizeof(sig->hash));
		RETFAIL(hash_uid_sig(key, uid, sig, sig->hash));
		if (!memcmp(sig->left, sig->hash, 2))
			sig->flags |= DREW_OPGP_SIGNATURE_HASH_CHECK;
		if (!memcmp(sig->keyid, pub->keyid, sizeof(sig->keyid))) {
			/* TODO: verify signature if that feature is enabled.  If we do, and
			 * the signature is good, this is a self-signature; add it to the
			 * list.  If we don't, then mark this as a self-signature, but don't
			 * mark it as validated.  Regardless, extract the preferences
			 * packet.
			 */
			const int checked_sig = DREW_OPGP_SIGNATURE_CHECKED;
			const int good_sig = checked_sig | DREW_OPGP_SIGNATURE_VALIDATED;
			if (flags & DREW_OPGP_SYNCHRONIZE_VALIDATE_SELF_SIGNATURES) {
				res = verify_sig(key, &key->pub, sig->hash, 0, sig->pkalgo,
							sig->mdalgo, sig->mpi);
				sig->flags &= ~good_sig;
				sig->flags |= (!res) ? good_sig :
					((res == -DREW_OPGP_ERR_BAD_SIGNATURE) ?  checked_sig : 0);
			}
			if (!(sig->flags & checked_sig) ||
					(sig->flags & good_sig) == good_sig)
				sig->flags |= DREW_OPGP_SIGNATURE_SELF_SIG;
			else
				sig->flags &= ~DREW_OPGP_SIGNATURE_SELF_SIG;
		}
		if (!(sig->flags & DREW_OPGP_SIGNATURE_SELF_SIG))
			memset(&sig->selfsig, 0, sizeof(sig->selfsig));
	}
	return 0;
}

/* Check whether all fields are self-consistent. If they are not, make them so.
 * If they cannot be made so, return an error.
 */
int drew_opgp_key_synchronize(drew_opgp_key_t key, int flags)
{
	pubkey_t *pub = &key->pub;
	RETFAIL(synchronize_pubkey(key->ldr, &key->pub, NULL, flags));
	if (key->pub.ver < 4 && (key->npubsubs || key->nprivsubs))
		return -DREW_OPGP_ERR_BAD_KEY_FORMAT;
	for (size_t i = 0; i < pub->nuids; i++) {
		cuid_t *uid = &pub->uids[i];
		for (size_t j = 0; j < uid->nsigs; j++)
			RETFAIL(synchronize_uid_sig(key, uid, &uid->sigs[j], flags));
		RETFAIL(synchronize_uid(key, uid, flags));
	}
	for (size_t i = 0; i < key->npubsubs; i++) {
		RETFAIL(synchronize_pubkey(key->ldr, &key->pubsubs[i], &key->pub,
					flags));
	}
	return 0;
	/* TODO:
	 * determine which signatures are self-signatures.
	 * determine *the* self-signature.
	 * ensure the main and subkeys are properly connected.
	 * validate the signatures to ensure ctime and issuer are set.
	 * hash the signatures if flags & 1
	 * validate the self-signatures if flags & 2
	 */
	return -DREW_ERR_NOT_IMPL;
}

static int dup_mpi(drew_opgp_mpi_t *dest, size_t ndest,
		const drew_opgp_mpi_t *src, size_t nsrc)
{
	memset(dest, 0, sizeof(*dest) * ndest);
	for (size_t i = 0; i < ndest && i < nsrc; i++) {
		if (!src[i].data)
			return 0;
		size_t bytelen = (src[i].len + 7) / 8;
		dest[i].len = src[i].len;
		dest[i].data = malloc(bytelen);
		if (!dest[i].data)
			return -ENOMEM;
		memcpy(dest[i].data, src[i].data, bytelen);
	}
	return 0;
}

static int public_load_public(pubkey_t *pub, const drew_opgp_packet_t *pkt)
{
	int res = 0;
	pub->ver = pkt->data.pubkey.ver;
	if (pub->ver < 4) {
		const drew_opgp_packet_pubkeyv3_t *pk = &pkt->data.pubkey.data.pubkeyv3;
		pub->ctime = pk->ctime;
		pub->algo = pk->pkalgo;
		pub->etime = pk->valid_days * 86400 + pub->ctime;
		res = dup_mpi(pub->mpi, DIM(pub->mpi), pk->mpi, DIM(pk->mpi));
		if (res < 0)
			return res;
	}
	else {
		const drew_opgp_packet_pubkeyv4_t *pk = &pkt->data.pubkey.data.pubkeyv4;
		pub->ctime = pk->ctime;
		pub->algo = pk->pkalgo;
		pub->etime = -1;
		res = dup_mpi(pub->mpi, DIM(pub->mpi), pk->mpi, DIM(pk->mpi));
		if (res < 0)
			return res;
	}
	return 0;
}

static int public_load_uid(pubkey_t *pub, const drew_opgp_packet_t *pkt)
{
	cuid_t *p, *uid;
	const drew_opgp_packet_data_t *d = &pkt->data.data;
	p = realloc(pub->uids, sizeof(*p) * (pub->nuids + 1));
	if (!p)
		return -ENOMEM;
	pub->uids = p;
	uid = &pub->uids[pub->nuids];
	memset(uid, 0, sizeof(*uid));
	uid->len = d->len;
	if (!(uid->s = malloc(d->len + 1)))
		return -ENOMEM;
	memcpy(uid->s, d->data, d->len);
	uid->s[d->len] = 0;
	pub->nuids++;
	return 0;
}

static int public_load_sig(csig_t *sig, const drew_opgp_packet_sig_t *s)
{
	memset(sig, 0, sizeof(*sig));
	sig->ver = s->ver;
	if (s->ver < 4) {
		const drew_opgp_packet_sigv3_t *s3 = &s->data.sigv3;
		sig->type = s3->type;
		sig->pkalgo = s3->pkalgo;
		sig->mdalgo = s3->mdalgo;
		sig->ctime = s3->ctime;
		memcpy(sig->keyid, s3->keyid, 8);
		memcpy(sig->left, s3->left, 2);
		RETFAIL(dup_mpi(sig->mpi, DIM(sig->mpi), s3->mpi, DIM(s3->mpi)));
	}
	else {
		const drew_opgp_packet_sigv4_t *s4 = &s->data.sigv4;
		sig->type = s4->type;
		sig->pkalgo = s4->pkalgo;
		sig->mdalgo = s4->mdalgo;
		sig->hashedlen = s4->hashedlen;
		sig->nhashed = s4->nhashed;
		sig->unhashedlen = s4->unhashedlen;
		sig->nunhashed = s4->nunhashed;
		RETFAIL(dup_mpi(sig->mpi, DIM(sig->mpi), s4->mpi, DIM(s4->mpi)));
		if (!(sig->hashed = malloc(sizeof(*sig->hashed) * sig->nhashed)))
			return -ENOMEM;
		memcpy(sig->hashed, s4->hashed, sizeof(*sig->hashed) * sig->nhashed);
		if (!(sig->hasheddata = malloc(sig->hashedlen)))
			return -ENOMEM;
		memcpy(sig->hasheddata, s4->hasheddata, sig->hashedlen);
		if (!(sig->unhashed = malloc(sizeof(*sig->unhashed) * sig->nunhashed)))
			return -ENOMEM;
		memcpy(sig->unhashed, s4->unhashed, sizeof(*sig->unhashed) *
				sig->nunhashed);
		if (!(sig->unhasheddata = malloc(sig->unhashedlen)))
			return -ENOMEM;
		memcpy(sig->unhasheddata, s4->unhasheddata, sig->unhashedlen);
		memcpy(sig->left, s4->left, 2);
		// We need to find the ctime.
		sig->ctime = -1;
		int nctimes = 0, nissuers = 0;
		for (size_t i = 0; i < sig->nhashed; i++) {
			drew_opgp_subpacket_t *sp = &sig->hashed[i];
			if (sp->type == 2) {
				sig->ctime = 0;
				if (sp->len != 4)
					continue;
				for (int j = 0; j < 4; j++) {
					sig->ctime <<= 8;
					sig->ctime |= sp->data[j];
				}
				nctimes++;
			}
			else if (sp->type == 16) {
				if (sp->len != 8)
					continue;
				memcpy(sig->keyid, sp->data, 8);
				nissuers++;
			}
		}
		if (!nissuers) {
			for (size_t i = 0; i < sig->nunhashed; i++) {
				drew_opgp_subpacket_t *sp = &sig->unhashed[i];
				if (sp->type == 16) {
					if (sp->len != 8)
						continue;
					memcpy(sig->keyid, sp->data, 8);
					nissuers++;
				}
			}
		}
		// We should have exactly one ctime and exactly one issuer.
		if (nctimes != 1 || nissuers != 1)
			sig->flags |= DREW_OPGP_SIGNATURE_INCOMPLETE;
	}
	return 0;
}

static int public_load_direct_sig(pubkey_t *pub, const drew_opgp_packet_t *pkt)
{
	csig_t *sig, *p;
	const drew_opgp_packet_sig_t *s = &pkt->data.sig;

	p = realloc(pub->sigs, sizeof(*p) * (pub->nsigs + 1));
	if (!p)
		return -ENOMEM;
	pub->sigs = p;
	sig = &pub->sigs[pub->nsigs];
	RETFAIL(public_load_sig(sig, s));
	pub->nsigs++;
	return 0;
}

static int public_load_uid_sig(pubkey_t *pub, const drew_opgp_packet_t *pkt)
{
	cuid_t *uid = &pub->uids[pub->nuids - 1];
	csig_t *sig, *p;
	const drew_opgp_packet_sig_t *s = &pkt->data.sig;

	p = realloc(uid->sigs, sizeof(*p) * (uid->nsigs + 1));
	if (!p)
		return -ENOMEM;
	uid->sigs = p;
	sig = &uid->sigs[uid->nsigs];
	RETFAIL(public_load_sig(sig, s));
	uid->nsigs++;
	return 0;
}

static int public_load_subkey_sig(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkt)
{
	pubkey_t *pub = &key->pubsubs[key->npubsubs-1];

	return public_load_direct_sig(pub, pkt);
}

static int public_load_subkey(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkt)
{
	pubkey_t *pub, *p;

	p = realloc(key->pubsubs, sizeof(*p) * (key->npubsubs + 1));
	if (!p)
		return -ENOMEM;
	memset(p+key->npubsubs, 0, sizeof(*p));
	key->pubsubs = p;
	pub = &key->pubsubs[key->npubsubs];
	RETFAIL(public_load_public(pub, pkt));
	key->npubsubs++;
	return 0;
}

/* Load a key from a series of packets.  Returns the number of packets
 * processed.
 */
int drew_opgp_key_load_public(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts)
{
	ssize_t i = 0;
	int state = 0, res = 0;
	pubkey_t *pub = &key->pub;
	pub->state &= ~DREW_OPGP_KEY_STATE_SYNCHRONIZED;
	for (i = 0; i < npkts; i++) {
		if (!state && pkts[i].type == 6) {
			res = public_load_public(pub, pkts+i);
			state = 1;
		}
		else if (state > 0 && state < 4 && pkts[i].type == 13) {
			res = public_load_uid(pub, pkts+i);
			state = 2;
		}
		else if (state > 0 && state < 4 && pkts[i].type == 17) {
			res = 0;
			state = 3;
		}
		else if (state == 1 && pkts[i].type == 2) {
			res = public_load_direct_sig(pub, pkts+i);
		}
		else if (state == 2 && pkts[i].type == 2) {
			res = public_load_uid_sig(pub, pkts+i);
		}
		else if (state == 3 && pkts[i].type == 2) {
			res = 0;
		}
		else if (state > 0 && pkts[i].type == 14) {
			res = public_load_subkey(key, pkts+i);
			state = 4;
		}
		else if (state == 4 && pkts[i].type == 2) {
			res = public_load_subkey_sig(key, pkts+i);
		}
		else
			break;	// Done with this key.
		if (res < 0)
			return res;
	}
	return i;
}

/* Load a key from a series of packets.  Returns the number of packets
 * processed.
 */
int drew_opgp_key_load_private(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Store a key into a series of packets.  Returns the number of packets created.
 */
int drew_opgp_key_store_public(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_key_store_private(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_key_get_preferences(drew_opgp_key_t key, int type,
		drew_opgp_prefs_t *prefs)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_key_get_user_ids(drew_opgp_key_t key, drew_opgp_uid_t **uids)
{
	if (!uids)
		return key->pub.nuids;

	drew_opgp_uid_t *p = malloc(sizeof(*p) * key->pub.nuids);
	if (!p)
		return -ENOMEM;

	for (size_t i = 0; i < key->pub.nuids; i++)
		p[i] = key->pub.uids+i;
	*uids = p;
	return key->pub.nuids;
}

int drew_opgp_uid_get_text(drew_opgp_uid_t uid, const char **p)
{
	*p = uid->s;
	return 0;
}

int drew_opgp_uid_get_signatures(drew_opgp_uid_t uid, drew_opgp_sig_t **sigs)
{
	if (!sigs)
		return uid->nsigs;

	drew_opgp_sig_t *p = malloc(sizeof(*p) * uid->nsigs);
	if (!p)
		return -ENOMEM;

	for (size_t i = 0; i < uid->nsigs; i++)
		p[i] = uid->sigs+i;
	*sigs = p;
	return uid->nsigs;
}
