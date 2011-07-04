#include "internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <drew/drew.h>
#include <drew/plugin.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/parser.h>

struct drew_opgp_key_s;
struct drew_opgp_signature_s;
struct drew_opgp_prefs_s;

typedef struct drew_opgp_signature_s *drew_opgp_signature_t;
typedef struct drew_opgp_key_s *drew_opgp_key_t;
typedef struct drew_opgp_prefs_s *drew_opgp_prefs_t;

// Has this signature been checked?
#define DREW_OPGP_SIGNATURE_CHECKED			(1 << 0)
// Has this signature been hashed and checked against the left two?
#define DREW_OPGP_SIGNATURE_HASH_CHECK		(1 << 1)
// Did the signature validate?
#define DREW_OPGP_SIGNATURE_VALIDATED		(1 << 2)
// Has this signature been revoked?
#define DREW_OPGP_SIGNATURE_REVOKED			(1 << 3)
// Has this signature expired?
#define DREW_OPGP_SIGNATURE_EXPIRED			(1 << 4)
// Is this signature consistent?
#define DREW_OPGP_SIGNATURE_CONSISTENT		(1 << 5)

// The SHA-256 hash, used as an internal identifier.
typedef uint8_t drew_opgp_id_t[32];
// A fingerprint, MD5 or SHA-1.
typedef uint8_t drew_opgp_fp_t[20];
// A hash value (could be as large as SHA-512).
typedef uint8_t drew_opgp_hash_t[64];
// A key ID.
typedef uint8_t drew_opgp_keyid_t[8];

struct drew_opgp_signature_s {
	int flags;
	uint8_t ver;
	uint8_t type;
	uint8_t pkalgo;
	uint8_t mdalgo;
	time_t ctime;
	drew_opgp_keyid_t keyid;
	size_t hashedlen;	
	size_t nhashed;
	uint8_t *hasheddata;
	drew_opgp_subpacket_t *hashed;
	size_t unhashedlen;	
	size_t nunhashed;
	uint8_t *unhasheddata;
	drew_opgp_subpacket_t *unhashed;
	uint8_t left[2];
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS];
	drew_opgp_hash_t hash;
	drew_opgp_id_t id;
};

typedef struct drew_opgp_signature_s csig_t;
typedef struct drew_opgp_key_s ckey_t;

typedef struct {
	char *s;
	csig_t *theselfsig;
	csig_t *selfsigs;
	size_t nselfsigs;
	csig_t *sigs;
	size_t nsigs;
	drew_opgp_id_t id;
} cuid_t;

typedef struct drew_opgp_pubkey_s {
	int state;
	uint8_t ver;
	uint8_t algo;
	time_t ctime;
	time_t etime;
	struct drew_opgp_pubkey_s *parent;
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS];
	cuid_t *uids;
	size_t nuids;
	csig_t *sigs;
	size_t nsigs;
	drew_opgp_id_t id;
} pubkey_t;

typedef struct drew_opgp_privkey_s {
	int state;
	struct drew_opgp_privkey_s *parent;
	pubkey_t *pub;
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS];
	drew_opgp_id_t id;
} privkey_t;

struct drew_opgp_key_s {
	pubkey_t pub;
	pubkey_t *pubsubs;
	size_t npubsubs;
	privkey_t priv;
	privkey_t *privsubs;
	size_t nprivsubs;
	drew_opgp_id_t id;
	const drew_loader_t *ldr;
};

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

/* Check whether all fields are self-consistent. If they are not, make them so.
 * If they cannot be made so, return an error.
 */
int drew_opgp_key_synchronize(drew_opgp_key_t key, int flags)
{
	/* TODO:
	 * generate the internal ID (SHA-256).
	 * generate the fingerprint (SHA-1 or MD5, as appropriate).
	 * determine which signatures are self-signatures.
	 * determine *the* self-signature.
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
		for (size_t i = 0; nissuers && i < sig->nunhashed; i++) {
			drew_opgp_subpacket_t *sp = &sig->unhashed[i];
			if (sp->type == 16) {
				if (sp->len != 8)
					continue;
				memcpy(sig->keyid, sp->data, 8);
				nissuers++;
			}
		}
		// We should have exactly one ctime and at most one issuer.
		if (nctimes != 1)
			sig->ctime = -1;
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
	for (i = 0; i < npkts; i++) {
		if (!state && pkts[i].type == 6) {
			res = public_load_public(pub, pkts+i);
			state = 1;
		}
		else if (state > 0 && state < 3 && pkts[i].type == 13) {
			res = public_load_uid(pub, pkts+i);
			state = 2;
		}
		else if (state == 1 && pkts[i].type == 2) {
			res = public_load_direct_sig(pub, pkts+i);
		}
		else if (state == 2 && pkts[i].type == 2) {
			res = public_load_uid_sig(pub, pkts+i);
		}
		else if (state > 0 && pkts[i].type == 14) {
			res = public_load_subkey(key, pkts+i);
			state = 3;
		}
		else if (state == 3 && pkts[i].type == 2) {
			res = public_load_subkey_sig(key, pkts+i);
		}
		else
			break;	// Done with this key.
		if (res < 0)
			return res;
	}
	drew_opgp_key_synchronize(key, 0);
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
