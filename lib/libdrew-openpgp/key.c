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

struct drew_opgp_signature_s {
	int dummy;
};

typedef struct drew_opgp_signature_s csig_t;
typedef struct drew_opgp_key_s ckey_t;

typedef struct {
	const char *t;
	csig_t *selfsigs;
	size_t nselfsigs;
	csig_t *sigs;
	size_t nsigs;
} cuid_t;

typedef struct drew_opgp_pubkey_s {
	int state;
	uint8_t ver;
	uint8_t algo;
	time_t ctime;
	time_t etime;
	struct drew_opgp_pubkey_s *parent;
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS_PUBKEY];
	cuid_t *uids;
	size_t nuids;
} pubkey_t;

typedef struct drew_opgp_privkey_s {
	int state;
	struct drew_opgp_privkey_s *parent;
	pubkey_t *pub;
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS_PRIVKEY];
} privkey_t;

struct drew_opgp_key_s {
	pubkey_t pub;
	pubkey_t *pubsub;
	size_t npubsub;
	privkey_t priv;
	privkey_t *privsub;
	size_t nprivsub;
};

int drew_opgp_key_new(drew_opgp_key_t *key)
{
	drew_opgp_key_t k;
	if (!(k = calloc(sizeof(*k), 1)))
		return -ENOMEM;
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
	return -DREW_ERR_NOT_IMPL;
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
		size_t order, time_t expires, const drew_loader_t *ldr)
{
	return -DREW_ERR_NOT_IMPL;
}

static int dup_mpis(drew_opgp_mpi_t *dest, size_t ndest,
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

/* Load a key from a series of packets.  Returns the number of packets
 * processed.
 */
int drew_opgp_key_load_public(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts)
{
	ssize_t i = 0;
	int state = 0, res = 0;
	for (i = 0; i < npkts; i++) {
		if (!state && pkts[i].type == 6) {
			key->pub.ver = pkts[i].data.pubkey.ver;
			if (key->pub.ver < 4) {
				const drew_opgp_packet_pubkeyv3_t *pk =
					&pkts[i].data.pubkey.data.pubkeyv3;
				key->pub.ctime = pk->ctime;
				key->pub.algo = pk->pkalgo;
				key->pub.etime = pk->valid_days * 86400 + key->pub.ctime;
				res = dup_mpis(key->pub.mpi, DIM(key->pub.mpi), pk->mpi,
						DIM(pk->mpi));
				if (res < 0)
					return res;
			}
			else {
				const drew_opgp_packet_pubkeyv4_t *pk =
					&pkts[i].data.pubkey.data.pubkeyv4;
				key->pub.ctime = pk->ctime;
				key->pub.algo = pk->pkalgo;
				key->pub.etime = -1;
				res = dup_mpis(key->pub.mpi, DIM(key->pub.mpi), pk->mpi,
						DIM(pk->mpi));
				if (res < 0)
					return res;
			}
		}
	}
	return -DREW_ERR_NOT_IMPL;
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
