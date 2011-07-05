#ifndef DREW_OPGP_KEY_H
#define DREW_OPGP_KEY_H

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

#define DREW_OPGP_KEY_STATE_SYNCHRONIZED	(1 << 0)

// The SHA-256 hash, used as an internal identifier.
typedef uint8_t drew_opgp_id_t[32];
// A fingerprint, MD5 or SHA-1.
typedef uint8_t drew_opgp_fp_t[20];
// A hash value (could be as large as SHA-512).
typedef uint8_t drew_opgp_hash_t[64];
// A key ID.
typedef uint8_t drew_opgp_keyid_t[8];

int drew_opgp_key_new(drew_opgp_key_t *key, const drew_loader_t *ldr);
int drew_opgp_key_free(drew_opgp_key_t *key);
int drew_opgp_key_has_secret(drew_opgp_key_t key);
int drew_opgp_key_has_usable_secret(drew_opgp_key_t key);
int drew_opgp_key_can_sign(drew_opgp_key_t key);
int drew_opgp_key_can_encrypt(drew_opgp_key_t key);
int drew_opgp_key_is_revoked(drew_opgp_key_t key, int flags);
int drew_opgp_key_is_expired(drew_opgp_key_t key, int flags);
int drew_opgp_key_can_do(drew_opgp_key_t key, int flags);
int drew_opgp_key_get_version(drew_opgp_key_t key);
int drew_opgp_key_get_type(drew_opgp_key_t key);
int drew_opgp_key_get_subkeys(drew_opgp_key_t key, drew_opgp_key_t *subkeys);
int drew_opgp_key_generate(drew_opgp_key_t key, uint8_t algo, size_t nbits,
		size_t order, time_t expires);
int drew_opgp_key_get_fingerprint(drew_opgp_key_t key, drew_opgp_fp_t fp);
int drew_opgp_key_get_id(drew_opgp_key_t key, drew_opgp_id_t id);
int drew_opgp_key_get_keyid(drew_opgp_key_t key, drew_opgp_keyid_t keyid);
int drew_opgp_key_synchronize(drew_opgp_key_t key, int flags);
int drew_opgp_key_load_public(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts);
int drew_opgp_key_load_private(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts);
int drew_opgp_key_store_public(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts);
int drew_opgp_key_store_private(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts);
int drew_opgp_key_get_preferences(drew_opgp_key_t key, int type,
		drew_opgp_prefs_t *prefs);

#endif
