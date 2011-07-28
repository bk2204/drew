#ifndef SIG_H
#define SIG_H

#include "internal.h"

#include <drew/drew.h>
#include <drew/plugin.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/key.h>
#include <drew-opgp/parser.h>

#define PREFS_CIPHER	0
#define PREFS_HASH		1
#define PREFS_COMPRESS	2

struct drew_opgp_prefs_s {
	uint8_t type;
	size_t len;
	uint8_t vals[16];
};

struct drew_opgp_self_sig_s {
	int keyflags;
	bool primary;
	time_t keyexp;
	drew_opgp_prefs_t prefs[3];
};

typedef struct drew_opgp_self_sig_s selfsig_t;

struct drew_opgp_signature_s {
	int flags;
	uint8_t ver;
	uint8_t type;
	uint8_t pkalgo;
	uint8_t mdalgo;
	time_t ctime;
	time_t etime;
	drew_opgp_keyid_t keyid;
	drew_opgp_subpacket_group_t hashed;
	drew_opgp_subpacket_group_t unhashed;
	uint8_t left[2];
	selfsig_t selfsig;
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS];
	drew_opgp_hash_t hash;
	drew_opgp_id_t id;
};

typedef struct drew_opgp_signature_s csig_t;
typedef struct drew_opgp_key_s ckey_t;
typedef struct drew_opgp_uid_s cuid_t;

struct drew_opgp_uid_s {
	char *s;
	size_t len;
	csig_t *theselfsig;
	csig_t **selfsigs;
	size_t nselfsigs;
	csig_t *sigs;
	size_t nsigs;
	drew_opgp_id_t id;
};

typedef struct drew_opgp_pubkey_s {
	int state;
	uint8_t ver;
	uint8_t algo;
	time_t ctime;
	time_t etime;
	struct drew_opgp_pubkey_s *parent;
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS];
	cuid_t *theuid;
	cuid_t *uids;
	size_t nuids;
	csig_t *sigs;
	size_t nsigs;
	drew_opgp_keyid_t keyid;
	drew_opgp_id_t id;
	drew_opgp_fp_t fp;
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

#endif
