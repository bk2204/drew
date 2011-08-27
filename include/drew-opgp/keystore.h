#ifndef DREW_OPGP_KEYSTORE_H
#define DREW_OPGP_KEYSTORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include <drew/drew.h>
#include <drew/plugin.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/key.h>

struct drew_opgp_keystore_s;
typedef struct drew_opgp_keystore_s *drew_opgp_keystore_t;

int drew_opgp_keystore_new(drew_opgp_keystore_t *ksp, const drew_loader_t *ldr);
int drew_opgp_keystore_free(drew_opgp_keystore_t *ksp);
int drew_opgp_keystore_set_backend(drew_opgp_keystore_t ks,
		const char *backend);
int drew_opgp_keystore_load(drew_opgp_keystore_t ks, drew_opgp_id_t missingid);
int drew_opgp_keystore_store(drew_opgp_keystore_t ks);
int drew_opgp_keystore_open(drew_opgp_keystore_t ks, const char *filename,
		bool write);
int drew_opgp_keystore_close(drew_opgp_keystore_t ks);
int drew_opgp_keystore_update_sigs(drew_opgp_keystore_t ks,
		drew_opgp_sig_t *sigs, size_t nsigs, int flags);
int drew_opgp_keystore_update_sig(drew_opgp_keystore_t ks, drew_opgp_sig_t sig,
		int flags);
int drew_opgp_keystore_update_user_ids(drew_opgp_keystore_t ks,
		drew_opgp_uid_t *uids, size_t nuids, int flags);
int drew_opgp_keystore_update_user_id(drew_opgp_keystore_t ks,
		drew_opgp_uid_t uid, int flags);
int drew_opgp_keystore_add_keys(drew_opgp_keystore_t ks,
		drew_opgp_key_t *keys, size_t nkeys, int flags);
int drew_opgp_keystore_add_key(drew_opgp_keystore_t ks, drew_opgp_key_t key,
		int flags);
int drew_opgp_keystore_update_keys(drew_opgp_keystore_t ks,
		drew_opgp_key_t *keys, size_t nkeys, int flags);
int drew_opgp_keystore_update_key(drew_opgp_keystore_t ks, drew_opgp_key_t key,
		int flags);
int drew_opgp_keystore_check(drew_opgp_keystore_t ks, int flags);
int drew_opgp_keystore_lookup_by_id(drew_opgp_keystore_t ks,
		drew_opgp_key_t *key, drew_opgp_id_t id);
int drew_opgp_keystore_lookup_by_keyid(drew_opgp_keystore_t ks,
		drew_opgp_key_t *key, size_t nkeys, drew_opgp_keyid_t keyid);
int drew_opgp_keystore_get_keys(drew_opgp_keystore_t ks,
		drew_opgp_key_t *key, size_t nkeys);
int drew_opgp_keystore_flush(drew_opgp_keystore_t ks);

int drew_opgp_key_validate_signatures(drew_opgp_key_t key,
		drew_opgp_keystore_t ks);

#ifdef __cplusplus
}
#endif
#endif
