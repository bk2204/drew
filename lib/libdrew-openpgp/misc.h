#ifndef OPGP_MISC_H
#define OPGP_MISC_H

#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

HIDE()
int clone_mpi(drew_opgp_mpi_t *, drew_opgp_mpi_t *);
int clone_mpis(drew_opgp_mpi_t *, drew_opgp_mpi_t *);
int clone_subpackets(drew_opgp_subpacket_group_t *,
		const drew_opgp_subpacket_group_t *);
int clone_sig(csig_t *, csig_t *);
int clone_uid(cuid_t *, cuid_t *);
int clone_pubkey(pubkey_t *, pubkey_t *, pubkey_t *parent);
void free_mpi(drew_opgp_mpi_t *mpi);
void free_subpacket_group(drew_opgp_subpacket_group_t *spg);
void free_sig(csig_t *sig);
void free_uid(cuid_t *uid);
void free_pubkey(pubkey_t *pub);
UNHIDE()

#ifdef __cplusplus
}
#endif

#endif
