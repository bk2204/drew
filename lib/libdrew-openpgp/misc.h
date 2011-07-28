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
UNHIDE()

#ifdef __cplusplus
}
#endif

#endif
