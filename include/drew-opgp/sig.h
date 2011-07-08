#ifndef DREW_OPGP_SIG_H
#define DREW_OPGP_SIG_H

#include <drew-opgp/key.h>

int drew_opgp_sig_get_flags(drew_opgp_sig_t sig, int *flags, size_t nflags);
int drew_opgp_sig_get_issuer(drew_opgp_sig_t sig, drew_opgp_keyid_t keyid);

#endif
