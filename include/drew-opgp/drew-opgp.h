#ifndef DREW_OPGP_H
#define DREW_OPGP_H

#include <stdint.h>

#include <drew/drew.h>
#include <drew/hash.h>

// The header information is corrupt.
#define DREW_OPGP_ERR_INVALID_HEADER	0x20001
#define DREW_OPGP_ERR_INVALID			0x20001
// More data is needed to continue.
#define DREW_OPGP_ERR_MORE_DATA			0x20002
// That functionality is not implemented.
#define DREW_OPGP_ERR_NOT_IMPL			0x20003
// A given algorithm is needed but has not been loaded.
#define DREW_OPGP_ERR_NO_SUCH_ALGO		0x20004
// A corrupt key ID is present.
#define DREW_OPGP_ERR_CORRUPT_KEYID		0x20005
// The format of this key is not understood.
#define DREW_OPGP_ERR_BAD_KEY_FORMAT	0x20006
// The format of this signature is not understood.
#define DREW_OPGP_ERR_BAD_SIGNATURE_FORMAT	0x20007
// This signature does not verify.
#define DREW_OPGP_ERR_BAD_SIGNATURE		0x20008

// The data is not in compliance with the versions specified.
#define DREW_OPGP_ERR_WRONG_VERSION		0x20101

#define DREW_OPGP_MDALGO_MD5			1
#define DREW_OPGP_MDALGO_SHA1			2
#define DREW_OPGP_MDALGO_RIPEMD160		3
// Algorithm 4 was reserved for double-width SHA, which was never defined.
#define DREW_OPGP_MDALGO_MD2			5
#define DREW_OPGP_MDALGO_TIGER192		6
#define DREW_OPGP_MDALGO_HAVAL5160		7
#define DREW_OPGP_MDALGO_SHA256			8
#define DREW_OPGP_MDALGO_SHA384			9
#define DREW_OPGP_MDALGO_SHA512			10
#define DREW_OPGP_MDALGO_SHA224			11

#define DREW_OPGP_SKALGO_NONE			0
#define DREW_OPGP_SKALGO_IDEA			1
#define DREW_OPGP_SKALGO_3DES			2
#define DREW_OPGP_SKALGO_CAST5			3
#define DREW_OPGP_SKALGO_BLOWFISH		4
#define DREW_OPGP_SKALGO_SAFERSK128		5
// Algorithm 6 was reserved for DES/SK.
#define DREW_OPGP_SKALGO_AES128			7
#define DREW_OPGP_SKALGO_AES192			8
#define DREW_OPGP_SKALGO_AES256			9
#define DREW_OPGP_SKALGO_TWOFISH		10
#define DREW_OPGP_SKALGO_CAMELLIA128	11
#define DREW_OPGP_SKALGO_CAMELLIA192	12
#define DREW_OPGP_SKALGO_CAMELLIA256	13

#ifdef __cplusplus
extern "C" {
#endif

struct drew_opgp_s;
typedef struct drew_opgp_s *drew_opgp_t;

DREW_SYM_PUBLIC
int drew_opgp_algo_hash_lookup(drew_opgp_t ctx, int algo,
		drew_hash_t *hash, const char **name, size_t *len,
		const uint8_t **prefix, size_t *prefixlen);

#ifdef __cplusplus
}
#endif

#endif
