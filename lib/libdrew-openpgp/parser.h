#ifndef DREW_OPGP_PARSER_H
#define DREW_OPGP_PARSER_H

#define DREW_OPGP_MAX_MPIS_ENCRYPT 2
#define DREW_OPGP_MAX_MPIS_SIGN 2

#define DREW_OPGP_MAX_SK_BLOCK_SIZE 16
#define DREW_OPGP_MAX_SK_KEY_SIZE 32

// This is because 32-bit systems might legitimately want to process files
// larger than 2**32.  It is only used for actual data or in places where
// containing lots of data 
typedef off_t drew_opgp_len_t;

typedef struct {
	int flags;
} drew_opgp_parser_t;

typedef struct {
	uint16_t len;
	uint8_t *data;
} drew_opgp_mpi_t;

typedef struct {
	uint8_t ver;
	uint8_t keyid[8];
	uint8_t pkalgo;
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS_ENCRYPT];
} drew_opgp_packet_pkesk_t;

typedef struct {
	uint8_t len;
	uint8_t type;
	uint32_t ctime;
	uint8_t keyid[8];
	uint8_t pkalgo;
	uint8_t mdalgo;
	uint8_t left[2]; // This is the left 16 bits of the hash value.
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS_SIGN];
} drew_opgp_packet_sigv3_t;

typedef struct {
	uint8_t type;
	bool critical;
	int lenoflen;
	size_t len;
	uint8_t *data;
} drew_opgp_subpacket_t;

typedef struct {
	uint8_t len;
	uint8_t type;
	uint8_t pkalgo;
	uint8_t mdalgo;
	uint16_t hashedlen;
	size_t nhashed;
	drew_opgp_subpacket_t *hashed;
	uint16_t unhashedlen;
	size_t nunhashed;
	drew_opgp_subpacket_t *unhashed;
	uint8_t left[2]; // This is the left 16 bits of the hash value.
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS_SIGN];
} drew_opgp_packet_sigv4_t;

typedef struct {
	uint8_t ver;
	union {
		drew_opgp_packet_sigv3_t sigv3;
		drew_opgp_packet_sigv4_t sigv4;
	} data;
} drew_opgp_packet_sig_t;

typedef struct {
	uint8_t ver;
	uint8_t skalgo;
	drew_opgp_s2k_t s2k;
	bool sk_present;
	uint8_t sk[DREW_OPGP_MAX_SK_KEY_SIZE + DREW_OPGP_MAX_SK_BLOCK_SIZE + 2 + 1];
} drew_opgp_packet_skesk_t;

typedef struct {
	uint8_t ver;
	uint8_t type;
	uint8_t mdalgo;
	uint8_t pkalgo;
	uint8_t keyid[8];
	uint8_t nested;
} drew_opgp_packet_onepass_sig_t;

typedef struct {
	uint8_t tag;
	uint8_t ver;
	uint8_t type;
	int lenoflen;
	drew_opgp_len_t len;
	union {
		drew_opgp_packet_pkesk_t pkesk;
		drew_opgp_packet_skesk_t skesk;
		drew_opgp_packet_onepass_sig_t onepass_sig;
	} data;
} drew_opgp_packet_t;

// The header information is corrupt.
#define DREW_OPGP_ERR_INVALID_HEADER	0x20001
#define DREW_OPGP_ERR_INVALID			0x20001
// More data is needed to continue.
#define DREW_OPGP_ERR_MORE_DATA			0x20002
// That functionality is not implemented.
#define DREW_OPGP_ERR_NOT_IMPL			0x20003

// The data is not in compliance with the versions specified.
#define DREW_OPGP_ERR_WRONG_VERSION		0x20101

#define DREW_OPGP_F0_RFC1991			(1 << 0)
#define DREW_OPGP_F0_RFC2440			(1 << 1)
#define DREW_OPGP_F0_RFC2440_BIS0		(1 << 2)

#endif
