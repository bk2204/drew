#ifndef DREW_OPGP_PARSER_H
#define DREW_OPGP_PARSER_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define DREW_OPGP_MAX_MPIS 10
#define DREW_OPGP_MAX_MPIS_ENCRYPT DREW_OPGP_MAX_MPIS
#define DREW_OPGP_MAX_MPIS_SIGN DREW_OPGP_MAX_MPIS
#define DREW_OPGP_MAX_MPIS_PUBKEY DREW_OPGP_MAX_MPIS
#define DREW_OPGP_MAX_MPIS_PRIVKEY DREW_OPGP_MAX_MPIS

#define DREW_OPGP_MAX_SK_BLOCK_SIZE 16
#define DREW_OPGP_MAX_SK_KEY_SIZE 32

// This is because 32-bit systems might legitimately want to process files
// larger than 2**32.  It is only used for actual data or in places where
// containing lots of data 
typedef off_t drew_opgp_len_t;

// The SHA-256 hash, used as an internal identifier.
typedef uint8_t drew_opgp_id_t[32];

struct drew_opgp_parser_s {
	int flags;
};

typedef struct drew_opgp_parser_s *drew_opgp_parser_t;

typedef struct {
	uint16_t len;
	uint8_t *data;
	drew_opgp_id_t id;
} drew_opgp_mpi_t;

typedef struct {
	uint8_t type;
	uint8_t mdalgo;
	uint8_t salt[8];
	uint8_t count;
} drew_opgp_s2k_t;

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
	uint8_t *hasheddata;
	drew_opgp_subpacket_t *hashed;
	uint16_t unhashedlen;
	size_t nunhashed;
	uint8_t *unhasheddata;
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
	uint32_t ctime;
	uint16_t valid_days;
	uint8_t pkalgo;
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS_PUBKEY];
} drew_opgp_packet_pubkeyv3_t;

typedef struct {
	uint32_t ctime;
	uint16_t valid_days;
	uint8_t pkalgo;
	drew_opgp_mpi_t mpi[DREW_OPGP_MAX_MPIS_PUBKEY];
} drew_opgp_packet_pubkeyv4_t;

typedef struct {
	uint8_t ver;
	union {
		drew_opgp_packet_pubkeyv3_t pubkeyv3;
		drew_opgp_packet_pubkeyv4_t pubkeyv4;
	} data;
} drew_opgp_packet_pubkey_t;

typedef struct {
	uint8_t ver;
	drew_opgp_packet_pubkey_t pubkey;
	uint8_t s2k_usage;
	uint8_t skalgo;
	drew_opgp_s2k_t s2k;
	uint8_t iv[DREW_OPGP_MAX_SK_BLOCK_SIZE];
	union {
		uint16_t cksum;
		uint8_t sha1sum[20];
	} checksum;
	size_t mpidatalen;
	uint8_t *mpidata;
} drew_opgp_packet_privkey_t;

/* This is used for all types of data *except* literal data packets. */
typedef struct {
	uint8_t type;
	uint8_t algo;
	uint8_t *data;
	size_t len;
} drew_opgp_packet_data_t;

typedef struct {
	uint8_t type;
	char *name;
	uint32_t time;
	uint8_t *data;
	size_t len;
} drew_opgp_packet_literal_data_t;

typedef struct {
	uint8_t tag;
	uint8_t ver;
	uint8_t type;
	int lenoflen;
	drew_opgp_len_t len;
	union {
		drew_opgp_packet_pkesk_t pkesk;
		drew_opgp_packet_sig_t sig;
		drew_opgp_packet_skesk_t skesk;
		drew_opgp_packet_onepass_sig_t onepass_sig;
		drew_opgp_packet_pubkey_t pubkey;
		drew_opgp_packet_privkey_t privkey;
		drew_opgp_packet_data_t data;
		drew_opgp_packet_literal_data_t literal;
	} data;
} drew_opgp_packet_t;


#define DREW_OPGP_F0_RFC1991			(1 << 0)
#define DREW_OPGP_F0_RFC2440			(1 << 1)
#define DREW_OPGP_F0_RFC2440_BIS0		(1 << 2)

int drew_opgp_parser_new(drew_opgp_parser_t *p, int mode, const int *flags);
int drew_opgp_parser_free(drew_opgp_parser_t *p);
int drew_opgp_parser_parse_packets(drew_opgp_parser_t p,
		drew_opgp_packet_t *packets, size_t *npackets, const uint8_t *data,
		size_t datalen, size_t *off);
int drew_opgp_parser_parse_packet(drew_opgp_parser_t parser,
		drew_opgp_packet_t *pkt, const uint8_t *data, size_t datalen);
int drew_opgp_parser_parse_packet_header(drew_opgp_parser_t parser,
		drew_opgp_packet_t *pkt, const uint8_t *data, size_t datalen);
int drew_opgp_parser_parse_packet_contents(drew_opgp_parser_t parser,
		drew_opgp_packet_t *pkt, const uint8_t *data, size_t datalen);

#endif
