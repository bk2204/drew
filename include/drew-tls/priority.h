#ifndef DREW_TLS_PRIORITY_H
#define DREW_TLS_PRIORITY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// These are bit flags.
#define DREW_TLS_PROFILE_NONE			0
#define DREW_TLS_PROFILE_SUITE_B_128	1
#define DREW_TLS_PROFILE_SUITE_B_192	2
#define DREW_TLS_PROFILE_SUITE_B		3
#define DREW_TLS_PROFILE_IMAP			8
#define DREW_TLS_PROFILE_SECURE			16
#define DREW_TLS_PROFILE_TLS_12			32

#define DREW_TLS_CIPHER_TYPE_NONE		0
#define DREW_TLS_CIPHER_TYPE_STREAM		1
#define DREW_TLS_CIPHER_TYPE_CBC		2
#define DREW_TLS_CIPHER_TYPE_GCM		3

struct drew_tls_priority_s;

typedef struct drew_tls_priority_s *drew_tls_priority_t;

typedef struct {
	uint8_t val[2];
} drew_tls_cipher_suite_t;

typedef struct {
	const char *mac;
	const char *keyex;
	const char *pkauth;
	const char *hash;
	const char *cipher;
	const char *eccurve;
	size_t cipher_key_len;
	int cipher_type;
	int profile;
	int flags;
	void *pad[4];
} drew_tls_cipher_suite_info_t;

DREW_SYM_PUBLIC
int drew_tls_priority_init(drew_tls_priority_t *prio);

DREW_SYM_PUBLIC
int drew_tls_priority_get_cipher_suites(drew_tls_priority_t prio,
		drew_tls_cipher_suite_t **suites, size_t *nsuites);

DREW_SYM_PUBLIC
int drew_tls_priority_set_sensible_default(drew_tls_priority_t prio);

DREW_SYM_PUBLIC
int drew_tls_priority_fini(drew_tls_priority_t *prio);

DREW_SYM_PUBLIC
int drew_tls_priority_set_string(drew_tls_priority_t prio, const char *s);

DREW_SYM_PUBLIC
int drew_tls_priority_get_cipher_suite_info(drew_tls_priority_t prio,
		drew_tls_cipher_suite_info_t *info, const drew_tls_cipher_suite_t *cs);

#ifdef __cplusplus
}
#endif

#endif
