#ifndef DREW_TLS_PRIORITY_H
#define DREW_TLS_PRIORITY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

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
	size_t cipher_key_len;
	int flags;
} drew_tls_cipher_suite_info_t;

int drew_tls_priority_init(drew_tls_priority_t *prio);
int drew_tls_priority_get_cipher_suites(drew_tls_priority_t prio,
		drew_tls_cipher_suite_t **suites, size_t *nsuites);
int drew_tls_priority_set_sensible_default(drew_tls_priority_t prio);
int drew_tls_priority_fini(drew_tls_priority_t *prio);
int drew_tls_priority_set_string(drew_tls_priority_t prio, const char *s);

#ifdef __cplusplus
}
#endif

#endif
