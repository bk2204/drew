#ifndef DREW_TLS_PRIORITY_H
#define DREW_TLS_PRIORITY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct drew_tls_priority_s {
	int dummy;
} *drew_tls_priority_t;

typedef struct {
	uint8_t val[2];
} drew_tls_cipher_suite_t;

int drew_tls_priority_get_cipher_suites(drew_tls_priority_t prio,
		drew_tls_cipher_suite_t **suites, size_t *nsuites);

#ifdef __cplusplus
}
#endif

#endif
