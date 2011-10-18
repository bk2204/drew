#ifndef DREW_TLS_SESSION_H
#define DREW_TLS_SESSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <drew/plugin.h>
#include <drew/block.h>
#include <drew/hash.h>
#include <drew/mac.h>
#include <drew/mode.h>
#include <drew/prng.h>

#include <drew-tls/drew-tls.h>
#include <drew-tls/priority.h>

typedef struct {
	uint8_t length;
	uint8_t sessionid[32];
} drew_tls_session_id_t;

typedef struct {
	size_t len;
	uint8_t *data;
} drew_tls_encoded_cert_t;

struct drew_tls_session_s;

typedef struct drew_tls_session_s *drew_tls_session_t;

typedef void *drew_tls_cert_ctxt_t;
typedef int (*drew_tls_cert_callback_t)(drew_tls_cert_ctxt_t,
		drew_tls_session_t, const drew_tls_encoded_cert_t *certs,
		size_t ncerts);

#ifdef __cplusplus
}
#endif

#endif
