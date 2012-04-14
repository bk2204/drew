#ifndef DREW_TLS_SESSION_H
#define DREW_TLS_SESSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <drew/drew.h>
#include <drew/plugin.h>
#include <drew/block.h>
#include <drew/hash.h>
#include <drew/mac.h>
#include <drew/mode.h>
#include <drew/prng.h>

#include <drew-util/x509.h>

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

typedef struct {
	const drew_util_x509_cert_t *x509;
	const void *pad[3];
} drew_tls_cert_t;

struct drew_tls_session_s;

typedef struct drew_tls_session_s *drew_tls_session_t;

typedef void *drew_tls_cert_ctxt_t;
typedef int (*drew_tls_cert_callback_t)(drew_tls_cert_ctxt_t,
		drew_tls_session_t, const drew_tls_encoded_cert_t *ecerts,
		const drew_tls_cert_t *dcerts, size_t ncerts);

DREW_SYM_PUBLIC
int drew_tls_session_init(drew_tls_session_t *sess, const drew_loader_t *ldr);

DREW_SYM_PUBLIC
int drew_tls_session_fini(drew_tls_session_t *sess);

DREW_SYM_PUBLIC
int drew_tls_session_set_end(drew_tls_session_t sess, int client);

DREW_SYM_PUBLIC
int drew_tls_session_set_priority(drew_tls_session_t sess,
		drew_tls_priority_t prio);

DREW_SYM_PUBLIC
int drew_tls_session_set_transport(drew_tls_session_t sess,
		drew_tls_data_in_func_t inf, drew_tls_data_out_func_t outf,
		drew_tls_data_ctxt_t inp, drew_tls_data_ctxt_t outp);

DREW_SYM_PUBLIC
int drew_tls_session_get_transport(drew_tls_session_t sess,
		drew_tls_data_in_func_t *inf, drew_tls_data_out_func_t *outf,
		drew_tls_data_ctxt_t *inp, drew_tls_data_ctxt_t *outp);

DREW_SYM_PUBLIC
int drew_tls_session_set_cert_callback(drew_tls_session_t sess,
		drew_tls_cert_callback_t cb);

DREW_SYM_PUBLIC
int drew_tls_session_handshake(drew_tls_session_t sess);

DREW_SYM_PUBLIC
int drew_tls_session_close(drew_tls_session_t sess);

DREW_SYM_PUBLIC
ssize_t drew_tls_session_send(drew_tls_session_t sess, const void *buf,
		size_t len);

DREW_SYM_PUBLIC
ssize_t drew_tls_session_recv(drew_tls_session_t sess, void *b, size_t count);

#ifdef __cplusplus
}
#endif

#endif
