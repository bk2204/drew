#ifndef DREW_TLS_SESSION_H
#define DREW_TLS_SESSION_H

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
	uint8_t *sessionid;
} drew_tls_session_id_t;

struct drew_tls_session_s {
	int client; // is this the client end or the server end?
	int enc_type;
	const drew_loader_t *ldr;
	drew_prng_t *prng;
	drew_mac_t *mac;
	drew_tls_priority_t prio;
	drew_tls_session_id_t session_id;
	drew_tls_protocol_version_t protover;
	drew_tls_data_ctxt_t data_inp;
	drew_tls_data_ctxt_t data_outp;
	drew_tls_data_in_func_t data_infunc;
	drew_tls_data_out_func_t data_outfunc;
	DREW_TLS_MUTEX_DECL()
};

typedef struct drew_tls_session_s *drew_tls_session_t;

#endif
