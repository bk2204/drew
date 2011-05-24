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
	uint8_t *sessionid;
} drew_tls_session_id_t;

struct drew_tls_session_s;

typedef struct drew_tls_session_s *drew_tls_session_t;

#ifdef __cplusplus
}
#endif

#endif
