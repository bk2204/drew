#ifndef DREW_TLS_H
#define DREW_TLS_H

#include <stdint.h>
#include <sys/types.h>

#define DREW_TLS_ERR_BASE						0x40000
#define DREW_TLS_ERR_CLOSE_NOTIFY				0x40000
#define DREW_TLS_ERR_UNEXPECTED_MESSAGE			0x4000a
#define DREW_TLS_ERR_BAD_RECORD_MAC				0x40014
#define DREW_TLS_ERR_DECRYPTION_FAILED			0x40015
#define DREW_TLS_ERR_RECORD_OVERFLOW			0x40016
#define DREW_TLS_ERR_DECOMPRESSION_FAILURE		0x4001e
#define DREW_TLS_ERR_HANDSHAKE_FAILURE			0x40028
#define DREW_TLS_ERR_BAD_CERTIFICATE			0x4002a
#define DREW_TLS_ERR_UNSUPPORTED_CERTIFICATE	0x4002b
#define DREW_TLS_ERR_CERTIFICATE_REVOKED		0x4002c
#define DREW_TLS_ERR_CERTIFICATE_EXPIRED		0x4002d
#define DREW_TLS_ERR_CERTIFICATE_UNKNOWN		0x4002e
#define DREW_TLS_ERR_ILLEGAL_PARAMETER			0x4002f
#define DREW_TLS_ERR_UNKNOWN_CA					0x40030
#define DREW_TLS_ERR_ACCESS_DENIED				0x40031
#define DREW_TLS_ERR_DECODE_ERROR				0x40032
#define DREW_TLS_ERR_DECRYPT_ERROR				0x40033
#define DREW_TLS_ERR_EXPORT_RESTRICTION			0x4003c
#define DREW_TLS_ERR_PROTOCOL_VERSION			0x40046
#define DREW_TLS_ERR_INSUFFICIENT_SECURITY		0x40047
#define DREW_TLS_ERR_INTERNAL_ERROR				0x40050
#define DREW_TLS_ERR_USER_CANCELED				0x4005a
#define DREW_TLS_ERR_NO_RENEGOTIATION			0x40064

typedef struct {
	uint8_t major, minor;
} drew_tls_protocol_version_t;

typedef void *drew_tls_data_ctxt_t;
typedef ssize_t (*drew_tls_data_in_func_t)(drew_tls_data_ctxt_t, void *,
		size_t);
typedef ssize_t (*drew_tls_data_out_func_t)(drew_tls_data_ctxt_t, const void *,
		size_t);
#endif
