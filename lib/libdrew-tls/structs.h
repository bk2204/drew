#ifndef DREW_TLS_STRUCTS_H
#define DREW_TLS_STRUCTS_H

#include <stdbool.h>

#include <drew/block.h>
#include <drew/stream.h>
#include <drew/mac.h>

typedef enum {
	connection_end_server,
	connection_end_client
} drew_tls_connection_end_t;

typedef enum {
	content_type_change_cipher_spec = 20,
	content_type_alert = 21,
	content_type_handshake = 22,
	content_type_application_data = 23
} drew_tls_content_type_t;

typedef struct {
	int end;
	drew_block_t *block;
	drew_stream_t *stream;
	drew_mac_t *mac;
	size_t key_size;
	size_t key_material_length;
	size_t hash_size;
	bool is_exportable;
	void *compression; 	// Not implemented; not currently used.
	uint8_t master_secret[48];
	uint8_t client_random[32];
	uint8_t server_random[32];
} drew_tls_security_parameters_t;

typedef struct {
	uint8_t *client_mac;
	uint8_t *server_mac;
	uint8_t *client_key;
	uint8_t *server_key;
	uint8_t *client_iv;
	uint8_t *server_iv;
} drew_tls_connection_parameters_t;

typedef struct {
	uint8_t major, minor;
} drew_tls_protocol_version_t;

typedef struct {
	drew_tls_content_type_t type;
	drew_tls_protocol_version_t version;
	uint16_t length;
	uint8_t *fragment;
} drew_tls_tls_plaintext_t;

typedef drew_tls_tls_plaintext_t drew_tls_tls_compressed_t;

typedef struct {
	uint8_t *content;
	size_t content_length;
	uint8_t *mac;
	size_t mac_length;
} drew_tls_generic_stream_cipher_t;

typedef struct {
	uint8_t *content;
	size_t content_length;
	uint8_t *mac;
	size_t mac_length;
	uint8_t *padding;
	uint8_t padding_length;
} drew_tls_generic_block_cipher_t;

typedef struct {
	drew_tls_content_type_t type;
	drew_tls_protocol_version_t version;
	uint16_t length;
	union {
		drew_tls_generic_stream_cipher_t generic_stream_cipher;
		drew_tls_generic_block_cipher_t generic_block_cipher;
	} fragment;
} drew_tls_tls_ciphertext_t;

#endif
