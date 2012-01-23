/*-
 * Copyright © 2010–2012 brian m. carlson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef DREW_TLS_STRUCTS_H
#define DREW_TLS_STRUCTS_H

#include <stdbool.h>

#include <drew/block.h>
#include <drew/bignum.h>
#include <drew/stream.h>
#include <drew/mac.h>

#include <drew-tls/drew-tls.h>
#include <drew-tls/priority.h>
#include <drew-tls/session.h>

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

typedef enum {
	compression_method_null = 0
} drew_tls_compression_method_t;

typedef enum {
	cipher_type_stream = 0,
	cipher_type_block,
	cipher_type_null = 256 // Non-standard.
} drew_tls_cipher_type_t;

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
	drew_tls_content_type_t type;
	drew_tls_protocol_version_t version;
	uint16_t length;
	uint8_t *fragment;
} drew_tls_record_t;

typedef drew_tls_record_t drew_tls_tls_plaintext_t;
typedef drew_tls_record_t drew_tls_tls_compressed_t;

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

typedef struct {
	uint32_t gmt_unix_time;
	uint8_t random_bytes[28];
} drew_tls_random_t;

typedef struct {
	drew_tls_protocol_version_t version;
	drew_tls_random_t random;
	drew_tls_session_id_t session_id;
	uint16_t cipher_suites_length;
	drew_tls_cipher_suite_t *cipher_suites;
	uint8_t compression_methods_length;
	drew_tls_compression_method_t *compression_methods;
} drew_tls_client_hello_t;

typedef struct {
	drew_tls_protocol_version_t version;
	drew_tls_random_t random;
	drew_tls_session_id_t session_id;
	drew_tls_cipher_suite_t cipher_suite;
	drew_tls_compression_method_t compression_method;
} drew_tls_server_hello_t;

typedef struct drew_tls_session_queues_s *drew_tls_session_queues_t;

typedef struct {
	int nmsgs; // The number of hashes used to calculate Finished messages.
	drew_hash_t msgs[2]; // The hash contexts for the above.
} drew_tls_handshake_t;

typedef struct {
	drew_bignum_t p;
	drew_bignum_t g;
	drew_bignum_t ys;
} drew_tls_dh_keyex_t;

#define HELLO_RANDOM_SIZE 32
struct drew_tls_session_s {
	int client; // is this the client end or the server end?
	int enc_type;
	drew_tls_cipher_suite_t cs;
	const drew_loader_t *ldr;
	drew_prng_t *prng;
	drew_tls_session_queues_t queues;
	uint8_t block_size;
	uint8_t hash_size;
	drew_mac_t *inmac;
	drew_mode_t *inmode;
	uint64_t inseqnum;
	drew_mac_t *outmac;
	drew_mode_t *outmode;
	uint64_t outseqnum;
	drew_tls_handshake_t handshake;
	int handshake_state;
	int state;
	uint8_t client_random[HELLO_RANDOM_SIZE];
	uint8_t server_random[HELLO_RANDOM_SIZE];
	drew_tls_dh_keyex_t keyex;
	drew_tls_priority_t prio;
	drew_tls_session_id_t session_id;
	drew_tls_protocol_version_t protover;
	drew_tls_data_ctxt_t data_inp;
	drew_tls_data_ctxt_t data_outp;
	drew_tls_data_in_func_t data_infunc;
	drew_tls_data_out_func_t data_outfunc;
	drew_tls_cert_ctxt_t cert_ctxt;
	drew_tls_cert_callback_t cert_callback;
	DREW_TLS_MUTEX_DECL()
};

#endif
