#ifndef DREW_GNUTLS_H
#define DREW_GNUTLS_H

typedef void (*gnutls_log_func)(int level, const char *s);

/* Yes, these look ugly, but they're the result of a perl script. */
int gnutls_init(gnutls_session_t *session, gnutls_connection_end_t con_end);
void gnutls_deinit(gnutls_session_t session);
int gnutls_bye(gnutls_session_t session, gnutls_close_request_t how);
int gnutls_handshake(gnutls_session_t session);
int gnutls_rehandshake(gnutls_session_t session);
gnutls_alert_description_t gnutls_alert_get(gnutls_session_t session);
int gnutls_alert_send(gnutls_session_t session, gnutls_alert_level_t level, gnutls_alert_description_t desc);
int gnutls_alert_send_appropriate(gnutls_session_t session, int err);
gnutls_sec_param_t gnutls_pk_bits_to_sec_param(gnutls_pk_algorithm_t algo, unsigned int bits);
unsigned int gnutls_sec_param_to_pk_bits(gnutls_pk_algorithm_t algo, gnutls_sec_param_t param);
gnutls_cipher_algorithm_t gnutls_cipher_get(gnutls_session_t session);
gnutls_kx_algorithm_t gnutls_kx_get(gnutls_session_t session);
gnutls_mac_algorithm_t gnutls_mac_get(gnutls_session_t session);
gnutls_compression_method_t gnutls_compression_get(gnutls_session_t session);
gnutls_certificate_type_t gnutls_certificate_type_get(gnutls_session_t session);
int gnutls_sign_algorithm_get_requested(gnutls_session_t session, size_t indx, gnutls_sign_algorithm_t *algo);
gnutls_mac_algorithm_t gnutls_mac_get_id(const char *name);
gnutls_compression_method_t gnutls_compression_get_id(const char *name);
gnutls_cipher_algorithm_t gnutls_cipher_get_id(const char *name);
gnutls_kx_algorithm_t gnutls_kx_get_id(const char *name);
gnutls_protocol_t gnutls_protocol_get_id(const char *name);
gnutls_certificate_type_t gnutls_certificate_type_get_id(const char *name);
gnutls_pk_algorithm_t gnutls_pk_get_id(const char *name);
gnutls_sign_algorithm_t gnutls_sign_get_id(const char *name);
int gnutls_error_is_fatal(int error);
int gnutls_error_to_alert(int err, int *level);
void gnutls_perror(int error);
void gnutls_handshake_set_private_extensions(gnutls_session_t session, int allow);
gnutls_handshake_description_t gnutls_handshake_get_last_out(gnutls_session_t session);
gnutls_handshake_description_t gnutls_handshake_get_last_in(gnutls_session_t session);
void gnutls_session_enable_compatibility_mode(gnutls_session_t session);
void gnutls_record_disable_padding(gnutls_session_t session);
int gnutls_record_get_direction(gnutls_session_t session);
int gnutls_prf(gnutls_session_t session, size_t label_size, const char *label, int server_random_first, size_t extra_size, const char *extra, size_t outsize, char *out);
int gnutls_prf_raw(gnutls_session_t session, size_t label_size, const char *label, size_t seed_size, const char *seed, size_t outsize, char *out);
int gnutls_server_name_set(gnutls_session_t session, gnutls_server_name_type_t type, const void *name, size_t name_length);
int gnutls_server_name_get(gnutls_session_t session, void *data, size_t *data_length, unsigned int *type, unsigned int indx);
int gnutls_safe_renegotiation_status(gnutls_session_t session);
int gnutls_session_ticket_key_generate(gnutls_datum_t *key);
int gnutls_session_ticket_enable_client(gnutls_session_t session);
int gnutls_session_ticket_enable_server(gnutls_session_t session, const gnutls_datum_t *key);
int gnutls_priority_init(gnutls_priority_t *priority_cache, const char *priorities, const char **err_pos);
void gnutls_priority_deinit(gnutls_priority_t priority_cache);
int gnutls_priority_set(gnutls_session_t session, gnutls_priority_t priority);
int gnutls_priority_set_direct(gnutls_session_t session, const char *priorities, const char **err_pos);
int gnutls_set_default_priority(gnutls_session_t session);
int gnutls_set_default_export_priority(gnutls_session_t session);
gnutls_protocol_t gnutls_protocol_get_version(gnutls_session_t session);
int gnutls_session_set_data(gnutls_session_t session, const void *session_data, size_t session_data_size);
int gnutls_session_get_data(gnutls_session_t session, void *session_data, size_t *session_data_size);
int gnutls_session_get_data2(gnutls_session_t session, gnutls_datum_t *data);
int gnutls_session_get_id(gnutls_session_t session, void *session_id, size_t *session_id_size);
int gnutls_session_channel_binding(gnutls_session_t session, gnutls_channel_binding_t cbtype, gnutls_datum_t *cb);
int gnutls_session_is_resumed(gnutls_session_t session);
void gnutls_db_set_cache_expiration(gnutls_session_t session, int seconds);
void gnutls_db_remove_session(gnutls_session_t session);
void gnutls_db_set_retrieve_function(gnutls_session_t session, gnutls_db_retr_func retr_func);
void gnutls_db_set_remove_function(gnutls_session_t session, gnutls_db_remove_func rem_func);
void gnutls_db_set_store_function(gnutls_session_t session, gnutls_db_store_func store_func);
void gnutls_db_set_ptr(gnutls_session_t session, void *ptr);
int gnutls_db_check_entry(gnutls_session_t session, gnutls_datum_t session_entry);
void gnutls_handshake_set_post_client_hello_function(gnutls_session_t session, gnutls_handshake_post_client_hello_func func);
void gnutls_handshake_set_max_packet_length(gnutls_session_t session, size_t max);
void gnutls_credentials_clear(gnutls_session_t session);
int gnutls_credentials_set(gnutls_session_t session, gnutls_credentials_type_t type, void *cred);
void gnutls_anon_free_server_credentials(gnutls_anon_server_credentials_t sc);
int gnutls_anon_allocate_server_credentials(gnutls_anon_server_credentials_t *sc);
void gnutls_anon_set_server_dh_params(gnutls_anon_server_credentials_t res, gnutls_dh_params_t dh_params);
void gnutls_anon_set_server_params_function(gnutls_anon_server_credentials_t res, gnutls_params_function *func);
void gnutls_anon_free_client_credentials(gnutls_anon_client_credentials_t sc);
int gnutls_anon_allocate_client_credentials(gnutls_anon_client_credentials_t *sc);
void gnutls_certificate_free_credentials(gnutls_certificate_credentials_t sc);
int gnutls_certificate_allocate_credentials(gnutls_certificate_credentials_t *res);
void gnutls_certificate_free_keys(gnutls_certificate_credentials_t sc);
void gnutls_certificate_free_cas(gnutls_certificate_credentials_t sc);
void gnutls_certificate_free_ca_names(gnutls_certificate_credentials_t sc);
void gnutls_certificate_free_crls(gnutls_certificate_credentials_t sc);
void gnutls_certificate_set_dh_params(gnutls_certificate_credentials_t res, gnutls_dh_params_t dh_params);
void gnutls_certificate_set_rsa_export_params(gnutls_certificate_credentials_t res, gnutls_rsa_params_t rsa_params);
void gnutls_certificate_set_verify_flags(gnutls_certificate_credentials_t res, unsigned int flags);
void gnutls_certificate_set_verify_limits(gnutls_certificate_credentials_t res, unsigned int max_bits, unsigned int max_depth);
int gnutls_certificate_set_x509_trust_file(gnutls_certificate_credentials_t res, const char *cafile, gnutls_x509_crt_fmt_t type);
int gnutls_certificate_set_x509_trust_mem(gnutls_certificate_credentials_t res, const gnutls_datum_t *ca, gnutls_x509_crt_fmt_t type);
int gnutls_certificate_set_x509_crl_file(gnutls_certificate_credentials_t res, const char *crlfile, gnutls_x509_crt_fmt_t type);
int gnutls_certificate_set_x509_crl_mem(gnutls_certificate_credentials_t res, const gnutls_datum_t *CRL, gnutls_x509_crt_fmt_t type);
int gnutls_certificate_set_x509_key_file(gnutls_certificate_credentials_t res, const char *certfile, const char *keyfile, gnutls_x509_crt_fmt_t type);
int gnutls_certificate_set_x509_key_mem(gnutls_certificate_credentials_t res, const gnutls_datum_t *cert, const gnutls_datum_t *key, gnutls_x509_crt_fmt_t type);
void gnutls_certificate_send_x509_rdn_sequence(gnutls_session_t session, int status);
int gnutls_certificate_set_x509_simple_pkcs12_file(gnutls_certificate_credentials_t res, const char *pkcs12file, gnutls_x509_crt_fmt_t type, const char *password);
int gnutls_certificate_set_x509_simple_pkcs12_mem(gnutls_certificate_credentials_t res, const gnutls_datum_t *p12blob, gnutls_x509_crt_fmt_t type, const char *password);
int gnutls_certificate_set_x509_key(gnutls_certificate_credentials_t res, gnutls_x509_crt_t *cert_list, int cert_list_size, gnutls_x509_privkey_t key);
int gnutls_certificate_set_x509_trust(gnutls_certificate_credentials_t res, gnutls_x509_crt_t *ca_list, int ca_list_size);
int gnutls_certificate_set_x509_crl(gnutls_certificate_credentials_t res, gnutls_x509_crl_t *crl_list, int crl_list_size);
int gnutls_global_init(void);
void gnutls_global_deinit(void);
void gnutls_global_set_mutex(mutex_init_func init, mutex_deinit_func deinit, mutex_lock_func lock, mutex_unlock_func unlock);
void gnutls_global_set_mem_functions(gnutls_alloc_function alloc_func, gnutls_alloc_function secure_alloc_func, gnutls_is_secure_function is_secure_func, gnutls_realloc_function realloc_func, gnutls_free_function free_func);
void gnutls_global_set_log_function(gnutls_log_func log_func);
void gnutls_global_set_log_level(int level);
int gnutls_dh_params_init(gnutls_dh_params_t *dh_params);
void gnutls_dh_params_deinit(gnutls_dh_params_t dh_params);
int gnutls_dh_params_import_raw(gnutls_dh_params_t dh_params, const gnutls_datum_t *prime, const gnutls_datum_t *generator);
int gnutls_dh_params_import_pkcs3(gnutls_dh_params_t params, const gnutls_datum_t *pkcs3_params, gnutls_x509_crt_fmt_t format);
int gnutls_dh_params_generate2(gnutls_dh_params_t params, unsigned int bits);
int gnutls_dh_params_export_pkcs3(gnutls_dh_params_t params, gnutls_x509_crt_fmt_t format, unsigned char *params_data, size_t *params_data_size);
int gnutls_dh_params_export_raw(gnutls_dh_params_t params, gnutls_datum_t *prime, gnutls_datum_t *generator, unsigned int *bits);
int gnutls_dh_params_cpy(gnutls_dh_params_t dst, gnutls_dh_params_t src);
int gnutls_rsa_params_init(gnutls_rsa_params_t *rsa_params);
void gnutls_rsa_params_deinit(gnutls_rsa_params_t rsa_params);
int gnutls_rsa_params_cpy(gnutls_rsa_params_t dst, gnutls_rsa_params_t src);
int gnutls_rsa_params_import_raw(gnutls_rsa_params_t rsa_params, const gnutls_datum_t *m, const gnutls_datum_t *e, const gnutls_datum_t *d, const gnutls_datum_t *p, const gnutls_datum_t *q, const gnutls_datum_t *u);
int gnutls_rsa_params_generate2(gnutls_rsa_params_t params, unsigned int bits);
int gnutls_rsa_params_export_raw(gnutls_rsa_params_t params, gnutls_datum_t *m, gnutls_datum_t *e, gnutls_datum_t *d, gnutls_datum_t *p, gnutls_datum_t *q, gnutls_datum_t *u, unsigned int *bits);
int gnutls_rsa_params_export_pkcs1(gnutls_rsa_params_t params, gnutls_x509_crt_fmt_t format, unsigned char *params_data, size_t *params_data_size);
int gnutls_rsa_params_import_pkcs1(gnutls_rsa_params_t params, const gnutls_datum_t *pkcs1_params, gnutls_x509_crt_fmt_t format);
void gnutls_transport_set_ptr(gnutls_session_t session, gnutls_transport_ptr_t ptr);
void gnutls_transport_set_ptr2(gnutls_session_t session, gnutls_transport_ptr_t recv_ptr, gnutls_transport_ptr_t send_ptr);
gnutls_transport_ptr_t gnutls_transport_get_ptr(gnutls_session_t session);
void gnutls_transport_get_ptr2(gnutls_session_t session, gnutls_transport_ptr_t *recv_ptr, gnutls_transport_ptr_t *send_ptr);
void gnutls_transport_set_vec_push_function(gnutls_session_t session, gnutls_vec_push_func vec_func);
void gnutls_transport_set_push_function(gnutls_session_t session, gnutls_push_func push_func);
void gnutls_transport_set_pull_function(gnutls_session_t session, gnutls_pull_func pull_func);
void gnutls_transport_set_errno_function(gnutls_session_t session, gnutls_errno_func errno_func);
void gnutls_transport_set_errno(gnutls_session_t session, int err);
void gnutls_session_set_ptr(gnutls_session_t session, void *ptr);
void gnutls_openpgp_send_cert(gnutls_session_t session, gnutls_openpgp_crt_status_t status);
int gnutls_fingerprint(gnutls_digest_algorithm_t algo, const gnutls_datum_t *data, void *result, size_t *result_size);
void gnutls_srp_free_client_credentials(gnutls_srp_client_credentials_t sc);
int gnutls_srp_allocate_client_credentials(gnutls_srp_client_credentials_t *sc);
int gnutls_srp_set_client_credentials(gnutls_srp_client_credentials_t res, const char *username, const char *password);
void gnutls_srp_free_server_credentials(gnutls_srp_server_credentials_t sc);
int gnutls_srp_allocate_server_credentials(gnutls_srp_server_credentials_t *sc);
int gnutls_srp_set_server_credentials_file(gnutls_srp_server_credentials_t res, const char *password_file, const char *password_conf_file);
int gnutls_srp_verifier(const char *username, const char *password, const gnutls_datum_t *salt, const gnutls_datum_t *generator, const gnutls_datum_t *prime, gnutls_datum_t *res);
void gnutls_srp_set_server_credentials_function(gnutls_srp_server_credentials_t cred, gnutls_srp_server_credentials_function *func);
void gnutls_srp_set_client_credentials_function(gnutls_srp_client_credentials_t cred, gnutls_srp_client_credentials_function *func);
int gnutls_srp_base64_encode(const gnutls_datum_t *data, char *result, size_t *result_size);
int gnutls_srp_base64_encode_alloc(const gnutls_datum_t *data, gnutls_datum_t *result);
int gnutls_srp_base64_decode(const gnutls_datum_t *b64_data, char *result, size_t *result_size);
int gnutls_srp_base64_decode_alloc(const gnutls_datum_t *b64_data, gnutls_datum_t *result);
void gnutls_psk_free_client_credentials(gnutls_psk_client_credentials_t sc);
int gnutls_psk_allocate_client_credentials(gnutls_psk_client_credentials_t *sc);
int gnutls_psk_set_client_credentials(gnutls_psk_client_credentials_t res, const char *username, const gnutls_datum_t *key, gnutls_psk_key_flags format);
void gnutls_psk_free_server_credentials(gnutls_psk_server_credentials_t sc);
int gnutls_psk_allocate_server_credentials(gnutls_psk_server_credentials_t *sc);
int gnutls_psk_set_server_credentials_file(gnutls_psk_server_credentials_t res, const char *password_file);
int gnutls_psk_set_server_credentials_hint(gnutls_psk_server_credentials_t res, const char *hint);
void gnutls_psk_set_server_credentials_function(gnutls_psk_server_credentials_t cred, gnutls_psk_server_credentials_function *func);
void gnutls_psk_set_client_credentials_function(gnutls_psk_client_credentials_t cred, gnutls_psk_client_credentials_function *func);
int gnutls_hex_encode(const gnutls_datum_t *data, char *result, size_t *result_size);
int gnutls_hex_decode(const gnutls_datum_t *hex_data, char *result, size_t *result_size);
void gnutls_psk_set_server_dh_params(gnutls_psk_server_credentials_t res, gnutls_dh_params_t dh_params);
void gnutls_psk_set_server_params_function(gnutls_psk_server_credentials_t res, gnutls_params_function *func);
gnutls_credentials_type_t gnutls_auth_get_type(gnutls_session_t session);
gnutls_credentials_type_t gnutls_auth_server_get_type(gnutls_session_t session);
gnutls_credentials_type_t gnutls_auth_client_get_type(gnutls_session_t session);
void gnutls_dh_set_prime_bits(gnutls_session_t session, unsigned int bits);
int gnutls_dh_get_secret_bits(gnutls_session_t session);
int gnutls_dh_get_peers_public_bits(gnutls_session_t session);
int gnutls_dh_get_prime_bits(gnutls_session_t session);
int gnutls_dh_get_group(gnutls_session_t session, gnutls_datum_t *raw_gen, gnutls_datum_t *raw_prime);
int gnutls_dh_get_pubkey(gnutls_session_t session, gnutls_datum_t *raw_key);
int gnutls_rsa_export_get_pubkey(gnutls_session_t session, gnutls_datum_t *exponent, gnutls_datum_t *modulus);
int gnutls_rsa_export_get_modulus_bits(gnutls_session_t session);
void gnutls_certificate_set_retrieve_function(gnutls_certificate_credentials_t cred, gnutls_certificate_retrieve_function *func);
void gnutls_certificate_set_verify_function(gnutls_certificate_credentials_t cred, gnutls_certificate_verify_function *func);
void gnutls_certificate_server_set_request(gnutls_session_t session, gnutls_certificate_request_t req);
int gnutls_certificate_client_get_request_status(gnutls_session_t session);
int gnutls_certificate_verify_peers2(gnutls_session_t session, unsigned int *status);
int gnutls_pem_base64_encode(const char *msg, const gnutls_datum_t *data, char *result, size_t *result_size);
int gnutls_pem_base64_decode(const char *header, const gnutls_datum_t *b64_data, unsigned char *result, size_t *result_size);
int gnutls_pem_base64_encode_alloc(const char *msg, const gnutls_datum_t *data, gnutls_datum_t *result);
int gnutls_pem_base64_decode_alloc(const char *header, const gnutls_datum_t *b64_data, gnutls_datum_t *result);
void gnutls_certificate_set_params_function(gnutls_certificate_credentials_t res, gnutls_params_function *func);
void gnutls_anon_set_params_function(gnutls_anon_server_credentials_t res, gnutls_params_function *func);
void gnutls_psk_set_params_function(gnutls_psk_server_credentials_t res, gnutls_params_function *func);
int gnutls_hex2bin(const char *hex_data, size_t hex_size, char *bin_data, size_t *bin_size);

#define GNUTLS_E_SUCCESS 0
#define GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM -3
#define GNUTLS_E_UNKNOWN_CIPHER_TYPE -6
#define GNUTLS_E_LARGE_PACKET -7
#define GNUTLS_E_UNSUPPORTED_VERSION_PACKET -8
#define GNUTLS_E_UNEXPECTED_PACKET_LENGTH -9
#define GNUTLS_E_INVALID_SESSION -10
#define GNUTLS_E_FATAL_ALERT_RECEIVED -12
#define GNUTLS_E_UNEXPECTED_PACKET -15
#define GNUTLS_E_WARNING_ALERT_RECEIVED -16
#define GNUTLS_E_ERROR_IN_FINISHED_PACKET -18
#define GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET -19
#define GNUTLS_E_UNKNOWN_CIPHER_SUITE -21
#define GNUTLS_E_UNWANTED_ALGORITHM -22
#define GNUTLS_E_MPI_SCAN_FAILED -23
#define GNUTLS_E_DECRYPTION_FAILED -24
#define GNUTLS_E_MEMORY_ERROR -25
#define GNUTLS_E_DECOMPRESSION_FAILED -26
#define GNUTLS_E_COMPRESSION_FAILED -27
#define GNUTLS_E_AGAIN -28
#define GNUTLS_E_EXPIRED -29
#define GNUTLS_E_DB_ERROR -30
#define GNUTLS_E_SRP_PWD_ERROR -31
#define GNUTLS_E_INSUFFICIENT_CREDENTIALS -32
#define GNUTLS_E_INSUFICIENT_CREDENTIALS GNUTLS_E_INSUFFICIENT_CREDENTIALS
#define GNUTLS_E_INSUFFICIENT_CRED GNUTLS_E_INSUFFICIENT_CREDENTIALS
#define GNUTLS_E_INSUFICIENT_CRED GNUTLS_E_INSUFFICIENT_CREDENTIALS
#define GNUTLS_E_HASH_FAILED -33
#define GNUTLS_E_BASE64_DECODING_ERROR -34
#define GNUTLS_E_MPI_PRINT_FAILED -35
#define GNUTLS_E_REHANDSHAKE -37
#define GNUTLS_E_GOT_APPLICATION_DATA -38
#define GNUTLS_E_RECORD_LIMIT_REACHED -39
#define GNUTLS_E_ENCRYPTION_FAILED -40
#define GNUTLS_E_PK_ENCRYPTION_FAILED -44
#define GNUTLS_E_PK_DECRYPTION_FAILED -45
#define GNUTLS_E_PK_SIGN_FAILED -46
#define GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION -47
#define GNUTLS_E_KEY_USAGE_VIOLATION -48
#define GNUTLS_E_NO_CERTIFICATE_FOUND -49
#define GNUTLS_E_INVALID_REQUEST -50
#define GNUTLS_E_SHORT_MEMORY_BUFFER -51
#define GNUTLS_E_INTERRUPTED -52
#define GNUTLS_E_PUSH_ERROR -53
#define GNUTLS_E_PULL_ERROR -54
#define GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER -55
#define GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE -56
#define GNUTLS_E_PKCS1_WRONG_PAD -57
#define GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION -58
#define GNUTLS_E_INTERNAL_ERROR -59
#define GNUTLS_E_DH_PRIME_UNACCEPTABLE -63
#define GNUTLS_E_FILE_ERROR -64
#define GNUTLS_E_TOO_MANY_EMPTY_PACKETS -78
#define GNUTLS_E_UNKNOWN_PK_ALGORITHM -80
#define GNUTLS_E_INIT_LIBEXTRA -82
#define GNUTLS_E_LIBRARY_VERSION_MISMATCH -83
#define GNUTLS_E_NO_TEMPORARY_RSA_PARAMS -84
#define GNUTLS_E_LZO_INIT_FAILED -85
#define GNUTLS_E_NO_COMPRESSION_ALGORITHMS -86
#define GNUTLS_E_NO_CIPHER_SUITES -87
#define GNUTLS_E_OPENPGP_GETKEY_FAILED -88
#define GNUTLS_E_PK_SIG_VERIFY_FAILED -89
#define GNUTLS_E_ILLEGAL_SRP_USERNAME -90
#define GNUTLS_E_SRP_PWD_PARSING_ERROR -91
#define GNUTLS_E_NO_TEMPORARY_DH_PARAMS -93
#define GNUTLS_E_ASN1_ELEMENT_NOT_FOUND -67
#define GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND -68
#define GNUTLS_E_ASN1_DER_ERROR -69
#define GNUTLS_E_ASN1_VALUE_NOT_FOUND -70
#define GNUTLS_E_ASN1_GENERIC_ERROR -71
#define GNUTLS_E_ASN1_VALUE_NOT_VALID -72
#define GNUTLS_E_ASN1_TAG_ERROR -73
#define GNUTLS_E_ASN1_TAG_IMPLICIT -74
#define GNUTLS_E_ASN1_TYPE_ANY_ERROR -75
#define GNUTLS_E_ASN1_SYNTAX_ERROR -76
#define GNUTLS_E_ASN1_DER_OVERFLOW -77
#define GNUTLS_E_OPENPGP_UID_REVOKED -79
#define GNUTLS_E_CERTIFICATE_ERROR -43
#define GNUTLS_E_X509_CERTIFICATE_ERROR GNUTLS_E_CERTIFICATE_ERROR
#define GNUTLS_E_CERTIFICATE_KEY_MISMATCH -60
#define GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE -61
#define GNUTLS_E_X509_UNKNOWN_SAN -62
#define GNUTLS_E_OPENPGP_FINGERPRINT_UNSUPPORTED -94
#define GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE -95
#define GNUTLS_E_UNKNOWN_HASH_ALGORITHM -96
#define GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE -97
#define GNUTLS_E_UNKNOWN_PKCS_BAG_TYPE -98
#define GNUTLS_E_INVALID_PASSWORD -99
#define GNUTLS_E_MAC_VERIFY_FAILED -100
#define GNUTLS_E_CONSTRAINT_ERROR -101
#define GNUTLS_E_WARNING_IA_IPHF_RECEIVED -102
#define GNUTLS_E_WARNING_IA_FPHF_RECEIVED -103
#define GNUTLS_E_IA_VERIFY_FAILED -104
#define GNUTLS_E_UNKNOWN_ALGORITHM -105
#define GNUTLS_E_UNSUPPORTED_SIGNATURE_ALGORITHM -106
#define GNUTLS_E_SAFE_RENEGOTIATION_FAILED -107
#define GNUTLS_E_UNSAFE_RENEGOTIATION_DENIED -108
#define GNUTLS_E_UNKNOWN_SRP_USERNAME -109
#define GNUTLS_E_BASE64_ENCODING_ERROR -201
#define GNUTLS_E_INCOMPATIBLE_GCRYPT_LIBRARY -202
#define GNUTLS_E_INCOMPATIBLE_CRYPTO_LIBRARY -202
#define GNUTLS_E_INCOMPATIBLE_LIBTASN1_LIBRARY -203
#define GNUTLS_E_OPENPGP_KEYRING_ERROR -204
#define GNUTLS_E_X509_UNSUPPORTED_OID -205
#define GNUTLS_E_RANDOM_FAILED -206
#define GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR -207
#define GNUTLS_E_OPENPGP_SUBKEY_ERROR -208
#define GNUTLS_E_CRYPTO_ALREADY_REGISTERED -209
#define GNUTLS_E_HANDSHAKE_TOO_LARGE -210
#define GNUTLS_E_CRYPTODEV_IOCTL_ERROR -211
#define GNUTLS_E_CRYPTODEV_DEVICE_ERROR -212
#define GNUTLS_E_CHANNEL_BINDING_NOT_AVAILABLE -213
#define GNUTLS_E_OPENPGP_PREFERRED_KEY_ERROR -215
#define GNUTLS_E_INCOMPAT_DSA_KEY_WITH_TLS_PROTOCOL -216
#define GNUTLS_E_PKCS11_ERROR -300
#define GNUTLS_E_PKCS11_LOAD_ERROR -301
#define GNUTLS_E_PARSING_ERROR -302
#define GNUTLS_E_PKCS11_PIN_ERROR -303
#define GNUTLS_E_PKCS11_SLOT_ERROR -305
#define GNUTLS_E_LOCKING_ERROR -306
#define GNUTLS_E_PKCS11_ATTRIBUTE_ERROR -307
#define GNUTLS_E_PKCS11_DEVICE_ERROR -308
#define GNUTLS_E_PKCS11_DATA_ERROR -309
#define GNUTLS_E_PKCS11_UNSUPPORTED_FEATURE_ERROR -310
#define GNUTLS_E_PKCS11_KEY_ERROR -311
#define GNUTLS_E_PKCS11_PIN_EXPIRED -312
#define GNUTLS_E_PKCS11_PIN_LOCKED -313
#define GNUTLS_E_PKCS11_SESSION_ERROR -314
#define GNUTLS_E_PKCS11_SIGNATURE_ERROR -315
#define GNUTLS_E_PKCS11_TOKEN_ERROR -316
#define GNUTLS_E_PKCS11_USER_ERROR -317
#define GNUTLS_E_CRYPTO_INIT_FAILED -318
#define GNUTLS_E_UNIMPLEMENTED_FEATURE -1250
#define GNUTLS_E_APPLICATION_ERROR_MAX -65000
#define GNUTLS_E_APPLICATION_ERROR_MIN -65500


#endif
