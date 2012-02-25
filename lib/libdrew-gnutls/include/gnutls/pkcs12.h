int gnutls_pkcs12_init(gnutls_pkcs12_t *pkcs12);
void gnutls_pkcs12_deinit(gnutls_pkcs12_t pkcs12);
int gnutls_pkcs12_import(gnutls_pkcs12_t pkcs12, const gnutls_datum_t *data, gnutls_x509_crt_fmt_t format, unsigned int flags);
int gnutls_pkcs12_export(gnutls_pkcs12_t pkcs12, gnutls_x509_crt_fmt_t format, void *output_data, size_t *output_data_size);
int gnutls_pkcs12_get_bag(gnutls_pkcs12_t pkcs12, int indx, gnutls_pkcs12_bag_t bag);
int gnutls_pkcs12_set_bag(gnutls_pkcs12_t pkcs12, gnutls_pkcs12_bag_t bag);
int gnutls_pkcs12_generate_mac(gnutls_pkcs12_t pkcs12, const char *pass);
int gnutls_pkcs12_verify_mac(gnutls_pkcs12_t pkcs12, const char *pass);
int gnutls_pkcs12_bag_decrypt(gnutls_pkcs12_bag_t bag, const char *pass);
int gnutls_pkcs12_bag_encrypt(gnutls_pkcs12_bag_t bag, const char *pass, unsigned int flags);
gnutls_pkcs12_bag_type_t gnutls_pkcs12_bag_get_type(gnutls_pkcs12_bag_t bag, int indx);
int gnutls_pkcs12_bag_get_data(gnutls_pkcs12_bag_t bag, int indx, gnutls_datum_t *data);
int gnutls_pkcs12_bag_set_data(gnutls_pkcs12_bag_t bag, gnutls_pkcs12_bag_type_t type, const gnutls_datum_t *data);
int gnutls_pkcs12_bag_set_crl(gnutls_pkcs12_bag_t bag, gnutls_x509_crl_t crl);
int gnutls_pkcs12_bag_set_crt(gnutls_pkcs12_bag_t bag, gnutls_x509_crt_t crt);
int gnutls_pkcs12_bag_init(gnutls_pkcs12_bag_t *bag);
void gnutls_pkcs12_bag_deinit(gnutls_pkcs12_bag_t bag);
int gnutls_pkcs12_bag_get_count(gnutls_pkcs12_bag_t bag);
int gnutls_pkcs12_bag_get_key_id(gnutls_pkcs12_bag_t bag, int indx, gnutls_datum_t *id);
int gnutls_pkcs12_bag_set_key_id(gnutls_pkcs12_bag_t bag, int indx, const gnutls_datum_t *id);
int gnutls_pkcs12_bag_get_friendly_name(gnutls_pkcs12_bag_t bag, int indx, char **name);
int gnutls_pkcs12_bag_set_friendly_name(gnutls_pkcs12_bag_t bag, int indx, const char *name);