#include <drew-tls/session.h>

#include <gnutls/gnutls.h>

int gnutls_init(gnutls_session_t *session, gnutls_connection_end_t con_end)
{
	int res = drew_tls_session_init(session->dt_sess, con_end);
	return drew_gnutls_map_error(res);
}

void gnutls_deinit(gnutls_session_t session)
{
	drew_tls_session_fini(session->dt_sess);
	// FIXME: remove session from database if it was terminated abnormally.
}
