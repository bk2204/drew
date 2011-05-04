#include "internal.h"

#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include <drew-tls/drew-tls.h>
#include <drew-tls/priority.h>
#include <drew-tls/session.h>

#include <drew/hash.h>
#include <drew/plugin.h>

#include "structs.h"

#define RETFAIL(x) do { if ((res = (x))) return res; } while (0)

/* Returns 0 on success or a negative value on error.  On success, hash will be
 * initialized and of the type specified in name.
 */
static int make_hash(const drew_loader_t *ldr, const char *name,
		drew_hash_t *hash)
{
	int res = 0;
	int start = 0;

	memset(hash, 0, sizeof(*hash));

	for (;;) {
		int id;
		const void *functbl;

		if ((id = res = drew_loader_lookup_by_name(ldr, name, start, -1)) < 0)
			break;
		start = id + 1;
		if (drew_loader_get_type(ldr, id) != DREW_TYPE_HASH)
			continue;
		if ((res = drew_loader_get_functbl(ldr, id, &functbl)))
			continue;
		hash->functbl = functbl;
		if (!(res = hash->functbl->init(hash, 0, ldr, NULL)))
			break;
	}
	// FIXME: remove -ENOENT once libdrew stops using it.
	if (res == -ENOENT)
		return -DREW_ERR_NONEXISTENT;
	return res;
}

static int make_prng(const drew_loader_t *ldr, const char *name,
		drew_prng_t *prng)
{
	int res = 0;
	int start = 0;

	memset(prng, 0, sizeof(*prng));

	if (!name)
		name = "ARC4Stir";

	for (;;) {
		int id;
		const void *functbl;

		if ((id = res = drew_loader_lookup_by_name(ldr, name, start, -1)) < 0)
			break;
		start = id + 1;
		if (drew_loader_get_type(ldr, id) != DREW_TYPE_PRNG)
			continue;
		if ((res = drew_loader_get_functbl(ldr, id, &functbl)))
			continue;
		prng->functbl = functbl;
		if (!(res = prng->functbl->init(prng, 0, ldr, NULL)))
			break;
	}
	// FIXME: remove -ENOENT once libdrew stops using it.
	if (res == -ENOENT)
		return -DREW_ERR_NONEXISTENT;
	return res;
}

int drew_tls_session_init(drew_tls_session_t *sess, const drew_loader_t *ldr)
{
	int res = 0;
	drew_tls_session_t s = NULL;
	s = malloc(sizeof(*s));
	if (!s)
		return -ENOMEM;

	s->ldr = ldr;
	s->data_inp = -1;
	s->data_outp = -1;
	s->data_infunc = (drew_tls_data_in_func_t)recv;
	s->data_outfunc = (drew_tls_data_out_func_t)send;
	if ((res = make_prng(s->ldr, NULL, s->prng))) {
		free(s);
		return res;
	}

	*sess = s;
	// FIXME: allocate shit.
	return 0;
}

int drew_tls_session_fini(drew_tls_session_t *sess)
{
	drew_tls_session_t s = *sess;
	// FIXME: free shit.
	s->prng->functbl->fini(s->prng, 0);
	free(*sess);
	*sess = NULL;
	return 0;
}

int drew_tls_session_set_end(drew_tls_session_t sess, int client)
{
	if (client != 0 && client != 1)
		return -DREW_TLS_ERR_INVALID;
	sess->client = client;
	return 0;
}

int drew_tls_session_set_priority(drew_tls_session_t sess,
		drew_tls_priority_t prio)
{
}

int drew_tls_session_set_transport(drew_tls_session_t sess,
		drew_tls_data_in_func_t inf, drew_tls_data_out_func_t outf,
		drew_tls_data_ctxt_t inp, drew_tls_data_ctxt_t outp)
{
	sess->data_inp = inp;
	sess->data_outp = outp;
	sess->data_infunc = inf;
	sess->data_outfunc = outf;
	return 0;
}

int drew_tls_session_get_transport(drew_tls_session_t sess,
		drew_tls_data_in_func_t *inf, drew_tls_data_out_func_t *outf,
		drew_tls_data_ctxt_t *inp, drew_tls_data_ctxt_t *outp)
{
	*inf = sess->data_infunc;
	*outf = sess->data_outfunc;
	*inp = sess->data_inp;
	*outp = sess->data_outp;
	return 0;
}

static int handshake_send_client_hello(drew_tls_session_t sess)
{
}

static int handshake_client(drew_tls_session_t sess)
{
	int res = 0;
	RETFAIL(handshake_send_client_hello(sess));
}

int drew_tls_session_handshake(drew_tls_session_t sess)
{
	int res = 0;
	RETFAIL(make_hash(sess->ldr, "MD5", &sess->handshake.md5));
	RETFAIL(make_hash(sess->ldr, "SHA-1", &sess->handshake.sha1));
	return sess->client ? handshake_client(sess) : handshake_server(sess);
}
