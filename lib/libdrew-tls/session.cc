/*-
 * Copyright © 2010–2011 brian m. carlson
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
#include "internal.h"

#include <utility>

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include <drew/drew.h>
#include <drew/mem.h>
#include <drew/plugin.h>

#include <drew-tls/drew-tls.h>
#include <drew-tls/priority.h>
#include <drew-tls/session.h>

#include "structs.h"
#include "structures.hh"

struct generic {
	void *ctx;
	const void *functbl;
	void *priv;
};

static int make_primitive(const drew_loader_t *ldr, const char *name,
		void *ctxp, int type)
{
	struct generic *ctx = (struct generic *)ctxp;
	int res = 0;
	int start = 0;

	memset(ctx, 0, sizeof(*ctx));

	for (;;) {
		int id;
		const void *functbl;

		if ((id = res = drew_loader_lookup_by_name(ldr, name, start, -1)) < 0)
			break;
		start = id + 1;
		if (drew_loader_get_type(ldr, id) != type)
			continue;
		if ((res = drew_loader_get_functbl(ldr, id, &functbl)))
			continue;
		ctx->functbl = functbl;
	}
	// FIXME: remove -ENOENT once libdrew stops using it.
	if (res == -ENOENT)
		return -DREW_ERR_NONEXISTENT;
	return res;
}

#if 0
/* Returns 0 on success or a negative value on error.  On success, hash will be
 * initialized and of the type specified in name.
 */
static int make_hash(const drew_loader_t *ldr, const char *name,
		drew_hash_t *hash)
{
	int res = 0;

	if ((res = make_primitive(ldr, name, hash, DREW_TYPE_HASH)))
		return res;
	res = hash->functbl->init(hash, 0, ldr, NULL);
	return res;
}
#endif

static int make_prng(const drew_loader_t *ldr, const char *name,
		drew_prng_t *prng)
{
	int res = 0;

	if (!name)
		name = "ARC4Stir";

	if ((res = make_primitive(ldr, name, prng, DREW_TYPE_HASH)))
		return res;
	res = prng->functbl->init(prng, 0, ldr, NULL);
	return res;
}

#if 0
static int make_mode(const drew_loader_t *ldr, const char *name,
		drew_mode_t *mode)
{
	int res = 0;

	if ((res = make_primitive(ldr, name, mode, DREW_TYPE_MODE)))
		return res;
	res = mode->functbl->init(mode, 0, ldr, NULL);
	return res;
}

static int make_mac(const drew_loader_t *ldr, const char *name,
		drew_mac_t *mac, drew_hash_t *hash)
{
	int res = 0;
	drew_param_t param;

	if ((res = make_primitive(ldr, name, mac, DREW_TYPE_MAC)))
		return res;
	param.name = "digest";
	param.param.value = hash;
	res = mac->functbl->init(mac, 0, ldr, hash ? &param : NULL);
	return res;
}
#endif

int drew_tls_session_init(drew_tls_session_t *sess, const drew_loader_t *ldr)
{
	int res = 0;
	drew_tls_session_t s = NULL;
	s = (drew_tls_session_t)malloc(sizeof(*s));
	if (!s)
		return -ENOMEM;

	memset(s, 0, sizeof(*s));

	s->ldr = ldr;
	s->data_inp = NULL;
	s->data_outp = NULL;
	s->data_infunc = (drew_tls_data_in_func_t)recv;
	s->data_outfunc = (drew_tls_data_out_func_t)send;
	if ((res = make_prng(s->ldr, NULL, s->prng))) {
		free(s);
		return res;
	}
	// TLS 1.0, since that's all we support right now.
	s->protover.major = 3;
	s->protover.minor = 1;

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
		return -DREW_ERR_INVALID;
	sess->client = client;
	return 0;
}

int drew_tls_session_set_priority(drew_tls_session_t sess,
		drew_tls_priority_t prio)
{
	LOCK(sess);
	sess->prio = prio;
	UNLOCK(sess);

	return 0;
}

int drew_tls_session_set_transport(drew_tls_session_t sess,
		drew_tls_data_in_func_t inf, drew_tls_data_out_func_t outf,
		drew_tls_data_ctxt_t inp, drew_tls_data_ctxt_t outp)
{
	LOCK(sess);
	sess->data_inp = inp;
	sess->data_outp = outp;
	sess->data_infunc = inf;
	sess->data_outfunc = outf;
	UNLOCK(sess);
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

#define HANDSHAKE_OVERHEAD 4

// Note that this assumes the use of CBC.  It will have to be adjusted for GCM.
static int encrypt_block(drew_tls_session_t sess, Record &rec,
		const uint8_t *inbuf, uint16_t inlen)
{
	drew_mac_t macimpl, *mac = &macimpl;
	drew_mode_t *mode = sess->outmode;

	// We always pad to a multiple of 256 to foil traffic analysis.  Also, this
	// guarantees that our data is a multiple of 16, so we can use the more
	// efficient encryption routines.
	uint16_t datalen = (inlen + sess->hash_size + 1);
	uint16_t totallen = (datalen + 0xff) & ~0xff;
	uint8_t padval = totallen - datalen;
	SerializedBuffer content(totallen);
	SerializedBuffer encbuf(totallen);

	content.Put(inbuf, inlen);

	SerializedBuffer macdata(totallen);
	macdata.Put(sess->outseqnum);
	macdata.Put(rec.type);
	rec.version.WriteToBuffer(macdata);
	macdata.Put(inlen);
	macdata.Put(inbuf, inlen);

	sess->outmac->functbl->clone(mac, sess->outmac, 0);
	mac->functbl->reset(mac);
	mac->functbl->update(mac, macdata.GetPointer(0), macdata.GetLength());
	mac->functbl->final(mac, content.GetPointer(inlen), 0);
	mac->functbl->fini(mac, 0);

	// Pad the data.
	memset(content.GetPointer(datalen-1), padval, padval+1);

	mode->functbl->encryptfast(mode, encbuf.GetPointer(0),
			content.GetPointer(0), totallen);

	rec.length = totallen;
	rec.data = encbuf;
	sess->outseqnum++;

	return 0;
}

static int encrypt_stream(drew_tls_session_t sess, Record &rec,
		const uint8_t *inbuf, uint16_t inlen)
{
	return -DREW_ERR_NOT_IMPL;
}

// Note that this assumes the use of CBC.  It will have to be adjusted for GCM.
static int decrypt_block(drew_tls_session_t sess, Record &rec,
		SerializedBuffer &sbuf)
{
	int res = 0;
	drew_mac_t macimpl, *mac = &macimpl;
	drew_mode_t *mode = sess->inmode;
	uint8_t *inbuf = rec.data.GetPointer(0);
	uint16_t inlen = rec.length;
	SerializedBuffer decbuffer(rec.length);
	uint8_t *decbuf = decbuffer.GetPointer(0);
	uint16_t declen, datalen = 0;
	uint8_t beseqnum[sizeof(sess->inseqnum)];
	uint8_t padbyte;
	SerializedBuffer macbuf(128);

	// This is really easy.  Return early here because it's trivial for the
	// attacker not to mess this one up.
	if (rec.length % sess->block_size)
		return -DREW_TLS_ERR_DECRYPTION_FAILED;

	mode->functbl->decrypt(mode, decbuf, inbuf, inlen);

	padbyte = decbuf[inlen - 1];
	declen = inlen - (padbyte + 1);
	for (size_t i = declen; i < inlen; i++)
		if (decbuf[i] != padbyte)
			res = -DREW_TLS_ERR_DECRYPTION_FAILED;

	if (declen < (sess->hash_size + 1))
		res = -DREW_TLS_ERR_DECRYPTION_FAILED;
	else
		datalen = declen - sess->hash_size;

	BigEndian::Copy(beseqnum, &sess->inseqnum, sizeof(beseqnum));

	sess->outmac->functbl->clone(mac, sess->outmac, 0);
	mac->functbl->reset(mac);
	mac->functbl->update(mac, beseqnum, sizeof(beseqnum));
	mac->functbl->update(mac, sbuf.GetPointer(0), 5);
	mac->functbl->update(mac, decbuf, datalen);
	mac->functbl->final(mac, macbuf.GetPointer(0), 0);
	mac->functbl->fini(mac, 0);

	if (memcmp(macbuf.GetPointer(0), decbuf+datalen, sess->hash_size))
		res = -DREW_TLS_ERR_DECRYPTION_FAILED;

	rec.length = datalen;
	rec.data = decbuffer;
	sess->inseqnum++;

	return res;
}

static int decrypt_stream(drew_tls_session_t sess, Record &rec,
		SerializedBuffer &sbuf)
{
	return -DREW_ERR_NOT_IMPL;
}

// This function must be externally locked.
static int send_record(drew_tls_session_t sess, const uint8_t *buf,
		size_t len, uint8_t type)
{
	int res = 0;
	Record rec;

	// Records cannot be greater than 2^14.
	if (len > 0x3000) {
		const size_t chunksz = 0x1000;
		for (size_t off = 0; off < len; off += chunksz) {
			const size_t chunk = MIN(chunksz, len - off);
			RETFAIL(send_record(sess, buf+off, chunk, type));
		}
		return 0;
	}

	rec.type = type;
	rec.version.major = sess->protover.major;
	rec.version.minor = sess->protover.minor;
	rec.data.Reset();
	
	switch (sess->enc_type) {
		case cipher_type_null:
			rec.length = len;
			rec.data.Put(buf, len);
			break;
		case cipher_type_stream:
			RETFAIL(encrypt_stream(sess, rec, buf, len));
			break;
		case cipher_type_block:
			RETFAIL(encrypt_block(sess, rec, buf, len));
			break;
	}

	SerializedBuffer output;
	rec.WriteToBuffer(output);

	if ((res = sess->data_outfunc(sess->data_outp, output.GetPointer(0),
					output.GetLength())))
		return res;
	
	return res;
}

static int recv_bytes(drew_tls_session_t sess, SerializedBuffer &buf,
		size_t len, int flags)
{
	ssize_t nrecvd = 0;
	while (nrecvd < ssize_t(len)) {
		ssize_t nbytes;
		uint8_t buffer[512];
		nbytes = sess->data_infunc(sess->data_inp, buffer,
				std::min(len-nrecvd, sizeof(buffer)));
		if (nbytes < 0)
			return -errno;
		buf.Put(buffer, nbytes);
		nrecvd += nbytes;
	}
	return 0;
}

// This function must be externally locked.
static int recv_record(drew_tls_session_t sess, Record &rec)
{
	int res = 0;
	SerializedBuffer buf;

	if ((res = recv_bytes(sess, buf, 1 + 2 + 2, 0)))
		return res;

	// Fill in the early fields, including the length.
	buf.ResetPosition();
	if ((res = rec.ReadFromBuffer(buf)))
		return -DREW_ERR_BUG;

	if (rec.length > ((1 << 14) + 2048))
		return -DREW_TLS_ERR_RECORD_OVERFLOW;

	if (!(res = recv_bytes(sess, buf, rec.length, 0)))
		return res;

	buf.ResetPosition();
	// Now fill in all the fields.
	if ((res = rec.ReadFromBuffer(buf)))
		return -DREW_ERR_BUG;
	buf.ResetPosition();
	
	switch (sess->enc_type) {
		case cipher_type_stream:
			return decrypt_stream(sess, rec, buf);
		case cipher_type_block:
			return decrypt_block(sess, rec, buf);
		case cipher_type_null:
			break;
	}

	return res;
}

#if 0
// This function must be externally locked.
static int send_handshake(drew_tls_session_t sess, uint8_t *buf,
		size_t len, uint8_t type)
{
	int res = 0;
	uint8_t *data = buf;
	uint32_t length = len - HANDSHAKE_OVERHEAD;
	
	BWR32(data, length);
	buf[0] = type;

	res = send_record(sess, buf, len, 0x16);
	free(buf);
	return res;
}

static int handshake_send_client_hello(drew_tls_session_t sess)
{
	int res = 0;
	drew_tls_client_hello_t ch;
	drew_prng_t *prng;
	uint8_t *buf, *obuf;
	drew_tls_cipher_suite_t *suites;
	size_t nsuites;

	ch.random.gmt_unix_time = time(NULL);

	LOCK(sess);
	
	prng = sess->prng;
	URETFAIL(sess, prng->functbl->bytes(prng, ch.random.random_bytes,
			sizeof(ch.random.random_bytes)));
	URETFAIL(sess, drew_tls_priority_get_cipher_suites(sess->prio, &suites, 
				&nsuites));

	// 2 for null compression method, 2 for length of ciphersuites.
	size_t nbytes = HANDSHAKE_OVERHEAD + sizeof(ch.version) +
		sizeof(ch.random) + 2 + (nsuites * 2) + 2 +
		sizeof(sess->session_id.length) + sess->session_id.length;

	if (!(obuf = buf = (uint8_t *)malloc(nbytes)))
		URETFAIL(sess, -ENOMEM);

	uint8_t ncomps = 1, comp = 0;

	buf += HANDSHAKE_OVERHEAD;
	BWR_OBJ(buf, sess->protover);
	BWR32(buf, ch.random.gmt_unix_time);
	BWR_ARR(buf, ch.random.random_bytes);
	BWR_BUF8(buf, sess->session_id.sessionid, sess->session_id.length);
	BWR_BUF16(buf, suites, (uint16_t)(nsuites * 2));
	BWR8(buf, ncomps);
	BWR8(buf, comp);

	URETFAIL(sess, send_handshake(sess, obuf, nbytes, 0x01));

	UNLOCK(sess);
	return res;
}

static int handshake_send_server_hello(drew_tls_session_t sess)
{
	LOCK(sess);
	UNLOCK(sess);

	return -DREW_ERR_NOT_IMPL;
}
#endif

static int parse_handshake(drew_tls_session_t sess, const Record &rec,
		SerializedBuffer &buf, uint32_t *length, uint8_t *type)
{
	int res = 0;

	if (rec.length < 4)
		return -DREW_TLS_ERR_ILLEGAL_PARAMETER;

	// length is really only 24 bits in length, but we can't just load a
	// three-byte quantity.  The type octet precedes it, so we do some fancy
	// footwork to get both. 
	buf = rec.data;
	buf.ResetPosition();
	buf.Get(*type);
	buf.ResetPosition();
	buf.Get(*length);

	*length &= 0xffffff;

	if (rec.length != *length + 4)
		return -DREW_TLS_ERR_ILLEGAL_PARAMETER;

	return res;
}

static int handshake_server(drew_tls_session_t sess)
{
	return -DREW_ERR_NOT_IMPL;
}

#define CLIENT_HANDSHAKE_HELLO_REQUEST				0
#define CLIENT_HANDSHAKE_NEED_SERVER_HELLO			1
#define CLIENT_HANDSHAKE_NEED_SERVER_CERT			2
#define CLIENT_HANDSHAKE_CERT_REQ_OR_DONE			3
#define CLIENT_HANDSHAKE_SERVER_DONE				4
#define CLIENT_HANDSHAKE_DONE_NEED_CERT				5
#define CLIENT_HANDSHAKE_NEED_CLIENT_CERT			6
#define CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX			7
#define CLIENT_HANDSHAKE_NEED_SERVER_KEYEX			8
#define CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX_CERT		9
#define CLIENT_HANDSHAKE_NEED_CLIENT_VERIFY			10
#define CLIENT_HANDSHAKE_NEED_CLIENT_CIPHER_SPEC	11
#define CLIENT_HANDSHAKE_NEED_CLIENT_FINISHED		12
#define CLIENT_HANDSHAKE_CLIENT_FINISHED			13
#define CLIENT_HANDSHAKE_FINISHED					20

#define ALERT_WARNING	1
#define ALERT_FATAL		2

#define STATE_DESTROYED	1

#define TYPE_CHANGE_CIPHER_SPEC		20
#define TYPE_ALERT					21
#define TYPE_HANDSHAKE				22
#define TYPE_APPLICATION_DATA		23

static int destroy_session(drew_tls_session_t sess)
{
	sess->state = STATE_DESTROYED;
	return 0;
}

static int send_alert(drew_tls_session_t sess, int alert, int level)
{
	return -DREW_ERR_NOT_IMPL;
}

static int get_pkalgos(drew_tls_priority_t prio,
		const drew_tls_cipher_suite_t &cs, const char **pkalgo,
		const char **keyexalgo)
{
	drew_tls_cipher_suite_info_t csi;

	RETFAIL(drew_tls_priority_get_cipher_suite_info(prio, &csi, &cs));
	*pkalgo = csi.pkauth;
	*keyexalgo = csi.keyex;
	return 0;
}

int need_server_keyex(drew_tls_priority_t prio,
		const drew_tls_cipher_suite_t &cs)
{
	const char *keyex, *pkauth;

	RETFAIL(get_pkalgos(prio, cs, &pkauth, &keyex));
	/* This works well for us as long as we don't implement RSA_EXPORT or DH
	 * certificates.  If we do decide to do that, we'll need to use different
	 * logic.
	 */
	return !!strcmp(keyex, pkauth);
}

int client_parse_server_cert(drew_tls_session_t sess,
	const HandshakeMessage &msg)
{
	int res = 0;
	uint8_t dummy;
	uint32_t certlen = 0, certoff = 3;
	size_t ncerts = 0;
	drew_tls_encoded_cert_t *certs = NULL;
	SerializedBuffer buf(msg.data);

	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_SERVER_CERT)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	for (size_t i = 0; i < 3; i++) {
		certlen <<= 8;
		buf.Get(dummy);
		certlen |= dummy;
	}

	if (msg.length != certlen + 3)
		return -DREW_TLS_ERR_ILLEGAL_PARAMETER;

	for (ncerts = 0; certoff < certlen; ncerts++) {
		uint32_t thiscertlen = 0;
		for (size_t i = 0; i < 3; i++) {
			thiscertlen <<= 8;
			buf.Get(dummy);
			thiscertlen |= dummy;
		}
		if (thiscertlen + certoff > msg.length)
			return -DREW_TLS_ERR_ILLEGAL_PARAMETER;
		certs = (drew_tls_encoded_cert_t *)realloc(certs,
				(ncerts+1)*sizeof(*certs));
		if (!certs)
			return -DREW_TLS_ERR_INTERNAL_ERROR;
		certs[ncerts].len = thiscertlen;
		certs[ncerts].data = buf.GetPointer(certoff + thiscertlen);
	}

	res = sess->cert_callback(sess->cert_ctxt, sess, certs, ncerts);

	free(certs);

	if (!res && (res = need_server_keyex(sess->prio, sess->cs))) {
		if (res < 0)
			return res;
		sess->handshake_state = res ? CLIENT_HANDSHAKE_NEED_SERVER_KEYEX :
			CLIENT_HANDSHAKE_CERT_REQ_OR_DONE;
	}

	return res;
}

static int client_parse_dh_params(drew_tls_session_t sess,
		const HandshakeMessage &msg, size_t &off)
{
	return -DREW_ERR_NOT_IMPL;
}

static int client_verify_dsa_sig(drew_tls_session_t sess,
		const HandshakeMessage &msg, size_t &off)
{
	return -DREW_ERR_NOT_IMPL;
}

static int client_verify_rsa_sig(drew_tls_session_t sess,
		const HandshakeMessage &msg, size_t &off)
{
	return -DREW_ERR_NOT_IMPL;
}

static int client_parse_server_keyex(drew_tls_session_t sess,
	const HandshakeMessage &msg)
{
	int res = 0;
	size_t off = 0;
	const char *pkauth, *keyex;

	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_SERVER_KEYEX)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	RETFAIL(get_pkalgos(sess->prio, sess->cs, &pkauth, &keyex));

	if (!strcmp("Diffie-Hellman", keyex))
		RETFAIL(client_parse_dh_params(sess, msg, off));
	else
		return -DREW_ERR_NOT_IMPL;

	if (!strcmp("DSA", pkauth))
		RETFAIL(client_verify_dsa_sig(sess, msg, off));
	else if (!strcmp("RSA", pkauth))
		RETFAIL(client_verify_rsa_sig(sess, msg, off));

	sess->handshake_state = CLIENT_HANDSHAKE_CERT_REQ_OR_DONE;

	return res;
}

int client_parse_server_certreq(drew_tls_session_t sess,
	const HandshakeMessage &msg)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_CERT_REQ_OR_DONE)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	sess->handshake_state = CLIENT_HANDSHAKE_DONE_NEED_CERT;

	return -DREW_ERR_NOT_IMPL;
}

int client_parse_server_hello_done(drew_tls_session_t sess,
	const HandshakeMessage &msg)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_CERT_REQ_OR_DONE &&
			sess->handshake_state != CLIENT_HANDSHAKE_DONE_NEED_CERT)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	if (sess->handshake_state == CLIENT_HANDSHAKE_DONE_NEED_CERT)
		sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_CERT;
	else
		sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX;

	return -DREW_ERR_NOT_IMPL;
}

int client_parse_server_finished(drew_tls_session_t sess,
	const HandshakeMessage &msg)
{
	return -DREW_ERR_NOT_IMPL;
}

int client_send_client_hello(drew_tls_session_t sess)
{
	return -DREW_ERR_NOT_IMPL;
}

int client_send_client_cert(drew_tls_session_t sess)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_CERT)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX_CERT;

	return -DREW_ERR_NOT_IMPL;
}

int client_send_client_keyex(drew_tls_session_t sess)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX &&
			sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX_CERT)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	if (sess->handshake_state == CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX_CERT)
		sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_VERIFY;
	else
		sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_CIPHER_SPEC;

	return -DREW_ERR_NOT_IMPL;
}

int client_send_client_verify(drew_tls_session_t sess)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_VERIFY)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_CIPHER_SPEC;

	return -DREW_ERR_NOT_IMPL;
}

int client_send_client_cipher_spec(drew_tls_session_t sess)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_CIPHER_SPEC)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_FINISHED;

	return -DREW_ERR_NOT_IMPL;
}

int client_send_client_finished(drew_tls_session_t sess)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_FINISHED)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	sess->handshake_state = CLIENT_HANDSHAKE_CLIENT_FINISHED;

	return -DREW_ERR_NOT_IMPL;
}

int client_send_client_data(drew_tls_session_t sess)
{
	while (sess->handshake_state != CLIENT_HANDSHAKE_CLIENT_FINISHED) {
		switch (sess->handshake_state) {
			case CLIENT_HANDSHAKE_NEED_CLIENT_CERT:
				RETFAIL(client_send_client_cert(sess));
				break;
			case CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX:
				RETFAIL(client_send_client_keyex(sess));
				break;
			case CLIENT_HANDSHAKE_NEED_CLIENT_VERIFY:
				RETFAIL(client_send_client_verify(sess));
				break;
			case CLIENT_HANDSHAKE_NEED_CLIENT_CIPHER_SPEC:
				RETFAIL(client_send_client_cipher_spec(sess));
				break;
			case CLIENT_HANDSHAKE_NEED_CLIENT_FINISHED:
				RETFAIL(client_send_client_finished(sess));
				break;
		}
	}

	return 0;
}

static int validate_cipher_suite(drew_tls_priority_t prio,
		drew_tls_cipher_suite_t &cs)
{
	drew_tls_cipher_suite_t *buf;
	size_t nsuites = 0;

	drew_tls_priority_get_cipher_suites(prio, &buf, &nsuites);
	for (size_t i = 0; i < nsuites; i++)
		if (!memcmp(buf[i].val, cs.val, sizeof(cs.val))) {
			free(buf);
			return 0;
		}

	free(buf);
	return -DREW_TLS_ERR_HANDSHAKE_FAILURE;
}

static int client_parse_server_hello(drew_tls_session_t sess,
		const HandshakeMessage &msg)
{
	int res = 0;
	ProtocolVersion pv;
	size_t minlength = 2 + 32 + 2 + 1 + 1;
	uint8_t random[32];
	drew_tls_cipher_suite_t cs;
	SerializedBuffer buf(msg.data);

	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_SERVER_HELLO)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	// The session ID can be up to 32 bytes.
	if (msg.length < minlength || msg.length > (minlength + 32))
		return -DREW_TLS_ERR_ILLEGAL_PARAMETER;

	pv.ReadFromBuffer(buf);

	if (pv.major != 3)
		return -DREW_TLS_ERR_HANDSHAKE_FAILURE;
	if (pv.minor != 1)
		return -DREW_TLS_ERR_HANDSHAKE_FAILURE;
	sess->protover.major = pv.major;
	sess->protover.minor = pv.minor;

	buf.Get(random, sizeof(random));
	buf.Get(sess->session_id.length);

	if (msg.length != minlength + sess->session_id.length)
		return -DREW_TLS_ERR_ILLEGAL_PARAMETER;

	buf.Get(sess->session_id.sessionid, sess->session_id.length);
	buf.Get(cs.val, sizeof(cs.val));

	uint8_t compress;
	buf.Get(compress);

	if (compress != 0)
		return -DREW_TLS_ERR_HANDSHAKE_FAILURE;

	if ((res = validate_cipher_suite(sess->prio, cs)))
		return res;

	memcpy(&sess->cs, &cs, sizeof(cs));

	sess->handshake_state = CLIENT_HANDSHAKE_NEED_SERVER_CERT;

	return 0;
}

static int client_handle_handshake(drew_tls_session_t sess, const Record &rec)
{
	int res = 0;
	HandshakeMessage hm;

	RETFAIL(parse_handshake(sess, rec, hm.data, &hm.length, &hm.type));

	switch (hm.type) {
		case 0:
			return 0;
		case 2:
			return client_parse_server_hello(sess, hm);
		case 11:
			return client_parse_server_cert(sess, hm);
		case 12:
			return client_parse_server_keyex(sess, hm);
		case 13:
			return client_parse_server_certreq(sess, hm);
		case 14:
			res = client_parse_server_hello_done(sess, hm);
			if (res < 0)
				return res;
			return client_send_client_data(sess);
		case 20:
			return client_parse_server_finished(sess, hm);
		case 15:
		case 16:
		case 1:
			// Only messages we should be sending, not the server.
		default:
			return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;
	}

}

// Return 0 to continue the connection, 1 to close it gracefully, and a negative
// error value to abort it abnormally.
static int handle_alert(drew_tls_session_t sess, const Record &rec)
{
	AlertMessage msg(rec);
	int errval = DREW_TLS_ERR_BASE + msg.description;
	if (errval == DREW_TLS_ERR_CLOSE_NOTIFY) {
		send_alert(sess, DREW_TLS_ERR_CLOSE_NOTIFY, ALERT_WARNING);
		destroy_session(sess);
		return 1;
	}
	if (msg.level == ALERT_FATAL) {
		destroy_session(sess);
		return -errval;
	}
	if (msg.level != ALERT_WARNING) {
		// Whatever the other side has been smoking, let's not inhale.
		send_alert(sess, DREW_TLS_ERR_UNEXPECTED_MESSAGE, ALERT_FATAL);
		destroy_session(sess);
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;
	}
	// FIXME: split this out into a function that we can get flags from.
	switch (errval) {
		case DREW_TLS_ERR_UNEXPECTED_MESSAGE:
		case DREW_TLS_ERR_BAD_RECORD_MAC:
		case DREW_TLS_ERR_DECRYPTION_FAILED:
		case DREW_TLS_ERR_RECORD_OVERFLOW:
		case DREW_TLS_ERR_DECOMPRESSION_FAILURE:
		case DREW_TLS_ERR_HANDSHAKE_FAILURE:
		case DREW_TLS_ERR_ILLEGAL_PARAMETER:
		case DREW_TLS_ERR_UNKNOWN_CA:
		case DREW_TLS_ERR_ACCESS_DENIED:
		case DREW_TLS_ERR_DECODE_ERROR:
		case DREW_TLS_ERR_EXPORT_RESTRICTION:
		case DREW_TLS_ERR_PROTOCOL_VERSION:
		case DREW_TLS_ERR_INSUFFICIENT_SECURITY:
		case DREW_TLS_ERR_INTERNAL_ERROR:
			// Oops.  Some idiot sent a fatal error as a warning.  Abort the
			// connection.
			send_alert(sess, DREW_TLS_ERR_UNEXPECTED_MESSAGE, ALERT_FATAL);
			destroy_session(sess);
			return -errval;
	}
	return 0;
}

static int handshake_client(drew_tls_session_t sess)
{
	int res = 0;

	LOCK(sess);
	
	sess->handshake_state = CLIENT_HANDSHAKE_HELLO_REQUEST;

	URETFAIL(sess, client_send_client_hello(sess));

	while (sess->handshake_state != CLIENT_HANDSHAKE_FINISHED) {
		Record rec;

		if (sess->state == STATE_DESTROYED)
			return -DREW_ERR_BUG;

		URETFAIL(sess, recv_record(sess, rec));
		res = -DREW_TLS_ERR_UNEXPECTED_MESSAGE;
		switch (rec.type) {
			case TYPE_CHANGE_CIPHER_SPEC:
				break;
			case TYPE_ALERT:
				URETFAIL(sess, handle_alert(sess, rec));
				break;
			case TYPE_HANDSHAKE:
				res = client_handle_handshake(sess, rec);
				if (!res)
					break;
				// Fallthru to send alert and return.
			case TYPE_APPLICATION_DATA:
				// Not allowed now.
			default:
				// Something else?
				send_alert(sess, -res, ALERT_FATAL);
				destroy_session(sess);
				URETFAIL(sess, res);
				break;
		}
	}

	UNLOCK(sess);

	return -DREW_ERR_NOT_IMPL;
}

int drew_tls_session_handshake(drew_tls_session_t sess)
{
	LOCK(sess);
	//URETFAIL(sess, make_hash(sess->ldr, "MD5", &sess->handshake.md5));
	//URETFAIL(sess, make_hash(sess->ldr, "SHA-1", &sess->handshake.sha1));
	UNLOCK(sess);
	return sess->client ? handshake_client(sess) : handshake_server(sess);
}
