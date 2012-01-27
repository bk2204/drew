/*-
 * Copyright © 2000–2011 The Legion Of The Bouncy Castle
 * (http://www.bouncycastle.org)
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
/* Part of the (re-)design of this code is based on the Bouncy Castle TLS
 * implementation.
 */
#include "internal.h"

#include <utility>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include <drew/drew.h>
#include <drew/bignum.h>
#include <drew/kdf.h>
#include <drew/pkenc.h>
#include <drew/pksig.h>
#include <drew/mem.h>
#include <drew/plugin.h>

#include <drew-tls/drew-tls.h>
#include <drew-tls/priority.h>
#include <drew-tls/session.h>

#include "util.hh"
#include "structs.h"
#include "structures.hh"

#ifdef DREW_DEBUG
#define DEBUG printf
#else
#define DEBUG (void)
#endif

#define COMPRESSION_TYPE_NONE 0

#define CONTENT_TYPE_CHANGE_CIPHER_SPEC 20
#define CONTENT_TYPE_ALERT 21
#define CONTENT_TYPE_HANDSHAKE 22

#define HANDSHAKE_TYPE_CLIENT_HELLO 1
#define HANDSHAKE_TYPE_CLIENT_KEYEX 16
#define HANDSHAKE_TYPE_CLIENT_FINISHED 20

#define HASH_MD5 0
#define HASH_SHA1 1

struct generic {
	void *ctx;
	const void *functbl;
	void *priv;
};

struct drew_tls_session_queues_s {
	ByteQueue cs;
	ByteQueue alert;
	ByteQueue handshake;
	ByteQueue appdata;
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
		if ((res = drew_loader_get_functbl(ldr, id, &functbl)) < 0)
			continue;
		res = 0;
		ctx->functbl = functbl;
		break;
	}
	// FIXME: remove -ENOENT once libdrew stops using it.
	if (res == -ENOENT)
		return -DREW_ERR_NONEXISTENT;
	return res;
}

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

static int make_prng(const drew_loader_t *ldr, const char *name,
		drew_prng_t *prng)
{
	int res = 0;

	if (!name)
		name = "DevURandom";

	if ((res = make_primitive(ldr, name, prng, DREW_TYPE_PRNG)))
		return res;
	res = prng->functbl->init(prng, 0, ldr, NULL);
	return res;
}

static int make_bignum(const drew_loader_t *ldr, drew_bignum_t *bignum,
		const uint8_t *data, size_t len)
{
	int res = 0;

	if ((res = make_primitive(ldr, "Bignum", bignum, DREW_TYPE_BIGNUM)))
		return res;
	res = bignum->functbl->init(bignum, 0, ldr, NULL);
	if (!res && data)
		res = bignum->functbl->setbytes(bignum, data, len);
	return res;
}

static int make_pksig(const drew_loader_t *ldr, const char *name,
		drew_pksig_t *pksig)
{
	int res = 0;

	if ((res = make_primitive(ldr, name, pksig, DREW_TYPE_PKSIG)))
		return res;
	res = pksig->functbl->init(pksig, 0, ldr, NULL);
	return res;
}

static int make_pkenc(const drew_loader_t *ldr, const char *name,
		drew_pkenc_t *pkenc)
{
	int res = 0;

	if ((res = make_primitive(ldr, name, pkenc, DREW_TYPE_PKENC)))
		return res;
	res = pkenc->functbl->init(pkenc, 0, ldr, NULL);
	return res;
}

static int make_block(const drew_loader_t *ldr, const char *name,
		drew_block_t *block)
{
	int res = 0;

	if ((res = make_primitive(ldr, name, block, DREW_TYPE_BLOCK)))
		return res;
	res = block->functbl->init(block, 0, ldr, NULL);
	return res;
}

static int make_stream(const drew_loader_t *ldr, const char *name,
		drew_stream_t *stream)
{
	int res = 0;

	if ((res = make_primitive(ldr, name, stream, DREW_TYPE_STREAM)))
		return res;
	res = stream->functbl->init(stream, 0, ldr, NULL);
	return res;
}

// Make a TLS PRF using HMAC-name.
static int make_prf(const drew_loader_t *ldr, const char *name,
		drew_kdf_t *prf)
{
	int res = 0;
	drew_hash_t hash;
	drew_kdf_t hmac;
	struct drew_param_t p, p2;

	p.next = NULL;
	p.name = "digest";
	p.param.value = &hash;

	p2.next = NULL;
	p2.name = "prf";
	p2.param.value = &hmac;

	RETFAIL(make_hash(ldr, name, &hash));

	RETFAIL(make_primitive(ldr, name, &hmac, DREW_TYPE_KDF));
	RETFAIL(hmac.functbl->init(&hmac, 0, ldr, &p));

	if ((res = make_primitive(ldr, name, prf, DREW_TYPE_KDF)))
		return res;
	res = prf->functbl->init(prf, 0, ldr, &p2);
	return res;
}

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
	s->prng = new drew_prng_t;
	s->enc_type = cipher_type_null;
	if ((res = make_prng(s->ldr, NULL, s->prng))) {
		free(s);
		return res;
	}
	s->queues = new drew_tls_session_queues_s;
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
	delete s->queues;
	delete s->prng;
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

int drew_tls_session_set_cert_callback(drew_tls_session_t sess,
		drew_tls_cert_callback_t cb)
{
	LOCK(sess);
	sess->cert_callback = cb;
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
	drew_tls_secparams_t *conn = sess->client ? &sess->clientp : &sess->serverp;
	drew_mode_t *mode = conn->mode;

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
	macdata.Put(conn->seqnum);
	macdata.Put(rec.type);
	rec.version.WriteToBuffer(macdata);
	macdata.Put(inlen);
	macdata.Put(inbuf, inlen);

	conn->mac->functbl->clone(mac, conn->mac, 0);
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
	conn->seqnum++;

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
	drew_tls_secparams_t *conn = sess->client ? &sess->serverp : &sess->clientp;
	drew_mac_t macimpl, *mac = &macimpl;
	drew_mode_t *mode = conn->mode;
	uint8_t *inbuf = rec.data.GetPointer(0);
	uint16_t inlen = rec.length;
	SerializedBuffer decbuffer(rec.length);
	uint8_t *decbuf = decbuffer.GetPointer(0);
	uint16_t declen, datalen = 0;
	uint8_t beseqnum[sizeof(conn->seqnum)];
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

	BigEndian::Copy(beseqnum, &conn->seqnum, sizeof(beseqnum));

	conn->mac->functbl->clone(mac, conn->mac, 0);
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
	conn->seqnum++;

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
					output.GetLength())) < 0)
		return res;
	
	return 0;
}

// This function must be externally locked.
static int send_record(drew_tls_session_t sess, SerializedBuffer &data,
		uint8_t type)
{
	return send_record(sess, data.GetPointer(0), data.GetLength(), type);
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

// This function must be externally locked.
static int send_handshake(drew_tls_session_t sess, SerializedBuffer &buf,
		uint8_t type)
{
	int res = 0;
	SerializedBuffer b2;
	drew_tls_handshake_t *hs = &sess->handshake;

	buf.ResetPosition();

	b2.Put(type); // HandshakeType
	b2.Put(uint8_t(buf.GetLength() >> 16));
	b2.Put(uint8_t(buf.GetLength() >> 8));
	b2.Put(uint8_t(buf.GetLength()));
	b2.Put(buf);

	hs->msgs[HASH_MD5].functbl->update(hs->msgs+HASH_MD5, b2.GetPointer(0),
			b2.GetLength());
	hs->msgs[HASH_SHA1].functbl->update(hs->msgs+HASH_SHA1, b2.GetPointer(0),
			b2.GetLength());

	res = send_record(sess, b2, CONTENT_TYPE_HANDSHAKE);
	return res;
}

static int send_change_cipher_spec(drew_tls_session_t sess)
{
	int res = 0;
	SerializedBuffer buf;

	buf.Put((uint8_t)1);

	res = send_record(sess, buf, CONTENT_TYPE_CHANGE_CIPHER_SPEC);
	return res;
}

#if 0
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
#define CLIENT_HANDSHAKE_NEED_SERVER_CIPHER_SPEC	12
#define CLIENT_HANDSHAKE_NEED_CLIENT_FINISHED		13
#define CLIENT_HANDSHAKE_CLIENT_FINISHED			14
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
	SerializedBuffer buf;

	buf.Put((uint8_t)alert);
	buf.Put((uint8_t)level);

	// Don't care if this fails.
	send_record(sess, buf, CONTENT_TYPE_ALERT);
	return 0;
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

static int need_server_keyex(drew_tls_priority_t prio,
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

static int client_parse_server_cert(drew_tls_session_t sess,
	const HandshakeMessage &msg)
{
	int res = 0;
	uint8_t dummy;
	uint32_t certlen = 0, certoff = 3;
	size_t ncerts = 0;
	drew_tls_encoded_cert_t *certs = NULL;
	drew_tls_cert_t *dcerts = NULL;
	SerializedBuffer buf(msg.data);
	drew_util_asn1_t asn;

	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_SERVER_CERT)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	for (size_t i = 0; i < 3; i++) {
		certlen <<= 8;
		buf.Get(dummy);
		certlen |= dummy;
	}

	if (msg.length != certlen + 3)
		return -DREW_TLS_ERR_ILLEGAL_PARAMETER;

	RETFAIL(drew_util_asn1_init(&asn));

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
		dcerts = (drew_tls_cert_t *)realloc(dcerts,
				(ncerts+1)*sizeof(*dcerts));
		if (!certs || !dcerts)
			return -DREW_TLS_ERR_INTERNAL_ERROR;
		certs[ncerts].len = thiscertlen;
		certs[ncerts].data = buf.GetPointer(certoff);
		drew_util_x509_cert_t *dcert =
			(drew_util_x509_cert_t *)drew_mem_malloc(sizeof(*dcert));
		if (!dcert)
			return -ENOMEM;

		RETFAIL(drew_util_x509_parse_certificate(asn, certs[ncerts].data,
					certs[ncerts].len, dcert, sess->ldr));
		dcerts[ncerts].x509 = dcert;
		certoff += thiscertlen;
	}

	res = sess->cert_callback(sess->cert_ctxt, sess, certs, dcerts, ncerts);

	RETFAIL(drew_util_asn1_fini(&asn));

	// FIXME: use a dealloc function.
	// We don't dealloc the first certificate here because we keep it to
	// validate the key exchange later.
	sess->serverp.cert = (drew_util_x509_cert_t *)dcerts[0].x509;
	for (size_t i = 1; i < ncerts; i++)
		free((void *)dcerts[i].x509);
	free(dcerts);
	free(certs);

	if (!res && (res = need_server_keyex(sess->prio, sess->cs))) {
		if (res < 0)
			return res;
		sess->handshake_state = res ? CLIENT_HANDSHAKE_NEED_SERVER_KEYEX :
			CLIENT_HANDSHAKE_CERT_REQ_OR_DONE;
	}

	return res;
}

// Assuming off is 0, which it is in a server keyex message.
static int client_parse_dh_params(drew_tls_session_t sess,
		const HandshakeMessage &msg, size_t &off)
{
	int res;
	SerializedBuffer b(msg.data);
	uint16_t plen, glen, yslen;
	uint8_t *p = 0, *g = 0, *ys = 0;

	if (b.GetLength() < 2)
		return -DREW_TLS_ERR_HANDSHAKE_FAILURE;

	b.Get(plen);
	if (b.BytesRemaining() < plen)
		return -DREW_TLS_ERR_HANDSHAKE_FAILURE;

	res = -ENOMEM;
	if (!(p = (uint8_t *)drew_mem_malloc(plen)))
		goto out;

	b.Get(p, plen);
	off += plen + sizeof(uint16_t);

	b.Get(glen);

	res = -DREW_TLS_ERR_HANDSHAKE_FAILURE;
	if (b.BytesRemaining() < glen)
		goto out;

	res = -ENOMEM;
	if (!(g = (uint8_t *)drew_mem_malloc(glen)))
		goto out;

	b.Get(g, glen);
	off += glen + sizeof(uint16_t);

	b.Get(yslen);

	res = -DREW_TLS_ERR_HANDSHAKE_FAILURE;
	if (b.BytesRemaining() < yslen)
		goto out;

	res = -ENOMEM;
	if (!(ys = (uint8_t *)drew_mem_malloc(yslen)))
		goto out;

	b.Get(ys, yslen);
	off += yslen + sizeof(uint16_t);

	if ((res = make_bignum(sess->ldr, &sess->keyex.p, p, plen)))
		goto out;
	if ((res = make_bignum(sess->ldr, &sess->keyex.g, g, glen)))
		goto out;
	if ((res = make_bignum(sess->ldr, &sess->keyex.ys, ys, yslen)))
		goto out;

	res = 0;

out:
	drew_mem_free(p);
	drew_mem_free(g);
	drew_mem_free(ys);
	return res;
}

static int client_verify_dsa_sig(drew_tls_session_t sess,
		const HandshakeMessage &msg, size_t &off, drew_hash_t *hashes)
{
	uint8_t buf[20];

	hashes[HASH_SHA1].functbl->final(&hashes[HASH_SHA1], buf, 20, 0);

	return -DREW_ERR_NOT_IMPL;
}

static int client_verify_rsa_sig(drew_tls_session_t sess,
		const HandshakeMessage &msg, size_t &off, drew_hash_t *hashes)
{
	uint8_t buf[16 + 20], *data;
	drew_bignum_t c, p;
	drew_pksig_t rsa;
	int size, res = 0, offset = 0;

	if (!sess->serverp.cert)
		return -DREW_TLS_ERR_INTERNAL_ERROR;

	drew_util_x509_pubkey_t *pubkey = &sess->serverp.cert->pubkey;

	RETFAIL(make_bignum(sess->ldr, &c, msg.data.GetPointer(off),
				msg.data.GetLength()-off));
	RETFAIL(make_bignum(sess->ldr, &p, NULL, 0));
	RETFAIL(make_pksig(sess->ldr, "RSA", &rsa));

	rsa.functbl->setval(&rsa, "n", pubkey->mpis[0].data, pubkey->mpis[0].len);
	rsa.functbl->setval(&rsa, "e", pubkey->mpis[1].data, pubkey->mpis[1].len);
	rsa.functbl->verify(&rsa, &p, &c);
	rsa.functbl->fini(&rsa, 0);

	hashes[HASH_MD5].functbl->final(&hashes[HASH_MD5], buf, 16, 0);
	hashes[HASH_SHA1].functbl->final(&hashes[HASH_SHA1], buf+16, 20, 0);

	c.functbl->fini(&c, 0);

	if ((size = p.functbl->nbytes(&p)) < 0)
		return size;

	if (size + 2 < pubkey->mpis[0].len)
		return -DREW_ERR_INVALID;

	// Make sure we have enough data to have valid padding.
	if (size_t(size) < sizeof(buf) + 1 + 1 + 1)
		return -DREW_ERR_INVALID;

	if (!(data = (uint8_t *)drew_mem_malloc(size)))
		return -ENOMEM;

	p.functbl->bytes(&p, data, size);
	p.functbl->fini(&p, 0);

	/* Check the padding for block type 1.  The final 36 bytes are the hash, the
	 * byte preceding that is 0, preceding that is a series of bytes with value
	 * 0xff, and before that the value 1 (the block type).  Also, don't return
	 * immediately if the data is corrupt to make timing attacks harder.
	 */
	if (memcmp(data+size-sizeof(buf), buf, sizeof(buf)))
		res = -DREW_ERR_INVALID;
	if (data[size-sizeof(buf)-1])
		res = -DREW_ERR_INVALID;
	if (data[0] == 0 && data[1] == 1)
		offset = 2;
	else if (data[0] == 1)
		offset = 1;
	else
		res = -DREW_ERR_INVALID;
	for (size_t i = offset; i < size-sizeof(buf)-1; i++)
		if (data[i] != 0xff)
			res = -DREW_ERR_INVALID;

	drew_mem_free(data);

	return res;
}

static int client_parse_server_keyex(drew_tls_session_t sess,
	const HandshakeMessage &msg)
{
	int res = 0;
	size_t off = 0;
	const char *pkauth, *keyex;
	drew_hash_t hashes[2];

	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_SERVER_KEYEX)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	RETFAIL(get_pkalgos(sess->prio, sess->cs, &pkauth, &keyex));

	make_hash(sess->ldr, "MD5", &hashes[HASH_MD5]);
	make_hash(sess->ldr, "SHA-1", &hashes[HASH_SHA1]);

	if (!strcmp("Diffie-Hellman", keyex))
		RETFAIL(client_parse_dh_params(sess, msg, off));
	else if (!strcmp("RSA", keyex))
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;
	else
		return -DREW_ERR_NOT_IMPL;

	for (size_t i = 0; i < DIM(hashes); i++) {
		hashes[i].functbl->update(hashes+i, sess->clientp.random,
				sizeof(sess->clientp.random));
		hashes[i].functbl->update(hashes+i, sess->serverp.random,
				sizeof(sess->serverp.random));
		hashes[i].functbl->update(hashes+i, msg.data.GetPointer(0), off);
	}

	if (!strcmp("DSA", pkauth))
		RETFAIL(client_verify_dsa_sig(sess, msg, off, hashes));
	else if (!strcmp("RSA", pkauth))
		RETFAIL(client_verify_rsa_sig(sess, msg, off, hashes));
	else
		return -DREW_ERR_NOT_IMPL;

	sess->handshake_state = CLIENT_HANDSHAKE_CERT_REQ_OR_DONE;

	return res;
}

static int client_parse_server_certreq(drew_tls_session_t sess,
	const HandshakeMessage &msg)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_CERT_REQ_OR_DONE)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	sess->handshake_state = CLIENT_HANDSHAKE_DONE_NEED_CERT;

	return -DREW_ERR_NOT_IMPL;
}

static int client_parse_server_hello_done(drew_tls_session_t sess,
	const HandshakeMessage &msg)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_CERT_REQ_OR_DONE &&
			sess->handshake_state != CLIENT_HANDSHAKE_DONE_NEED_CERT)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	if (sess->handshake_state == CLIENT_HANDSHAKE_DONE_NEED_CERT)
		sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_CERT;
	else
		sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX;

	return 0;
}

static int client_send_client_hello(drew_tls_session_t sess)
{
	drew_tls_cipher_suite_t *suites;
	size_t nsuites = 0;
	uint32_t t = time(NULL);
	SerializedBuffer buf;

	BigEndian::Copy(sess->clientp.random, &t, sizeof(t));
	sess->prng->functbl->bytes(sess->prng, sess->clientp.random+sizeof(t),
			sizeof(sess->clientp.random)-sizeof(t));

	RETFAIL(drew_tls_priority_get_cipher_suites(sess->prio, &suites,
				&nsuites));

	buf.Put(sess->protover.major);
	buf.Put(sess->protover.minor);
	buf.Put(sess->clientp.random, sizeof(sess->clientp.random));
	// We don't yet support resuming sessions, so don't bother sending a
	// session_id.
	buf.Put((uint8_t)0);
	buf.Put((const uint8_t *)suites, nsuites * 2);
	// We don't support any compression methods, either, so just use
	// uncompressed.
	buf.Put((uint8_t)1);
	buf.Put((uint8_t)COMPRESSION_TYPE_NONE);

	RETFAIL(send_handshake(sess, buf, HANDSHAKE_TYPE_CLIENT_HELLO));

	return 0;
}

int client_send_client_cert(drew_tls_session_t sess)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_CERT)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX_CERT;

	return -DREW_ERR_NOT_IMPL;
}

// This works for TLS 1.0 and 1.1, but will need to be adjusted for TLS 1.2,
// since it uses a simple SHA-256-only PRF.
static int do_tls_prf(drew_tls_session_t sess, uint8_t *out, size_t outlen,
		const char *label, const uint8_t *secret, size_t len, const uint8_t *in,
		size_t inlen)
{
	const uint8_t *s1, *s2;
	size_t slen, blen, llen = strlen(label);
	drew_kdf_t prf[2];
	uint8_t *buf;
	uint8_t *halves[2];

	blen = llen + inlen;
	buf = (uint8_t *)drew_mem_malloc(blen);
	halves[0] = (uint8_t *)drew_mem_malloc(outlen);
	halves[1] = (uint8_t *)drew_mem_malloc(outlen);

	RETFAIL(make_prf(sess->ldr, "MD5", prf+HASH_MD5));
	RETFAIL(make_prf(sess->ldr, "SHA-1", prf+HASH_SHA1));

	slen = (len + 1) / 2;
	s1 = secret;
	s2 = secret + len - slen;

	prf[HASH_MD5].functbl->setkey(&prf[HASH_MD5], s1, slen);
	prf[HASH_SHA1].functbl->setkey(&prf[HASH_SHA1], s2, slen);

	memcpy(buf, label, llen);
	memcpy(buf+llen, in, inlen);

	prf[HASH_MD5].functbl->generate(&prf[HASH_MD5], halves[0], outlen, buf,
			sizeof(buf));
	prf[HASH_SHA1].functbl->generate(&prf[HASH_SHA1], halves[1], outlen, buf,
			sizeof(buf));
	XorBuffers(out, halves[0], halves[1], outlen);

	prf[HASH_MD5].functbl->fini(&prf[HASH_MD5], 0);
	prf[HASH_SHA1].functbl->fini(&prf[HASH_SHA1], 0);

	drew_mem_free(buf);
	drew_mem_free(halves[0]);
	drew_mem_free(halves[1]);

	return 0;
}

// This operates on the client_random and server_random implicitly.
static int do_tls_prf(drew_tls_session_t sess, uint8_t *out, size_t outlen,
		const char *label, const uint8_t *secret, size_t len)
{
	uint8_t randoms[sizeof(sess->clientp.random) * 2];

	memcpy(randoms, sess->clientp.random, sizeof(sess->clientp.random));
	memcpy(randoms+(sizeof(randoms)/2), sess->serverp.random,
			sizeof(sess->serverp.random));

	return do_tls_prf(sess, out, outlen, label, secret, len, randoms,
			sizeof(randoms));
}

static int client_parse_server_finished(drew_tls_session_t sess,
	const HandshakeMessage &msg)
{
	uint8_t verify_data[12];

	if (msg.data.GetLength() != sizeof(verify_data))
		return -DREW_TLS_ERR_HANDSHAKE_FAILURE;

	RETFAIL(do_tls_prf(sess, verify_data, sizeof(verify_data),
				"server finished", sess->handshake.final,
				sizeof(sess->handshake.final)));

	return memcmp(verify_data, msg.data.GetPointer(0), sizeof(verify_data)) ?
		0 : -DREW_TLS_ERR_HANDSHAKE_FAILURE;
}

static int generate_master_secret(drew_tls_session_t sess, const uint8_t *pms,
		size_t len)
{
	RETFAIL(do_tls_prf(sess, sess->clientp.master_secret,
				sizeof(sess->clientp.master_secret), "master secret", pms,
				len));
	memcpy(sess->serverp.master_secret, sess->clientp.master_secret,
			sizeof(sess->serverp.master_secret));
	return 0;
}

static int client_generate_keyex_dh(drew_tls_session_t sess, uint8_t **p,
		size_t *len)
{
	SerializedBuffer buf;
	drew_bignum_t x, y, z;
	uint8_t *data;
	size_t nbytes;
	uint16_t plen;

	nbytes = sess->keyex.p.functbl->nbytes(&sess->keyex.p);
	if (!(data = (uint8_t *)drew_mem_malloc(nbytes)))
		return -ENOMEM;

	sess->prng->functbl->bytes(sess->prng, data, nbytes);

	drew_mem_free(data);

	RETFAIL(make_bignum(sess->ldr, &x, data, nbytes));
	RETFAIL(make_bignum(sess->ldr, &y, NULL, 0));
	RETFAIL(make_bignum(sess->ldr, &z, NULL, 0));

	// The public value.
	y.functbl->expmod(&y, &sess->keyex.g, &x, &sess->keyex.p);
	// The pre-master secret.
	z.functbl->expmod(&z, &sess->keyex.ys, &x, &sess->keyex.p);

	// Save the pre-master secret.
	*len = z.functbl->nbytes(&z);
	*p = (uint8_t *)drew_mem_malloc(*len);
	z.functbl->bytes(&z, *p, *len);

	plen = y.functbl->nbytes(&y);
	data = (uint8_t *)drew_mem_malloc(plen);
	y.functbl->bytes(&y, data, plen);
	buf.Put(plen);
	buf.Put(data, plen);

	return send_handshake(sess, buf, HANDSHAKE_TYPE_CLIENT_KEYEX);
}

static int client_generate_keyex_rsa(drew_tls_session_t sess, uint8_t **p,
		size_t *len)
{
	uint8_t *data;
	size_t dlen;
	drew_bignum_t pt, ct;
	drew_pkenc_t rsa;
	drew_util_x509_pubkey_t *pubkey = &sess->serverp.cert->pubkey;

	if (!sess->serverp.cert)
		return -DREW_TLS_ERR_INTERNAL_ERROR;

	*len = 48;
	*p = (uint8_t *)drew_mem_malloc(*len);

	(*p)[0] = sess->protover.major;
	(*p)[1] = sess->protover.minor;

	dlen = pubkey->mpis[0].len;
	if (dlen < *len + 4)
		return -DREW_TLS_ERR_BAD_CERTIFICATE;
	data = (uint8_t *)drew_mem_malloc(dlen);

	sess->prng->functbl->bytes(sess->prng, (*p)+2, *len-2);

	RETFAIL(make_pkenc(sess->ldr, "RSA", &rsa));
	rsa.functbl->setval(&rsa, "n", pubkey->mpis[0].data, pubkey->mpis[0].len);
	rsa.functbl->setval(&rsa, "e", pubkey->mpis[1].data, pubkey->mpis[1].len);

	data[0] = 0;
	data[1] = 2;
	memcpy(data+dlen-*len, *p, *len);
	data[dlen-*len-1] = 0;

	// The padding bytes have to be nonzero.
	for (size_t i = 2; i < dlen-*len-1; i++) {
		do {
			sess->prng->functbl->bytes(sess->prng, data+i, 1);
		}
		while (!data[i]);
	}

	RETFAIL(make_bignum(sess->ldr, &pt, data, dlen));
	RETFAIL(make_bignum(sess->ldr, &ct, NULL, 0));

	rsa.functbl->encrypt(&rsa, &ct, &pt);
	rsa.functbl->fini(&rsa, 0);

	drew_mem_free(data);

	return 0;
}

// Right now this only implements ephemeral DH and RSA.
static int client_send_client_keyex(drew_tls_session_t sess)
{
	uint8_t *pms;
	const char *pkauth, *keyex;
	size_t len;

	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX &&
			sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX_CERT)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	RETFAIL(get_pkalgos(sess->prio, sess->cs, &pkauth, &keyex));

	if (!strcmp("Diffie-Hellman", keyex))
		RETFAIL(client_generate_keyex_dh(sess, &pms, &len));
	else if (!strcmp("RSA", keyex))
		RETFAIL(client_generate_keyex_rsa(sess, &pms, &len));
	else
		return -DREW_ERR_NOT_IMPL;

	generate_master_secret(sess, pms, len);
	drew_mem_free(pms);

	if (sess->handshake_state == CLIENT_HANDSHAKE_NEED_CLIENT_KEYEX_CERT)
		sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_VERIFY;
	else
		sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_CIPHER_SPEC;

	return 0;
}

static int client_send_client_verify(drew_tls_session_t sess)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_VERIFY)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_CIPHER_SPEC;

	return -DREW_ERR_NOT_IMPL;
}

static int client_send_client_cipher_spec(drew_tls_session_t sess)
{
	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_CIPHER_SPEC)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	RETFAIL(send_change_cipher_spec(sess));

	sess->handshake_state = CLIENT_HANDSHAKE_NEED_SERVER_CIPHER_SPEC;

	return 0;
}

static int client_send_client_finished(drew_tls_session_t sess)
{
	uint8_t verify_data[12];
	drew_tls_handshake_t *hs = &sess->handshake;
	SerializedBuffer buf;

	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_CLIENT_FINISHED)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	hs->msgs[HASH_MD5].functbl->final(hs->msgs+HASH_MD5, hs->final, 16, 0);
	hs->msgs[HASH_SHA1].functbl->final(hs->msgs+HASH_SHA1, hs->final+16, 20, 0);

	RETFAIL(do_tls_prf(sess, verify_data, sizeof(verify_data),
				"client finished", sess->handshake.final,
				sizeof(sess->handshake.final)));

	buf.Put(verify_data, sizeof(verify_data));

	RETFAIL(send_handshake(sess, buf, HANDSHAKE_TYPE_CLIENT_FINISHED));

	sess->handshake_state = CLIENT_HANDSHAKE_CLIENT_FINISHED;

	return 0;
}

static int handle_server_change_cipher_spec(drew_tls_session_t sess,
		const Record &rec)
{
	drew_tls_cipher_suite_info_t csi;
	drew_hash_t hash;
	size_t bytes_needed = 0;

	if (sess->handshake_state != CLIENT_HANDSHAKE_NEED_SERVER_CIPHER_SPEC)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	if (*rec.data.GetPointer(0) != 1)
		return -DREW_TLS_ERR_UNEXPECTED_MESSAGE;

	// Generate key material and key data.
	drew_tls_priority_get_cipher_suite_info(sess->prio, &csi, &sess->cs);

	sess->clientp.mac =
		(drew_mac_t *)drew_mem_malloc(sizeof(*sess->clientp.mac));
	sess->serverp.mac =
		(drew_mac_t *)drew_mem_malloc(sizeof(*sess->serverp.mac));
	sess->clientp.stream = sess->serverp.stream = 0;
	sess->clientp.block = sess->serverp.block = 0;
	sess->clientp.mode = sess->serverp.mode = 0;

	RETFAIL(make_hash(sess->ldr, csi.hash, &hash));
	RETFAIL(make_mac(sess->ldr, "HMAC", sess->clientp.mac, &hash));
	RETFAIL(make_mac(sess->ldr, "HMAC", sess->serverp.mac, &hash));

	sess->clientp.key_size = sess->serverp.key_size = csi.cipher_key_len;
	sess->clientp.hash_size = sess->serverp.hash_size =
		hash.functbl->info2(&hash, DREW_HASH_SIZE_CTX, NULL, NULL);

	bytes_needed += sess->clientp.hash_size;
	bytes_needed += csi.cipher_key_len;

	if (!strcmp(csi.cipher, "RC4")) {
		sess->clientp.stream =
			(drew_stream_t *)drew_mem_malloc(sizeof(*sess->clientp.stream));
		sess->serverp.stream =
			(drew_stream_t *)drew_mem_malloc(sizeof(*sess->serverp.stream));
		sess->enc_type = cipher_type_stream;

		RETFAIL(make_stream(sess->ldr, csi.cipher, sess->clientp.stream));
		RETFAIL(make_stream(sess->ldr, csi.cipher, sess->serverp.stream));
	}
	else {
		sess->clientp.block =
			(drew_block_t *)drew_mem_malloc(sizeof(*sess->clientp.block));
		sess->serverp.block =
			(drew_block_t *)drew_mem_malloc(sizeof(*sess->serverp.block));
		sess->clientp.mode =
			(drew_mode_t *)drew_mem_malloc(sizeof(*sess->clientp.mode));
		sess->serverp.mode =
			(drew_mode_t *)drew_mem_malloc(sizeof(*sess->serverp.mode));
		sess->enc_type = cipher_type_block;

		// For the IV.
		bytes_needed += csi.cipher_key_len;

		RETFAIL(make_block(sess->ldr, csi.cipher, sess->clientp.block));
		RETFAIL(make_block(sess->ldr, csi.cipher, sess->serverp.block));
		RETFAIL(make_mode(sess->ldr, "CBC", sess->clientp.mode));
		RETFAIL(make_mode(sess->ldr, "CBC", sess->serverp.mode));
	}

	bytes_needed *= 2;

	uint8_t *material = (uint8_t *)drew_mem_smalloc(bytes_needed);
	do_tls_prf(sess, material, bytes_needed, "key expansion",
			sess->clientp.master_secret, sizeof(sess->clientp.master_secret));
	size_t off = 0;

	sess->clientp.mac->functbl->setkey(sess->clientp.mac, material+off,
			sess->clientp.hash_size);
	off += sess->clientp.hash_size;
	sess->serverp.mac->functbl->setkey(sess->serverp.mac, material+off,
			sess->serverp.hash_size);
	off += sess->serverp.hash_size;
	if (sess->enc_type == cipher_type_stream) {
		sess->clientp.stream->functbl->setkey(sess->clientp.stream,
				material+off, csi.cipher_key_len, 0);
		off += csi.cipher_key_len;
		sess->serverp.stream->functbl->setkey(sess->serverp.stream,
				material+off, csi.cipher_key_len, 0);
		off += csi.cipher_key_len;
	}
	else {
		sess->clientp.block->functbl->setkey(sess->clientp.block,
				material+off, csi.cipher_key_len, 0);
		off += csi.cipher_key_len;
		sess->serverp.block->functbl->setkey(sess->serverp.block,
				material+off, csi.cipher_key_len, 0);
		off += csi.cipher_key_len;

		sess->clientp.mode->functbl->setblock(sess->clientp.mode,
				sess->clientp.block);
		sess->serverp.mode->functbl->setblock(sess->serverp.mode,
				sess->serverp.block);

		sess->clientp.mode->functbl->setiv(sess->clientp.mode,
				material+off, csi.cipher_key_len);
		off += csi.cipher_key_len;
		sess->serverp.mode->functbl->setiv(sess->serverp.mode,
				material+off, csi.cipher_key_len);
		off += csi.cipher_key_len;
	}

	drew_mem_sfree(material);

	sess->handshake_state = CLIENT_HANDSHAKE_NEED_CLIENT_FINISHED;

	return 0;
}

static int client_send_client_data(drew_tls_session_t sess)
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

	// The entire message can be longer than this because of extensions.  At the
	// moment, we completely ignore any extensions.
	if (msg.length <= minlength + sess->session_id.length)
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

static int client_dispatch_handshake(drew_tls_session_t sess,
		HandshakeMessage &hm)
{
	int res = 0;

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

static int client_handle_handshake(drew_tls_session_t sess)
{
	int res = 0;
	bool read;
	drew_tls_handshake_t *hs = &sess->handshake;
	ByteQueue &hq = sess->queues->handshake;

	do {
		read = false;
		if (hq.GetSize() < 4)
			continue;

		uint8_t type = hq.Read<uint8_t>(0);
		uint32_t len = hq.Read24(1);

		if (hq.GetSize() < (4 + len))
			continue;

		uint8_t *buf = new uint8_t[len + 4];

		hq.Read(buf, len + 4);
		hq.Remove(len + 4);

		for (int i = 0; i < hs->nmsgs; i++)
			hs->msgs[i].functbl->update(hs->msgs+i, buf, len + 4);

		// process message.
		HandshakeMessage hm;
		hm.type = type;
		hm.length = len;
		hm.data.Put(buf+4, len);

		res = client_dispatch_handshake(sess, hm);

		delete[] buf;
		read = true;
	} while (read);

	return res;
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

	URETFAIL(sess, make_hash(sess->ldr, "MD5",
				sess->handshake.msgs+HASH_MD5));
	URETFAIL(sess, make_hash(sess->ldr, "SHA-1",
				sess->handshake.msgs+HASH_SHA1));

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
				URETFAIL(sess, handle_server_change_cipher_spec(sess, rec));
				break;
			case TYPE_ALERT:
				URETFAIL(sess, handle_alert(sess, rec));
				break;
			case TYPE_HANDSHAKE:
				sess->queues->handshake.AddData(rec.data.GetPointer(),
						rec.length);
				res = client_handle_handshake(sess);
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

	sess->handshake.msgs[HASH_MD5].functbl->fini(sess->handshake.msgs+HASH_MD5, 0);
	sess->handshake.msgs[HASH_SHA1].functbl->fini(sess->handshake.msgs+HASH_SHA1, 0);

	UNLOCK(sess);

	return 0;
}

int drew_tls_session_handshake(drew_tls_session_t sess)
{
	LOCK(sess);
	//URETFAIL(sess, make_hash(sess->ldr, "MD5", &sess->handshake.md5));
	//URETFAIL(sess, make_hash(sess->ldr, "SHA-1", &sess->handshake.sha1));
	UNLOCK(sess);
	return sess->client ? handshake_client(sess) : handshake_server(sess);
}
