#include "internal.h"

#include <utility>

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

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
		name = "ARC4Stir";

	if ((res = make_primitive(ldr, name, prng, DREW_TYPE_HASH)))
		return res;
	res = prng->functbl->init(prng, 0, ldr, NULL);
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
	int res = 0;

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

	return 0;
}

static int decrypt_stream(drew_tls_session_t sess, Record &rec,
		SerializedBuffer &sbuf)
{
	int res = 0;

	return -DREW_ERR_NOT_IMPL;
}

// This function must be externally locked.
static int send_record(drew_tls_session_t sess, const uint8_t *buf,
		size_t len, uint8_t type)
{
	int res = 0;
	Record rec;
	uint16_t belen;

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
	while (nrecvd < len) {
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
	drew_tls_server_hello_t sh;
	
	LOCK(sess);
	UNLOCK(sess);

	return -DREW_ERR_NOT_IMPL;
}

static int recv_handshake(drew_tls_session_t sess, SerializedBuffer &buf,
		uint32_t *length, uint8_t *type)
{
	int res = 0;
	Record rec;

	res = recv_record(sess, rec);

	if (rec.length < 4)
		return -DREW_TLS_ERR_ILLEGAL_PARAMETER;

	// length is really only 24 bits in length, but we can't just load a
	// three-byte quantity.  The type octet precedes it, so we do some fancy
	// footwork to get both. 
	buf = rec.data;
	buf.ResetPosition();
	buf.Get(*length);
	buf.ResetPosition();
	buf.Get(*type);
	buf.ResetPosition();

	*length &= 0xffffff;

	return res;
}


static int handshake_recv_server_hello(drew_tls_session_t sess)
{
	int res = 0;
	drew_tls_server_hello_t sh;

	LOCK(sess);

	UNLOCK(sess);

	return -DREW_ERR_NOT_IMPL;
}

static int handshake_server(drew_tls_session_t sess)
{
	return -DREW_ERR_NOT_IMPL;
}

static int handshake_client(drew_tls_session_t sess)
{
	int res = 0;
	RETFAIL(handshake_send_client_hello(sess));
	RETFAIL(handshake_recv_server_hello(sess));

	return -DREW_ERR_NOT_IMPL;
}

int drew_tls_session_handshake(drew_tls_session_t sess)
{
	int res = 0;
	LOCK(sess);
	//URETFAIL(sess, make_hash(sess->ldr, "MD5", &sess->handshake.md5));
	//URETFAIL(sess, make_hash(sess->ldr, "SHA-1", &sess->handshake.sha1));
	UNLOCK(sess);
	return sess->client ? handshake_client(sess) : handshake_server(sess);
}
