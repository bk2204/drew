
#include "parser.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))

int drew_opgp_parser_new(drew_opgp_parser_t *p, int mode, const int *flags)
{
}

int drew_opgp_parser_free(drew_opgp_parser_t *p)
{
}

int drew_opgp_parser_parse_packets(drew_opgp_parser_t *p,
		drew_opgp_packet_t *packets, size_t *npackets, const uint8_t *data,
		size_t datalen, size_t *off)
{
}

static inline uint16_t get_uint16(const uint8_t **datap)
{
	const uint8_t *data = *datap;
	uint16_t res;
	res = *data++;
	res <<= 8;
	res |= *data++;
	*datap = data;
	return res;
}

static inline uint32_t get_uint32(const uint8_t **datap)
{
	const uint8_t *data = *datap;
	uint32_t res;
	res = *data++;
	res <<= 8;
	res |= *data++;
	res <<= 8;
	res |= *data++;
	res <<= 8;
	res |= *data++;
	*datap = data;
	return res;
}

// Return on failure.
#define RETFAIL(x) do { int res = (x); if (res < 0) return res; } while(0)
// Declare a need for at least x more bytes.  Return if they're not available.
#define DECLARE_NEED(x) \
	do { if ((data+(x)-origdata) >= datalen) return -DREW_ERR_MORE_DATA; } \
	while(0)
#define GET_UINT16() get_uint16(&data)
#define GET_UINT32() get_uint32(&data)

int drew_opgp_parser_parse_packet(drew_opgp_parser_t *parser,
		drew_opgp_packet_t *pkt, const uint8_t *data, size_t datalen)
{
	int res = 0;

	res = drew_opgp_parser_parse_packet_header(parser, pkt, data, datalen);
	if (res < 0)
		return res;
	data += res;
	datalen -= res;
	res = drew_opgp_parser_parse_packet_contents(parser, pkt, data, datalen);
	if (res < 0)
		return res;
}

int drew_opgp_parser_parse_packet_header(drew_opgp_parser_t *parser,
		drew_opgp_packet_t *pkt, const uint8_t *data, size_t datalen)
{
	const uint8_t *origdata = data;
	if (datalen < 4)
		return -DREW_ERR_MORE_DATA;
	pkt->tag = *data++;
	if (!(pkt->tag & 0x80))
		return -DREW_ERR_INVALID_HEADER;
	pkt->ver = (pkt->tag & 0x40) ? 4 : 3;
	if (pkt->ver <= 3) {
		pkt->type = (pkt->tag >> 2) & 0x0f;
		// old-style (v2 or v3) packet
		if ((pkt->tag & 3) == 3) {
			pkt->lenoflen = -1;
			pkt->len = 0;
		}
		else
			pkt->lenoflen = 1 << (pkt->tag & 3);
		DECLARE_NEED(pkt->lenoflen);
		pkt->len = 0;
		for (int i = 0; i < pkt->lenoflen; i++) {
			pkt->len <<= 8;
			pkt->len |= *data++;
		}
	}
	else {
		// new-style (v4) packet
		pkt->type = pkt->tag & 0x3f;
		DECLARE_NEED(1);
		uint8_t lenbyte = *data++;
		if (lenbyte < 0xc0) {
			pkt->lenoflen = 1;
			pkt->len = lenbyte;
		}
		else if (lenbyte < 0xe0) {
			DECLARE_NEED(1);
			pkt->lenoflen = 2;
			uint8_t b2 = *data++;
			pkt->len = (drew_opgp_len_t(lenbyte - 0xc0) << 8) + b2 + 0xc0;
		}
		else if (lenbyte == 0xff) {
			DECLARE_NEED(4);
			pkt->lenoflen = 4;
			pkt->len = GET_UINT32()
		}
		else {
			pkt->lenoflen = -1;
			pkt->len = drew_opgp_len_t(1) << (lenbyte & 0x1f);
		}
	}
	return data-origdata;
}

static size_t get_nmpis_encryption(uint8_t pkalgo)
{
	switch (pkalgo) {
		case 1:
		case 2:
		case 3:
			return 1;
		case 16:
		case 20:
			return 2;
		case 17:
		case 19:
			// Can't encrypt with these algorithms.
			return 0;
		case 18:
			// FIXME: read the specification and implement.
			return 0;
		default:
			// Something else?
			return 0;
	};
}

static size_t get_nmpis_signature(uint8_t pkalgo)
{
	switch (pkalgo) {
		case 1:
		case 2:
		case 3:
			return 1;
		case 17:
		case 20:
			return 2;
		case 16: // FIXME: Check to see if GnuPG allowed signatures with type 16.
		case 18:
			// Can't sign with these algorithms.
			return 0;
		case 19:
			// FIXME: read the specification and implement.
			return 0;
		default:
			// Something else?
			return 0;
	};
}

static size_t get_nmpis_pubkey(uint8_t pkalgo)
{
	switch (pkalgo) {
		case 1:
		case 2:
		case 3:
			return 2;
		case 16:
		case 20:
			return 3;
		case 17:
			// Can't encrypt with these algorithms.
			return 4;
		default:
			// Something else?
			return 0;
	};
}

static size_t get_nmpis_privkey(uint8_t pkalgo)
{
	switch (pkalgo) {
		case 1:
		case 2:
		case 3:
			return 4;
		case 16:
		case 17:
		case 20:
			return 1;
		default:
			// Something else?
			return 0;
	};
}

static size_t get_sk_block_size(uint8_t skalgo)
{
	if (!skalgo)
		return 0;
	if (skalgo <= 6)
		return 8;
	if (skalgo <= 13)
		return 16;
	return 0;
}

static inline int load_mpis(drew_opgp_mpi_t *mpis, size_t max,
		const uint8_t *data, size_t datalen)
{
	const uint8_t *origdata = data;
	for (int i = 0; i < max; i++) {
		DECLARE_NEED(2);
		uint16_t len = GET_UINT16();
		mpis[i].len = len;
		DECLARE_NEED(len);
		uint8_t *mpidata = malloc(len);
		if (!mpidata)
			return -ENOMEM;
		memcpy(mpidata, data, len);
		data += len;
		mpis[i].data = mpidata;
	}
	return data-origdata;
}

static int parse_pkesk(drew_opgp_parser_t *parser, drew_opgp_packet_t *pkt,
		const uint8_t *data, size_t datalen)
{
	const uint8_t *origdata = data;
	drew_opgp_packet_pkesk_t *p = &pkt.data.pkesk;
	DECLARE_NEED(1 + 8 + 1 + 2);
	DECLARE_NEED(pkt->len);

	p->ver = *data++;
	memcpy(p->keyid, data, sizeof(p->keyid));
	data += sizeof(p->keyid);
	p->pkalgo = *data++;

	size_t nmpis = get_nmpis_encryption(p->pkalgo);
	// FIXME: Decide what to do it nmpis is zero (invalid).
	int res = load_mpis(p->mpi, nmpis, data,
			datalen - (data - origdata));
	if (res < 0)
		return res;
	data += res;
	return data-origdata;
}

static int parse_sigv3(drew_opgp_parser_t *parser, drew_opgp_packet_t *pkt,
		const uint8_t *data, size_t datalen)
{
	const uint8_t *origdata = data;
	drew_opgp_packet_sig_t *sig = &pkt.data.sig;
	drew_opgp_packet_sigv3_t *p = &sig->sigv3;

	DECLARE_NEED(1 + 1 + 1 + 4 + 8 + 1 + 1 + 2 + 2);
	sig->ver = *data++;
	p->len = *data++;
	if (p->len != 5)
		return -DREW_ERR_INVALID;
	p->type = *data++;
	p->ctime = GET_UINT32();
	memcpy(p->keyid, data, sizeof(p->keyid));
	data += sizeof(p->keyid);
	p->pkalgo = *data++;
	p->mdalgo = *data++;
	memcpy(p->left, data, sizeof(p->left));
	data += sizeof(p->left);

	size_t nmpis = get_nmpis_signature(p->pkalgo);
	// FIXME: Decide what to do it nmpis is zero (invalid).
	int res = load_mpis(p->mpi, nmpis, data,
			datalen - (data - origdata));
	if (res < 0)
		return res;
	data += res;
	return data-origdata;
}

static int load_subpackets(drew_opgp_subpacket_t **sparr, size_t *nsp,
		const uint8_t *data, uint16_t datalen)
{
	const uint8_t *origdata = data;
	size_t nalloced = 20; // Probably larger than needed.
	drew_opgp_subpacket_t *sp = malloc(sizeof(*sp) * nalloced);

	if (!sp)
		return -ENOMEM;
	*nsp = 0;

	for (size_t i = 0; (data - origdata) < datalen; i++) {
		if (i >= nalloced) {
			drew_opgp_subpacket_t *spnew = realloc(sp, sizeof(*sp) * i);
			if (!spnew)
				return -ENOMEM;
			sp = spnew;
			nalloced++;
		}
		DECLARE_NEED(1);
		uint8_t lenbyte = *data++;
		if (lenbyte < 0xc0) {
			sp[i].lenoflen = 1;
			sp[i].len = lenbyte;
		}
		else if (lenbyte < 0xff) {
			DECLARE_NEED(1);
			sp[i].lenoflen = 2;
			uint8_t b2 = *data++;
			sp[i].len = (size_t(lenbyte - 0xc0) << 8) + b2 + 0xc0;
		}
		else {
			DECLARE_NEED(4);
			sp[i].lenoflen = 4;
			sp[i].len = GET_UINT32();
		}
		if (!sp[i].len)
			return -DREW_OPGP_ERR_INVALID;
		DECLARE_NEED(sp[i].len);
		uint8_t typebyte = *data++;
		sp[i].type = typebyte & 0x7f;
		sp[i].critical = typebyte & 0x80;
		sp[i].data = malloc(sp[i].len - 1);
		memcpy(sp[i].data, data, sp[i].len);
		data += sp[i].len;
		// FIXME: split into data chunks.
		(*nsp)++;
	}
}

static int parse_sigv4(drew_opgp_parser_t *parser, drew_opgp_packet_t *pkt,
		const uint8_t *data, size_t datalen)
{
	const uint8_t *origdata = data;
	drew_opgp_packet_sig_t *sig = &pkt.data.sig;
	drew_opgp_packet_sigv4_t *p = &sig->sigv4;
	int res = 0;

	DECLARE_NEED(1 + 1 + 1 + 1 + 2 + 2 + 2 + 2);
	sig->ver = *data++;
	p->type = *data++;
	p->pkalgo = *data++;
	p->mdalgo = *data++;
	p->hashedlen = GET_UINT16();

	DECLARE_NEED(p->hashedlen);
	res = load_subpackets(&p->hashed, &p->nhashed, data, p->hashedlen);
	if (res < 0)
		return res;
	data += p->hashedlen;

	p->unhashedlen = GET_UINT16();

	DECLARE_NEED(p->unhashedlen);
	res = load_subpackets(&p->unhashed, &p->nunhashed, data, p->unhashedlen);
	if (res < 0)
		return res;
	data += p->hashedlen;

	memcpy(p->left, data, sizeof(p->left));
	data += sizeof(p->left);

	size_t nmpis = get_nmpis_signature(p->pkalgo);
	// FIXME: Decide what to do it nmpis is zero (invalid).
	int res = load_mpis(p->mpi, nmpis, data,
			datalen - (data - origdata));
	if (res < 0)
		return res;
	data += res;
	return data-origdata;
}

static int parse_sig(drew_opgp_parser_t *parser, drew_opgp_packet_t *pkt,
		const uint8_t *data, size_t datalen)
{
	uint8_t ver = *data; // Not incrementing intentionally.
	if (ver <= 3)
		return parse_sigv3(parser, pkt, data, datalen);
	else
		return parse_sigv4(parser, pkt, data, datalen);
}

static int parse_s2k(drew_opgp_parser_t *parser, drew_opgp_s2k_t *s2k,
		const uint8_t *data, size_t datalen)
{
	const uint8_t *origdata = data;
	DECLARE_NEED(2);
	s2k->type = *data++;
	s2k->mdalgo = *data++;

	if (s2k->type != 0x00) {
		DECLARE_NEED(8);

		memcpy(s2k->salt, data, sizeof(s2k->salt));
		data += sizeof(s2k->salt);
		if (s2k->type == 0x03) {
			DECLARE_NEED(1);
			s2k->count = *data++;
		}
	}

	return data-origdata;
}

static int parse_skesk(drew_opgp_parser_t *parser, drew_opgp_packet_t *pkt,
		const uint8_t *data, size_t datalen)
{
	const uint8_t *origdata = data;
	drew_opgp_packet_skesk_t *p = &pkt.data.skesk;
	DECLARE_NEED(1 + 1 + 2);

	p->ver = *data++;
	p->skalgo = *data++;
	int res = parse_s2k(parser, &p->s2k, data, datalen-(data-origdata));
	if (res < 0)
		return res;
	data += res;
	if (!(data - origdata)) {
		p->sk_present = false;
		goto out;
	}
	p->sk_present = true;
	size_t nbytes = MIN(sizeof(p->sk), data - origdata);
	memcpy(p->sk, data, nbytes);
	data += nbytes;
out:
	return data-origdata;
}

static int parse_onepass_sig(drew_opgp_parser_t *parser,
		drew_opgp_packet_t *pkt, const uint8_t *data, size_t datalen)
{
	const uint8_t *origdata = data;
	drew_opgp_packet_skesk_t *p = &pkt.data.onepass_sig;
	DECLARE_NEED(1 + 1 + 1 + 1 + 8 + 1);

	p->ver = *data++;
	p->type = *data++;
	p->mdalgo = *data++;
	p->pkalgo = *data++;
	memcpy(p->keyid, data, sizeof(p->keyid));
	data += sizeof(p->keyid);
	p->nested = !!*data++;
	return data-origdata;
}

static int parse_pubkeyv3(drew_opgp_parser_t *parser, drew_opgp_packet_t *pkt,
		const uint8_t *data, size_t datalen)
{
	const uint8_t *origdata = data;
	drew_opgp_packet_pubkey_t *pk = &pkt.data.pubkey;
	drew_opgp_packet_pubkeyv3_t *p = &pk->pubkeyv3;
	int res = 0;

	DECLARE_NEED(1 + 4 + 2 + 1);
	sig->ver = *data++;
	p->type = *data++;
	p->pkalgo = *data++;
	p->mdalgo = *data++;
	p->hashedlen = GET_UINT16();

	DECLARE_NEED(p->hashedlen);
	res = load_subpackets(&p->hashed, &p->nhashed, data, p->hashedlen);
	if (res < 0)
		return res;
	data += p->hashedlen;

	p->unhashedlen = GET_UINT16();

	DECLARE_NEED(p->unhashedlen);
	res = load_subpackets(&p->unhashed, &p->nunhashed, data, p->unhashedlen);
	if (res < 0)
		return res;
	data += p->hashedlen;

	memcpy(p->left, data, sizeof(p->left));
	data += sizeof(p->left);

	size_t nmpis = get_nmpis_signature(p->pkalgo);
	// FIXME: Decide what to do it nmpis is zero (invalid).
	int res = load_mpis(p->mpi, nmpis, data,
			datalen - (data - origdata));
	if (res < 0)
		return res;
	data += res;
	return data-origdata;
}


static int parse_pubkey(drew_opgp_parser_t *parser, drew_opgp_packet_t *pkt,
		const uint8_t *data, size_t datalen)
{
	uint8_t ver = *data; // Not incrementing intentionally.
	if (ver <= 3)
		return parse_pubkeyv3(parser, pkt, data, datalen);
	else
		return parse_pubkeyv4(parser, pkt, data, datalen);
}

static const int (*func[64])(drew_opgp_parser_t *, drew_opgp_packet_t *,
		const uint8_t *, size_t) = {
	NULL,
	parse_pkesk,
	parse_sig,
	parse_skesk,
	parse_onepass_sig,
	parse_privkey,
	parse_pubkey,
	parse_privkey,
	parse_pubkey,
	NULL
};

int drew_opgp_parser_parse_packet_contents(drew_opgp_parser_t *parser,
		drew_opgp_packet_t *pkt, const uint8_t *data, size_t datalen)
{
	if (pkt->type == 0)
		return -DREW_OPGP_ERR_INVALID;
	else if (!func[pkt->type])
		return -DREW_OPGP_ERR_NOT_IMPL;

	int res = func[pkt->type](parser, pkt, data, datalen);
}
