#include "internal.h"
#include "structs.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <drew/drew.h>
#include <drew/hash.h>
#include <drew/mem.h>
#include <drew/plugin.h>
#include <drew/pksig.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/key.h>
#include <drew-opgp/keystore.h>
#include <drew-opgp/parser.h>

#include "util.hh"
#include "key.hh"

HIDE()
typedef BigEndian E;

static int make_bignum(const drew_loader_t *ldr, drew_bignum_t *bn)
{
	int id = 0, res = 0;
	const void *tbl = NULL;

	id = drew_loader_lookup_by_name(ldr, "Bignum", 0, -1);
	if (id < 0)
		return id;
	res = drew_loader_get_functbl(ldr, id, &tbl);
	if (res < 0)
		return res;
	bn->functbl = (const drew_bignum_functbl_t *)tbl;
	RETFAIL(bn->functbl->init(bn, 0, ldr, NULL));
	return 0;
}

static int make_pksig(const drew_loader_t *ldr, drew_pksig_t *pksig,
		const char *algoname)
{
	int id = 0, res = 0;
	const void *tbl = NULL;
	drew_param_t param;
	drew_bignum_t bn;

	id = drew_loader_lookup_by_name(ldr, algoname, 0, -1);
	if (id == -DREW_ERR_NONEXISTENT)
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	else if (id < 0)
		return id;
	res = drew_loader_get_functbl(ldr, id, &tbl);
	if (res < 0)
		return res;
	pksig->functbl = (const drew_pksig_functbl_t *)tbl;
	param.next = 0;
	param.name = "bignum";
	param.param.value = &bn;
	RETFAIL(make_bignum(ldr, &bn));
	RETFAIL(pksig->functbl->init(pksig, 0, ldr, &param));
	return 0;
}

static int verify_rsa(const drew_loader_t *ldr, const drew::PublicKey &pub,
		drew_pksig_t *pksig, drew_opgp_hash_t digest, size_t len, int hashalgo,
		const drew::MPI *mpi)
{
	using namespace drew;
	drew_bignum_t bn[2];
	drew_bignum_t *c = bn+0, *m = bn+1;
	int res = 0;

	try {
		if (!Hash::GetAlgorithmPrefixLength(hashalgo))
			return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	}
	catch (int e) {
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	}

	if (!len)
		len = Hash::GetAlgorithmLength(hashalgo);

	if (len != Hash::GetAlgorithmLength(hashalgo))
		return -DREW_OPGP_ERR_BAD_SIGNATURE;

	for (size_t i = 0; i < DIM(bn); i++)
		RETFAIL(make_bignum(ldr, bn+i));

	const drew::MPI *pubmpi = pub.GetMPIs();
	size_t nlen = pubmpi[0].GetByteLength();
	pksig->functbl->setval(pksig, "n", pubmpi[0].GetData(),
			pubmpi[0].GetByteLength());
	pksig->functbl->setval(pksig, "e", pubmpi[1].GetData(),
			pubmpi[1].GetByteLength());
	c->functbl->setbytes(c, mpi[0].GetData(), mpi[0].GetByteLength());

	pksig->functbl->verify(pksig, m, c);
	pksig->functbl->fini(pksig, 0);
	size_t mlen = m->functbl->nbytes(m);
	if (mlen != nlen - 1)
		return -DREW_OPGP_ERR_BAD_SIGNATURE;
	uint8_t *buf = new uint8_t[mlen];
	if (!buf)
		return -ENOMEM;
	m->functbl->bytes(m, buf, mlen);
	size_t soh = mlen - len;
	size_t sop = soh - Hash::GetAlgorithmPrefixLength(hashalgo);
	if (sop-1 - 1 < 8)
		res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	if (buf[0] != 0x01)
		res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	if (memcmp(buf+soh, digest, len))
		res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	if (memcmp(buf+sop, Hash::GetAlgorithmPrefix(hashalgo),
				Hash::GetAlgorithmPrefixLength(hashalgo)))
		res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	if (buf[sop-1] != 0x00)
		res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	for (size_t i = 1; i < sop-1; i++)
		if (buf[i] != 0xff)
			res = -DREW_OPGP_ERR_BAD_SIGNATURE;
	delete[] buf;
	return res;
}

static int verify_dsa(const drew_loader_t *ldr, const drew::PublicKey &pub,
		drew_pksig_t *pksig, drew_opgp_hash_t digest, size_t len, int hashalgo,
		const drew::MPI *mpi)
{
	using namespace drew;
	drew_bignum_t bn[5];
	drew_bignum_t *r = bn+0, *s = bn+1, *h = bn+2, *v = bn+3, *z = bn+4;
	size_t qlen;
	int res = 0;

	try {
		if (!Hash::GetAlgorithmPrefixLength(hashalgo))
			return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	}
	catch (int e) {
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	}

	if (!len)
		len = Hash::GetAlgorithmLength(hashalgo);

	if (len != Hash::GetAlgorithmLength(hashalgo))
		return -DREW_OPGP_ERR_BAD_SIGNATURE;

	// The hash must be at least as large as q.
	qlen = pub.GetMPIs()[1].GetByteLength();
	if (len < qlen)
		return -DREW_OPGP_ERR_BAD_SIGNATURE;

	for (size_t i = 0; i < DIM(bn); i++)
		RETFAIL(make_bignum(ldr, bn+i));

	const char *names[] = {"p", "q", "g", "y"};
	for (size_t i = 0; i < 4; i++)
		pksig->functbl->setval(pksig, names[i], pub.GetMPIs()[i].GetData(),
				pub.GetMPIs()[i].GetByteLength());

	z->functbl->setzero(z);
	r->functbl->setbytes(r, mpi[0].GetData(), mpi[0].GetByteLength());
	s->functbl->setbytes(s, mpi[1].GetData(), mpi[1].GetByteLength());
	if (!r->functbl->compare(r, z, 0) || !s->functbl->compare(s, z, 0))
		return -DREW_OPGP_ERR_BAD_SIGNATURE;
	h->functbl->setbytes(s, digest, qlen);
	pksig->functbl->verify(pksig, v, bn);
	pksig->functbl->fini(pksig, 0);
	res = r->functbl->compare(r, v, 0) ? 0 : -DREW_OPGP_ERR_BAD_SIGNATURE;

	for (size_t i = 0; i < DIM(bn); i++)
		bn[i].functbl->fini(bn+i, 0);

	return res;
}

static int verify_sig(const drew_loader_t *ldr, const drew::PublicKey &pub,
		drew_opgp_hash_t digest, size_t len, int pkalgo, int hashalgo,
		const drew::MPI *mpi)
{
	using namespace drew;
	drew_pksig_t xsa;
	const char *algoname = NULL;
	int (*verify)(const drew_loader_t *ldr, const PublicKey &, drew_pksig_t *,
			drew_opgp_hash_t, size_t, int, const MPI *);

	if (pkalgo >= 1 && pkalgo <= 3) {
		algoname = "RSASignature";
		verify = verify_rsa;
	}
	else if (pkalgo == 17) {
		algoname = "DSA";
		verify = verify_dsa;
	}
	else if (pkalgo == 16 || pkalgo == 20)
		return -DREW_ERR_NOT_IMPL;
	else
		return -DREW_OPGP_ERR_NO_SUCH_ALGO;
	RETFAIL(make_pksig(ldr, &xsa, algoname));
	return verify(ldr, pub, &xsa, digest, len, hashalgo, mpi);
}


template<class T>
inline static void hash_obj(drew_hash_t *hash, T x)
{
	uint8_t buf[sizeof(T)];
	const uint8_t *p = E::CopyIfNeeded(buf, &x, sizeof(T));
	hash->functbl->update(hash, p, sizeof(T));
}

inline static void hash_u8(drew_hash_t *hash, uint8_t x)
{
	hash->functbl->update(hash, &x, 1);
}

inline static void hash_u16(drew_hash_t *hash, uint16_t x)
{
	hash_obj(hash, x);
}

inline static void hash_u32(drew_hash_t *hash, uint32_t x)
{
	hash_obj(hash, x);
}

const drew::Hash::hash_algos drew::Hash::hashes[] = {
	{
		NULL, 0, 0, {}
	},
	{
		"MD5", 16, 18, {
			0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
			0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
			0x04, 0x10
		}
	},
	{
		"SHA-1", 20, 15, {
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
			0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
		}
	},
	{
		"RIPEMD-160", 20, 15, {
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24,
			0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14
		}
	},
	{
		NULL, 0, 0, {}
	},
	{
		"MD2", 16, 18, {
			0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
			0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00,
			0x04, 0x10
		}
	},
	{
		"Tiger", 24, 0, {}
	},
	{
		NULL, 0, 0, {}
	},
	{
		"SHA-256", 32, 19, {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
			0x00, 0x04, 0x20
		}
	},
	{
		"SHA-384", 32, 19, {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
			0x00, 0x04, 0x30
		}
	},
	{
		"SHA-512", 64, 19, {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
			0x00, 0x04, 0x40
		}
	},
	{
		"SHA-224", 28, 19, {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
			0x00, 0x04, 0x1c
		}
	}
};


drew::Hash::Hash(const drew_loader_t *l, int algoid)
{
	int id = 0, res = 0;
	const void *tbl = NULL;

	ldr = l;
	hash.ctx = NULL;

	if (algoid >= int(DIM(hashes)))
		throw DREW_ERR_INVALID;
	if (!hashes[algoid].algoname)
		throw DREW_ERR_INVALID;

	id = drew_loader_lookup_by_name(ldr, hashes[algoid].algoname, 0, -1);
	if (id == -DREW_ERR_NONEXISTENT)
		throw DREW_OPGP_ERR_NO_SUCH_ALGO;
	else if (id < 0)
		throw id;	
	res = drew_loader_get_functbl(ldr, id, &tbl);
	if (res < 0)
		throw res;
	hash.functbl = (const drew_hash_functbl_t *)tbl;
	NTHROWFAIL(hash.functbl->init(&hash, 0, ldr, NULL));
}

drew::Hash::~Hash()
{
	if (hash.ctx)
		hash.functbl->fini(&hash, 0);
}

void drew::Hash::Update(const uint8_t *buf, size_t len)
{
	hash.functbl->update(&hash, buf, len);
}

template<class T>
void drew::Hash::Update(T x)
{
	hash_obj(&hash, x);
}

void drew::Hash::Final(uint8_t *digest)
{
	hash.functbl->final(&hash, digest, 0);
}
const char *drew::Hash::GetAlgorithmName(int algo)
{
	if (algo < 0 || algo > int(DIM(hashes)))
		throw DREW_ERR_INVALID;
	return hashes[algo].algoname;
}

size_t drew::Hash::GetAlgorithmLength(int algo)
{
	if (algo < 0 || algo > int(DIM(hashes)))
		throw DREW_ERR_INVALID;
	return hashes[algo].len;
}

size_t drew::Hash::GetAlgorithmPrefixLength(int algo)
{
	if (algo < 0 || algo > int(DIM(hashes)))
		throw DREW_ERR_INVALID;
	return hashes[algo].prefixlen;
}

const uint8_t *drew::Hash::GetAlgorithmPrefix(int algo)
{
	if (algo < 0 || algo > int(DIM(hashes)))
		throw DREW_ERR_INVALID;
	return hashes[algo].prefix;
}

drew::MPI::MPI()
{
	memset(&mpi, 0, sizeof(mpi));
}

drew::MPI::MPI(const drew_opgp_mpi_t &other)
{
	SetMPI(other);
}

drew::MPI::MPI(const MPI &other)
{
	SetMPI(other.mpi);
	this->ldr = other.ldr;
}

drew::MPI::~MPI()
{
	drew_mem_free(mpi.data);
}

const drew_opgp_mpi_t &drew::MPI::GetMPI() const
{
	return mpi;
}

const uint8_t *drew::MPI::GetData() const
{
	return mpi.data;
}

size_t drew::MPI::GetBitLength() const
{
	return mpi.len;
}

size_t drew::MPI::GetByteLength() const
{
	return DivideAndRoundUp(mpi.len, 8);
}

void drew::MPI::SetMPI(const drew_opgp_mpi_t &other)
{
	mpi.len = other.len;
	mpi.data = (uint8_t *)((other.data) ?
			drew_mem_memdup(other.data, other.len) : 0);
	memcpy(&mpi.id, &other.id, sizeof(mpi.id));
	SetInternalID(other.id);
}

void drew::MPI::SetMPI(const uint8_t *p, size_t len)
{
	mpi.len = len;
	mpi.data = (uint8_t *)drew_mem_memdup(p, len);
	memset(&mpi.id, 0, sizeof(mpi.id));
}

void drew::MPI::GenerateID()
{
	Hash hash(ldr, DREW_OPGP_MDALGO_SHA256);
	hash.Update(mpi.len);
	hash.Update(mpi.data, GetByteLength());
	hash.Final(id);
}

void clone_subpackets(drew_opgp_subpacket_group_t *nu,
		const drew_opgp_subpacket_group_t *old)
{
	memcpy(nu, old, sizeof(*nu));
	if (!(nu->data = (uint8_t *)drew_mem_memdup(nu->data, nu->len)))
		throw ENOMEM;
	nu->subpkts = (drew_opgp_subpacket_t *)drew_mem_memdup(nu->subpkts,
			nu->nsubpkts * sizeof(*nu->subpkts));
	if (!nu->subpkts)
		throw ENOMEM;

	for (size_t i = 0; i < nu->nsubpkts; i++) {
		nu->subpkts[i].data = (uint8_t *)drew_mem_memdup(nu->subpkts[i].data,
				nu->subpkts[i].len);
		if (!nu->subpkts[i].data)
			throw ENOMEM;
	}
}

void free_subpackets(drew_opgp_subpacket_group_t *spg)
{
	drew_mem_free(spg->data);
	drew_mem_free(spg->subpkts);
}

drew::Signature::Signature()
{
	memset(&selfsig, 0, sizeof(selfsig));
	memset(&hashed, 0, sizeof(hashed));
	memset(&unhashed, 0, sizeof(unhashed));
	etime = -1;
}

drew::Signature::Signature(const Signature &other)
{
	memcpy(&selfsig, &other.selfsig, sizeof(selfsig));
	for (size_t i = 0; i < DREW_OPGP_MAX_MPIS; i++)
		mpi[i] = other.mpi[i];
	clone_subpackets(&hashed, &other.hashed);
	clone_subpackets(&unhashed, &other.unhashed);
	flags = other.flags;
	ver = other.ver;
	type = other.type;
	pkalgo = other.pkalgo;
	mdalgo = other.mdalgo;
	ctime = other.ctime;
	etime = other.etime;
	memcpy(&keyid, &other.keyid, sizeof(keyid));
	memcpy(&left, other.left, sizeof(left));
	ldr = other.ldr;
}

drew::Signature::~Signature()
{
	free_subpackets(&hashed);
	free_subpackets(&unhashed);
}

void drew::Signature::SetCreationTime(time_t t)
{
	ctime = t;
}

time_t drew::Signature::GetCreationTime() const
{
	return ctime;
}

void drew::Signature::SetExpirationTime(time_t t)
{
	etime = t;
}

time_t drew::Signature::GetExpirationTime() const
{
	return etime;
}

int drew::Signature::GetVersion() const
{
	return ver;
}

void drew::Signature::SetVersion(int x) 
{
	if (x < 2 || x > 4)
		throw DREW_ERR_INVALID;
	ver = x;
}

int drew::Signature::GetType() const
{
	return type;
}

void drew::Signature::SetType(int x)
{
	type = x;
}

int drew::Signature::GetPublicKeyAlgorithm() const
{
	return pkalgo;
}

void drew::Signature::SetPublicKeyAlgorithm(int x)
{
	pkalgo = x;
}

int drew::Signature::GetDigestAlgorithm() const
{
	return mdalgo;
}

void drew::Signature::SetDigestAlgorithm(int x)
{
	mdalgo = x;
}

const uint8_t *drew::Signature::GetKeyID() const
{
	return keyid;
}

const drew::MPI *drew::Signature::GetMPIs() const
{
	return mpi;
}

const drew_opgp_subpacket_group_t &drew::Signature::GetHashedSubpackets() const
{
	return hashed;
}

const drew_opgp_subpacket_group_t &drew::Signature::GetUnhashedSubpackets()
	const
{
	return unhashed;
}

uint8_t *drew::Signature::GetKeyID()
{
	return keyid;
}

drew::MPI *drew::Signature::GetMPIs()
{
	return mpi;
}

drew_opgp_subpacket_group_t &drew::Signature::GetHashedSubpackets()
{
	return hashed;
}

drew_opgp_subpacket_group_t &drew::Signature::GetUnhashedSubpackets()
{
	return unhashed;
}

void drew::Signature::GenerateID()
{
	Hash hash(ldr, DREW_OPGP_MDALGO_SHA256);
	size_t nmpis = 0;
	uint32_t totallen = 0;

	for (int i = 0; i < DREW_OPGP_MAX_MPIS && mpi[i].GetByteLength();
			i++, nmpis++)
		totallen += mpi[i].GetByteLength();

	/* By analogy with hashing the key, this is a v3 encoding of a signature
	 * packet with four-octet length (it might contain more than a two-octet
	 * length's worth of data).
	 */
	hash.Update<uint8_t>(0x8a);
	totallen += 1 + 1 + 1 + 1 + 4 + 2 + hashed.len + 2 +
		unhashed.len + (2 * nmpis);
	hash.Update<uint32_t>(totallen);
	hash.Update<uint8_t>(ver);
	hash.Update<uint8_t>(type);
	hash.Update<uint8_t>(pkalgo);
	hash.Update<uint8_t>(mdalgo);
	hash.Update<uint32_t>(ctime);
	hash.Update<uint16_t>(hashed.len);
	hash.Update(hashed.data, hashed.len);
	/* We include the unhashed data here because our interest is providing a
	 * unique ID for this signature and we want to distinguish between
	 * signatures that have different unhashed data (where the issuer key ID is
	 * usually placed.
	 */
	hash.Update<uint16_t>(unhashed.len);
	hash.Update(unhashed.data, unhashed.len);
	for (size_t i = 0; i < nmpis; i++) {
		hash.Update<uint16_t>(mpi[i].GetBitLength());
		hash.Update(mpi[i].GetData(), mpi[i].GetByteLength());
	}
	hash.Final(id);
}

void drew::Signature::HashUserIDSignature(const PublicKey &pub,
		const UserID &uid)
{
	memset(hash, 0, sizeof(hash));
	Hash h(ldr, mdalgo);
	pub.HashData(h);
	uid.HashData(h);
	this->HashData(h);
	h.Final(hash);
}

int drew::Signature::ValidateSignature(const PublicKey &pub, bool is_selfsig)
{
	int res = 0;
	const int checked_sig = DREW_OPGP_SIGNATURE_CHECKED;
	const int good_sig = checked_sig | DREW_OPGP_SIGNATURE_VALIDATED;
	res = verify_sig(ldr, pub, hash, 0, pkalgo, mdalgo, mpi);
	flags &= ~good_sig;
	flags |= (!res) ? good_sig :
		((res == -DREW_OPGP_ERR_BAD_SIGNATURE) ?  checked_sig : 0);
	if (is_selfsig) {
		if ((!(flags & checked_sig) ||
				(flags & good_sig) == good_sig))
			flags |= DREW_OPGP_SIGNATURE_SELF_SIG;
		else
			flags &= ~DREW_OPGP_SIGNATURE_SELF_SIG;
	}
	return res;
}

void drew::Signature::SynchronizeUserIDSignature(const Key &key,
		const UserID &uid, int f)
{
	const PublicKey &pub = key.GetPublicMainKey();
	if (ver < 2 || ver > 4)
		flags |= DREW_OPGP_SIGNATURE_IGNORED;
	if (type == 0x30) {
		// FIXME: implement.
		flags |= DREW_OPGP_SIGNATURE_IGNORED;
	}
	else if ((type & ~3) != 0x10) {
		// Wherever this signature belongs, it's not here.
		flags |= DREW_OPGP_SIGNATURE_IGNORED;
	}
	if (f & (DREW_OPGP_SYNCHRONIZE_HASH_SIGS |
				DREW_OPGP_SYNCHRONIZE_VALIDATE_SELF_SIGNATURES)) {
		HashUserIDSignature(pub, uid);
		if (!memcmp(left, hash, 2))
			flags |= DREW_OPGP_SIGNATURE_HASH_CHECK;
		if (!memcmp(keyid, keyid, sizeof(keyid))) {
			if (f & DREW_OPGP_SYNCHRONIZE_VALIDATE_SELF_SIGNATURES)
				ValidateSignature(key.GetPublicMainKey(), true);
		}
		if (!(flags & DREW_OPGP_SIGNATURE_SELF_SIG))
			memset(&selfsig, 0, sizeof(selfsig));
	}
	for (size_t i = 0; i < DREW_OPGP_MAX_MPIS && mpi[i].GetByteLength(); i++) {
		mpi[i].SetLoader(ldr);
		mpi[i].GenerateID();
	}
	GenerateID();
}

void drew::Signature::Synchronize(int f)
{
	// FIXME: implement.
}

void drew::Signature::HashData(Hash &hash) const
{
	if (ver < 4) {
		hash.Update<uint8_t>(type);
		hash.Update<uint32_t>(ctime);
	}
	else {
		uint32_t len = 1 + 1 + 1 + 1 + 2 + hashed.len;
		hash.Update<uint8_t>(ver);
		hash.Update<uint8_t>(type);
		hash.Update<uint8_t>(pkalgo);
		hash.Update<uint8_t>(mdalgo);
		hash.Update<uint16_t>(hashed.len);
		hash.Update(hashed.data, hashed.len);
		// Trailer.
		hash.Update<uint16_t>(0x04ff);
		hash.Update<uint32_t>(len);
	}
}

int drew::Signature::GetFlags() const
{
	return flags;
}

bool drew::Signature::IsSelfSignature() const
{
	return flags & DREW_OPGP_SIGNATURE_SELF_SIG;
}

const uint8_t *drew::Signature::GetLeft2() const
{
	return left;
}

uint8_t *drew::Signature::GetLeft2()
{
	return left;
}

void drew::UserID::SetText(const std::string &t)
{
	text = t;
}

void drew::UserID::SetText(const char *s)
{
	text = s;
}

void drew::UserID::SetText(const uint8_t *s, size_t len)
{
	text = std::string((const char *)s, len);
}

const std::string &drew::UserID::GetText() const
{
	return text;
}

void drew::UserID::GenerateID(const PublicKey &pub)
{
	Hash hash(ldr, DREW_OPGP_MDALGO_SHA256);
	pub.HashData(hash);
	HashData(hash);
	hash.Final(id);
}

void drew::UserID::Synchronize(int flags)
{
	time_t latest = 0;

	selfsigs.clear();

	typedef SignatureStore::iterator it_t;
	for (it_t it = sigs.begin(); it != sigs.end(); it++) {
		it->second.SetLoader(ldr);
		if (it->second.IsSelfSignature()) {
			selfsigs.push_back(it->first);
			if (it->second.GetCreationTime() > latest) {
				latest = it->second.GetCreationTime();
				theselfsig = it->first;
			}
		}
	}
}

const drew::UserID::SignatureStore &drew::UserID::GetSignatures() const
{
	return sigs;
}

void drew::UserID::AddSignature(const Signature &sig)
{
	sigs[sig.GetInternalID()] = sig;
}

void drew::UserID::HashData(Hash &hash) const
{
	hash.Update<uint8_t>(0xb4);
	hash.Update<uint32_t>(text.size());
	hash.Update((const uint8_t *)text.data(), text.size());
}


drew::PublicKey::PublicKey() : main(true)
{
}

drew::PublicKey::PublicKey(bool is_main) : main(is_main)
{
}

drew::PublicKey::PublicKey(const PublicKey &pub)
{
	ldr = pub.ldr;
	ver = pub.ver;
	algo = pub.algo;
	ctime = pub.ctime;
	etime = pub.etime;
	for (size_t i = 0; i < DREW_OPGP_MAX_MPIS; i++)
		mpi[i] = pub.mpi[i];
	memcpy(&keyid, &pub.keyid, sizeof(keyid));
	memcpy(&fp, &pub.fp, sizeof(fp));
	theuid = pub.theuid;
	uids = pub.uids;
	sigs = pub.sigs;
}

void drew::PublicKey::AddUserID(const UserID &uid)
{
	uids[uid.GetInternalID()] = uid;
}

void drew::PublicKey::AddSignature(const Signature &sig)
{
	sigs[sig.GetInternalID()] = sig;
}

void drew::PublicKey::Merge(const PublicKey &pub)
{
	// FIXME: implement.
}

void drew::PublicKey::Synchronize(int flags)
{
	GenerateID();

	if (ver < 2 || ver > 4)
		throw DREW_OPGP_ERR_BAD_KEY_FORMAT;

	CalculateFingerprint();
	if (ver < 4) {
		const MPI &m = mpi[0];
		memcpy(keyid, m.GetData()+m.GetByteLength()-8, 8);
		/* The key ID is the bottom 64 bits of the modulus, which is a multiple
		 * of two odd primes.  Since the product of two odd numbers is odd,
		 * check to see that the key ID has the bottom bit set.
		 */
		if (!(keyid[7] & 1))
			throw DREW_OPGP_ERR_CORRUPT_KEYID;
	}
	else
		memcpy(keyid, fp+20-8, 8);
	if (!main && uids.size())
		throw DREW_OPGP_ERR_BAD_KEY_FORMAT;
	for (size_t i = 0; i < DREW_OPGP_MAX_MPIS && mpi[i].GetByteLength(); i++) {
		mpi[i].SetLoader(ldr);
		mpi[i].GenerateID();
	}
	typedef UserIDStore::iterator uidit_t;
	for (uidit_t it = uids.begin(); it != uids.end(); it++) {
		it->second.SetLoader(ldr);
		it->second.GenerateID(*this);
		it->second.Synchronize(flags);
	}
	typedef SignatureStore::iterator sigit_t;
	for (sigit_t it = sigs.begin(); it != sigs.end(); it++) {
		it->second.SetLoader(ldr);
		it->second.GenerateID(*this);
		it->second.Synchronize(flags);
	}
	return 0;
}

const drew::PublicKey::UserIDStore &drew::PublicKey::GetUserIDs() const
{
	return uids;
}

const drew::PublicKey::SignatureStore &drew::PublicKey::GetSignatures() const
{
	return sigs;
}

const uint8_t *drew::PublicKey::GetKeyID() const
{
	return keyid;
}

const uint8_t *drew::PublicKey::GetFingerprint() const
{
	return fp;
}

void drew::PublicKey::CalculateFingerprint()
{
	if (ver < 4)
		CalculateFingerprintV3();
	else
		CalculateFingerprintV4();
}

void drew::PublicKey::CalculateFingerprintV3()
{
	Hash hash(ldr, DREW_OPGP_MDALGO_MD5);
	
	// This is probably a v3 ElGamal key. Not implemented yet.
	if (algo > 3)
		throw -DREW_ERR_NOT_IMPL;

	for (size_t i = 0; i < DREW_OPGP_MAX_MPIS; i++)
		hash.Update(mpi[i].GetData(), mpi[i].GetByteLength());
	hash.Final(fp);
}

void drew::PublicKey::CalculateFingerprintV4()
{
	Hash hash(ldr, DREW_OPGP_MDALGO_SHA1);
	HashData(hash);
	hash.Final(fp);
}

const drew::MPI *drew::PublicKey::GetMPIs() const
{
	return mpi;
}

void drew::PublicKey::SetCreationTime(time_t t)
{
	ctime = t;
}

time_t drew::PublicKey::GetCreationTime() const
{
	return ctime;
}

void drew::PublicKey::SetExpirationTime(time_t t)
{
	etime = t;
}

time_t drew::PublicKey::GetExpirationTime() const
{
	return etime;
}

int drew::PublicKey::GetVersion() const
{
	return ver;
}

int drew::PublicKey::GetAlgorithm() const
{
	return algo;
}

void drew::PublicKey::SetVersion(int v)
{
	ver = v;
}

void drew::PublicKey::SetAlgorithm(int a)
{
	algo = a;
}

void drew::PublicKey::GenerateID()
{
	Hash hash(ldr, DREW_OPGP_MDALGO_SHA256);

	HashData(hash);
	hash.Final(id);
}

void drew::PublicKey::HashData(Hash &hash) const
{
	uint8_t buf[16];
	int nmpis = 0;
	uint16_t totallen = 0;

	hash.Update<uint8_t>(0x99);
	for (int i = 0; i < DREW_OPGP_MAX_MPIS && mpi[i].GetByteLength();
			i++, nmpis++)
		totallen += mpi[i].GetByteLength();

	uint16_t len = 1 + 4 + 1 + (2 * nmpis) + totallen;
	if (ver < 4)
		len += 2;
	hash.Update<uint16_t>(len);
	hash.Update<uint8_t>(ver);
	hash.Update<uint32_t>(ctime);
	if (ver < 4)
		hash.Update<uint16_t>((etime - ctime) / 86400);
	hash.Update<uint8_t>(algo);
	for (int i = 0; i < nmpis; i++) {
		hash.Update<uint16_t>(mpi[i].GetBitLength());
		hash.Update(mpi[i].GetData(), mpi[i].GetByteLength());
	}
}

void drew::Key::Synchronize(int flags)
{
	// v3 subkeys are not allowed.
	if (main.GetVersion() < 4 && pubsubs.size())
		throw DREW_OPGP_ERR_BAD_KEY_FORMAT;
	main.SetLoader(ldr);
	main.Synchronize(flags);	
	for (size_t i = 0; i < pubsubs.size(); i++) {
		pubsubs[i].SetLoader(ldr);
		pubsubs[i].Synchronize(flags);
	}
}

const PublicKey &drew::Key::GetPublicMainKey() const
{
	return main;
}

const PrivateKey &drew::Key::GetPrivateMainKey() const
{
	return priv;
}

PublicKey &drew::Key::GetPublicMainKey()
{
	return main;
}

PrivateKey &drew::Key::GetPrivateMainKey()
{
	return priv;
}

const std::vector<PublicKey> &drew::Key::GetPublicKeys() const
{
	return pubsubs;
}

const std::vector<PrivateKey> &drew::Key::GetPrivateKeys() const
{
	return privsubs;
}

UNHIDE()

int drew_opgp_key_new(drew_opgp_key_t *key, const drew_loader_t *ldr)
{
	Key *k;
	START_FUNC();
	k = new Key(ldr);
	*key = k;
	END_FUNC();
	return 0;
}

int drew_opgp_key_free(drew_opgp_key_t *key)
{
	Key *k = reinterpret_cast<Key *>(*key);
	START_FUNC();
	delete k;
	END_FUNC();
	return 0;
}

int drew_opgp_key_clone(drew_opgp_key_t *newp, drew_opgp_key_t old)
{
	Key *oldk = reinterpret_cast<Key *>(old), *newk;
	START_FUNC();
	newk = new Key(*oldk);
	*newp = newk;
	END_FUNC();
	return 0;
}

/* Does secret material exist for this key, either in a dummy or usable form?
 * Returns 1 for true and 0 for false.
 */
int drew_opgp_key_has_secret(drew_opgp_key_t key)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Does usable secret material exist for this key? */
int drew_opgp_key_has_usable_secret(drew_opgp_key_t key)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Is the key physically capable of signing? */
int drew_opgp_key_can_sign(drew_opgp_key_t key)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Is the key physically capable of encrypting? */
int drew_opgp_key_can_encrypt(drew_opgp_key_t key)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Is the key revoked? */
int drew_opgp_key_is_revoked(drew_opgp_key_t key, int flags)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Is the key expired? */
int drew_opgp_key_is_expired(drew_opgp_key_t key, int flags)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Is the key permitted to perform all of the behaviors specified? */
int drew_opgp_key_can_do(drew_opgp_key_t key, int flags)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Returns the version of the key. */
int drew_opgp_key_get_version(drew_opgp_key_t key)
{
	return key->pub.ver;
}

int drew_opgp_key_get_type(drew_opgp_key_t key)
{
	return key->pub.algo;
}

/* Returns the number of subkeys placed in subkeys. */
int drew_opgp_key_get_subkeys(drew_opgp_key_t key, drew_opgp_key_t *subkeys)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Generate a key of type algo nbits long with order (e.g. DSA q) order bits
 * long that expires at the given time.
 */
int drew_opgp_key_generate(drew_opgp_key_t key, uint8_t algo, size_t nbits,
		size_t order, time_t expires)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_key_get_fingerprint(drew_opgp_key_t k, drew_opgp_fp_t fp)
{
	Key *key = reinterpret_cast<Key *>(k);
	START_FUNC();
	size_t len = (key->GetPublicMainKey().GetVersion() < 4) ? 16 : 20;
	memcpy(fp, key->GetPublicMainKey().GetFingerprint(), len);
	END_FUNC();
	return 0;
}

int drew_opgp_key_get_id(drew_opgp_key_t key, drew_opgp_id_t id)
{
	Key *key = reinterpret_cast<Key *>(k);
	START_FUNC();
	memcpy(id, key->GetPublicMainKey().GetInternalID(), sizeof(drew_opgp_id_t));
	END_FUNC();
	return 0;
}

int drew_opgp_key_get_keyid(drew_opgp_key_t k, drew_opgp_keyid_t keyid)
{
	Key *key = reinterpret_cast<Key *>(k);
	START_FUNC();
	memcpy(keyid, key->GetPublicMainKey().GetKeyID(),
			sizeof(drew_opgp_keyid_t));
	END_FUNC();
	return 0;
}

int drew_opgp_key_validate_signatures(drew_opgp_key_t key,
		drew_opgp_keystore_t ks)
{
	drew_opgp_key_t signer;
	for (size_t i = 0; i < key->pub.nsigs; i++) {
		csig_t *sig = key->pub.sigs+i;
		if (!drew_opgp_keystore_lookup_by_keyid(ks, &signer, 1, sig->keyid))
			continue;
		validate_signature(signer, &signer->pub, sig, 0);
	}
	for (size_t i = 0; i < key->pub.nuids; i++) {
		for (size_t j = 0; j < key->pub.uids[i].nsigs; j++) {
			csig_t *sig = key->pub.uids[i].sigs+j;
			if (!drew_opgp_keystore_lookup_by_keyid(ks, &signer, 1, sig->keyid))
				continue;
			validate_signature(signer, &signer->pub, sig, 0);
		}
	}
	return 0;
}

/* Check whether all fields are self-consistent. If they are not, make them so.
 * If they cannot be made so, return an error.
 */
int drew_opgp_key_synchronize(drew_opgp_key_t k, int flags)
{
	Key *key = reinterpret_cast<Key *>(k);
	START_FUNC();
	key->Synchronize(flags);
	END_FUNC();
	return 0;
}

static int public_load_public(pubkey_t *pub, const drew_opgp_packet_t *pkt)
{
	int res = 0;
	pub->ver = pkt->data.pubkey.ver;
	if (pub->ver < 2)
		return -DREW_OPGP_ERR_BAD_KEY_FORMAT;
	else if (pub->ver < 4) {
		const drew_opgp_packet_pubkeyv3_t *pk = &pkt->data.pubkey.data.pubkeyv3;
		pub->ctime = pk->ctime;
		pub->algo = pk->pkalgo;
		pub->etime = pk->valid_days * 86400 + pub->ctime;
		res = dup_mpi(pub->mpi, DIM(pub->mpi), pk->mpi, DIM(pk->mpi));
		if (res < 0)
			return res;
	}
	else {
		const drew_opgp_packet_pubkeyv4_t *pk = &pkt->data.pubkey.data.pubkeyv4;
		pub->ctime = pk->ctime;
		pub->algo = pk->pkalgo;
		pub->etime = -1;
		res = dup_mpi(pub->mpi, DIM(pub->mpi), pk->mpi, DIM(pk->mpi));
		if (res < 0)
			return res;
	}
	return 0;
}

static int public_load_uid(pubkey_t *pub, const drew_opgp_packet_t *pkt)
{
	cuid_t *p, *uid;
	const drew_opgp_packet_data_t *d = &pkt->data.data;
	p = realloc(pub->uids, sizeof(*p) * (pub->nuids + 1));
	if (!p)
		return -ENOMEM;
	pub->uids = p;
	uid = &pub->uids[pub->nuids];
	memset(uid, 0, sizeof(*uid));
	uid->len = d->len;
	if (!(uid->s = malloc(d->len + 1)))
		return -ENOMEM;
	memcpy(uid->s, d->data, d->len);
	uid->s[d->len] = 0;
	pub->nuids++;
	return 0;
}

static int public_load_sig(csig_t *sig, const drew_opgp_packet_sig_t *s)
{
	memset(sig, 0, sizeof(*sig));
	sig->ver = s->ver;
	if (s->ver < 4) {
		const drew_opgp_packet_sigv3_t *s3 = &s->data.sigv3;
		sig->type = s3->type;
		sig->pkalgo = s3->pkalgo;
		sig->mdalgo = s3->mdalgo;
		sig->ctime = s3->ctime;
		memcpy(sig->keyid, s3->keyid, 8);
		memcpy(sig->left, s3->left, 2);
		RETFAIL(dup_mpi(sig->mpi, DIM(sig->mpi), s3->mpi, DIM(s3->mpi)));
	}
	else {
		const drew_opgp_packet_sigv4_t *s4 = &s->data.sigv4;
		sig->type = s4->type;
		sig->pkalgo = s4->pkalgo;
		sig->mdalgo = s4->mdalgo;
		RETFAIL(dup_mpi(sig->mpi, DIM(sig->mpi), s4->mpi, DIM(s4->mpi)));
		clone_subpackets(&sig->hashed, &s4->hashed);
		clone_subpackets(&sig->unhashed, &s4->unhashed);
		memcpy(sig->left, s4->left, 2);
		// We need to find the ctime.
		sig->ctime = -1;
		int nctimes = 0, nissuers = 0;
		for (size_t i = 0; i < sig->hashed.nsubpkts; i++) {
			drew_opgp_subpacket_t *sp = &sig->hashed.subpkts[i];
			if (sp->type == 2) {
				sig->ctime = 0;
				if (sp->len != 4)
					continue;
				for (int j = 0; j < 4; j++) {
					sig->ctime <<= 8;
					sig->ctime |= sp->data[j];
				}
				nctimes++;
			}
			else if (sp->type == 16) {
				if (sp->len != 8)
					continue;
				memcpy(sig->keyid, sp->data, 8);
				nissuers++;
			}
		}
		if (!nissuers) {
			for (size_t i = 0; i < sig->unhashed.nsubpkts; i++) {
				drew_opgp_subpacket_t *sp = &sig->unhashed.subpkts[i];
				if (sp->type == 16) {
					if (sp->len != 8)
						continue;
					memcpy(sig->keyid, sp->data, 8);
					nissuers++;
				}
			}
		}
		// We should have exactly one ctime and exactly one issuer.
		if (nctimes != 1 || nissuers != 1)
			sig->flags |= DREW_OPGP_SIGNATURE_INCOMPLETE;
	}
	return 0;
}

static int public_load_direct_sig(pubkey_t *pub, const drew_opgp_packet_t *pkt)
{
	csig_t *sig, *p;
	const drew_opgp_packet_sig_t *s = &pkt->data.sig;

	p = realloc(pub->sigs, sizeof(*p) * (pub->nsigs + 1));
	if (!p)
		return -ENOMEM;
	pub->sigs = p;
	sig = &pub->sigs[pub->nsigs];
	RETFAIL(public_load_sig(sig, s));
	pub->nsigs++;
	return 0;
}

static int public_load_uid_sig(pubkey_t *pub, const drew_opgp_packet_t *pkt)
{
	cuid_t *uid = &pub->uids[pub->nuids - 1];
	csig_t *sig, *p;
	const drew_opgp_packet_sig_t *s = &pkt->data.sig;

	p = realloc(uid->sigs, sizeof(*p) * (uid->nsigs + 1));
	if (!p)
		return -ENOMEM;
	uid->sigs = p;
	sig = &uid->sigs[uid->nsigs];
	RETFAIL(public_load_sig(sig, s));
	uid->nsigs++;
	return 0;
}

static int public_load_subkey_sig(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkt)
{
	pubkey_t *pub = &key->pubsubs[key->npubsubs-1];

	return public_load_direct_sig(pub, pkt);
}

static int public_load_subkey(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkt)
{
	pubkey_t *pub, *p;

	p = realloc(key->pubsubs, sizeof(*p) * (key->npubsubs + 1));
	if (!p)
		return -ENOMEM;
	memset(p+key->npubsubs, 0, sizeof(*p));
	key->pubsubs = p;
	pub = &key->pubsubs[key->npubsubs];
	RETFAIL(public_load_public(pub, pkt));
	key->npubsubs++;
	return 0;
}

/* Load a key from a series of packets.  Returns the number of packets
 * processed.
 */
int drew_opgp_key_load_public(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts)
{
	ssize_t i = 0;
	int state = 0, res = 0;
	pubkey_t *pub = &key->pub;
	pub->state &= ~DREW_OPGP_KEY_STATE_SYNCHRONIZED;
	for (i = 0; i < npkts; i++) {
		if (!state && pkts[i].type == 6) {
			res = public_load_public(pub, pkts+i);
			state = 1;
		}
		else if (state > 0 && state < 4 && pkts[i].type == 13) {
			res = public_load_uid(pub, pkts+i);
			state = 2;
		}
		else if (state > 0 && state < 4 && pkts[i].type == 17) {
			res = 0;
			state = 3;
		}
		else if (state == 1 && pkts[i].type == 2) {
			res = public_load_direct_sig(pub, pkts+i);
		}
		else if (state == 2 && pkts[i].type == 2) {
			res = public_load_uid_sig(pub, pkts+i);
		}
		else if (state == 3 && pkts[i].type == 2) {
			res = 0;
		}
		else if (state > 0 && pkts[i].type == 14) {
			res = public_load_subkey(key, pkts+i);
			state = 4;
		}
		else if (state == 4 && pkts[i].type == 2) {
			res = public_load_subkey_sig(key, pkts+i);
		}
		else
			break;	// Done with this key.
		if (res < 0)
			return res;
	}
	return i;
}

/* Load a key from a series of packets.  Returns the number of packets
 * processed.
 */
int drew_opgp_key_load_private(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts)
{
	return -DREW_ERR_NOT_IMPL;
}

/* Store a key into a series of packets.  Returns the number of packets created.
 */
int drew_opgp_key_store_public(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_key_store_private(drew_opgp_key_t key,
		const drew_opgp_packet_t *pkts, size_t npkts)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_key_get_preferences(drew_opgp_key_t key, int type,
		drew_opgp_prefs_t *prefs)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_opgp_key_get_user_ids(drew_opgp_key_t k, drew_opgp_uid_t **uids)
{
	Key *key = reinterpret_cast<Key *>(k);
	const PublicKey &pub = key->GetPublicMainKey();
	int nuids = pub.GetUserIDs().size();
	if (!uids)
		return nuids;

	drew_opgp_uid_t *p = malloc(sizeof(*p) * key->pub.nuids);
	if (!p)
		return -ENOMEM;

	for (size_t i = 0; i < key->pub.nuids; i++)
		p[i] = key->pub.uids+i;
	*uids = p;
	return nuids;
}

int drew_opgp_uid_get_text(drew_opgp_uid_t uid, const char **p)
{
	*p = uid->s;
	return 0;
}

int drew_opgp_uid_get_signatures(drew_opgp_uid_t uid, drew_opgp_sig_t **sigs)
{
	if (!sigs)
		return uid->nsigs;

	drew_opgp_sig_t *p = malloc(sizeof(*p) * uid->nsigs);
	if (!p)
		return -ENOMEM;

	for (size_t i = 0; i < uid->nsigs; i++)
		p[i] = uid->sigs+i;
	*sigs = p;
	return uid->nsigs;
}
