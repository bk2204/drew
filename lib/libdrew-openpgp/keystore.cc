#include "keystore.hh"

class FileBackend : public Backend
{
	public:
		FileBackend() : fd(-1)
		{
		}
		~FileBackend()
		{
			Close();
		}
		virtual bool IsRandomAccess() const
		{
			return false;
		}
		virtual void Open(const char *filename, bool write)
		{
			if (write) {
				if ((fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0)
					error = -errno;
			}
			else if ((fd = open(filename, O_RDONLY)) < 0)
				error = -errno;
		}
		virtual void Close()
		{
			if (fd >= 0)
				close(fd);
			fd = -1;
		}
		virtual int GetError() const
		{
			return error;
		}
		virtual bool IsOpen() const
		{
			return fd >= 0;
		}
		virtual void WriteChunks(const KeyChunk &k, const Chunk *c,
				size_t nchunks)
		{
			write(fd, k.chunk, sizeof(k.chunk));
			for (size_t i = 0; i < nchunks; i++)
				write(fd, c[i].chunk, sizeof(c[i].chunk));
		}
		virtual void ReadKeyChunk(KeyChunk &k)
		{
			ssize_t res;
			res = read(fd, k.chunk, sizeof(k.chunk));
			if (res < 0)
				throw -errno;
			if (!res)
				throw 0;
		}
		virtual Chunk *ReadChunks(const KeyChunk &k, size_t &nchunks)
		{
			Chunk c, *cp;
			read(fd, c.chunk, sizeof(c.chunk));
			nchunks = E::Convert<uint32_t>(c.chunk) + 1;
			cp = new Chunk[nchunks];
			cp[0] = c;
			for (size_t i = 1; i < nchunks; i++)
				read(fd, cp[i], sizeof(cp[i].chunk));
			return cp;
		}
	protected:
		int fd;
		int error;
	private:	
};

EXPORT()
extern "C"
int drew_opgp_keystore_new(drew_opgp_keystore_t *ksp, const drew_loader_t *ldr)
{
	drew_opgp_keystore_t ks;
	ks = new drew_opgp_keystore_s;
	if (!ks)
		return -ENOMEM;

	ks->ldr = ldr;
	ks->major = 0x00;
	ks->minor = 0x01;
	ks->b = 0;
	*ksp = ks;
	return 0;
}

extern "C"
int drew_opgp_keystore_free(drew_opgp_keystore_t *ksp)
{
	drew_opgp_keystore_t ks = *ksp;
	delete ks->b;
	delete ks;
	*ksp = 0;
	return 0;
}

extern "C"
int drew_opgp_keystore_set_backend(drew_opgp_keystore_t ks, const char *backend)
{
	delete ks->b;
	ks->b = 0;
	if (!strcmp(backend, "file"))
		ks->b = new FileBackend;
	else if (!strcmp(backend, "bdb")) {
#ifdef DREW_OPGP_BACKEND_BDB
		ks->b = new BerkeleyDBBackend;
#else
		return -DREW_ERR_NOT_IMPL;
#endif
	}
	else
		return -DREW_ERR_INVALID;
	return 0;
}
UNEXPORT()

#define ROUND(x) (DivideAndRoundUp(x, 2))

template<class T>
size_t GetNumberOfMPIs(const T &x)
{
	size_t nmpis = 0;
	for (size_t i = 0; i < DREW_OPGP_MAX_MPIS &&
			x.GetMPIs()[i].GetByteLength(); i++, nmpis++);
	return nmpis;
}

/* There is intentionally no external documentation for this format.  Because
 * the format includes precomputed information, like whether a signature is
 * valid, it should not be read and written by external programs.
 *
 * The first chunk of each item starts with a 32-byte unique identifier field.
 * This is followed by a byte indicating the meaning of this field, whether the
 * field is an internal SHA-256 ID, a zero-padded 16- or 20-byte fingerprint, or
 * the special header (which is always all-zero).
 * 
 * All of the first chunk must be predictable, because this chunk will be stored
 * as the key in a database.  Other statistical and structural information must
 * be stored in the immediately following chunk, the info chunk.  For
 * efficiency, all 16-bit and 32-bit numbers are stored 4-byte aligned, and
 * 64-bit numbers are stored 8-byte aligned (including OpenPGP key IDs).  All
 * data is big-endian.
 */
static void store_pubkey(drew_opgp_keystore_t ks, const drew_opgp_id_t id,
		const Key *key, const PublicKey &pub, int type, size_t npubsubs)
{
	KeyChunk fchunk;
	memcpy(fchunk, id, sizeof(drew_opgp_id_t));
	fchunk[0x20] = CHUNK_TYPE_ID;
	fchunk[0x21] = type;
	fchunk[0x22] = ks->major;
	fchunk[0x23] = ks->minor;

	const PublicKey::UserIDStore &uidstore = pub.GetUserIDs();
	const PublicKey::SignatureStore &sigstore = pub.GetSignatures();

	uint32_t nmpis = GetNumberOfMPIs(pub);
	uint32_t nchunks = ROUND(uidstore.size()) + ROUND(sigstore.size()) +
		ROUND(npubsubs) + ROUND(nmpis);
	Chunk *c = new Chunk[nchunks + 1];
	// Number of subsequent chunks.
	E::Convert(c[0], nchunks);
	E::Convert<uint16_t>(c[0]+0x04, pub.GetFlags());
	c[0][0x06] = pub.GetVersion();
	c[0][0x07] = pub.GetAlgorithm();
	E::Convert<uint32_t>(c[0]+0x08, pub.GetCreationTime());
	E::Convert<uint32_t>(c[0]+0x0c, pub.GetExpirationTime());
	E::Convert<uint32_t>(c[0]+0x10, uidstore.size());
	E::Convert<uint32_t>(c[0]+0x14, sigstore.size());
	memcpy(c[0]+0x18, pub.GetKeyID(), 8);
	memcpy(c[0]+0x20, pub.GetFingerprint(), (pub.GetVersion() == 4 ? 20 : 16));
	E::Convert<uint32_t>(c[0]+0x34, npubsubs);
	E::Convert<uint32_t>(c[0]+0x38, nmpis);

	IDConverter idc;
	typedef PublicKey::UserIDStore::const_iterator uidit_t;
	typedef PublicKey::SignatureStore::const_iterator sigit_t;
	// Write the primary UID ID first, followed by the others.
	if (uidstore.size() && pub.GetPrimaryUserID())
		idc.Add(pub.GetPrimaryUserID());
	for (uidit_t it = uidstore.begin(); it != uidstore.end(); it++)
		if (pub.GetPrimaryUserID() != it->first)
			idc.Add(it->first);
	if (uidstore.size() & 1)
		idc.Add(DrewID());

	for (sigit_t it = sigstore.begin(); it != sigstore.end(); it++)
		idc.Add(it->first);
	if (sigstore.size() & 1)
		idc.Add(DrewID());

	if (npubsubs) {
		const std::vector<PublicKey> &pubstore = key->GetPublicKeys();
		for (size_t i = 0; i < npubsubs; i++)
			idc.Add(pubstore[i].GetInternalID());
		if (npubsubs & 1)
			idc.Add(DrewID());
	}

	for (size_t i = 0; i < nmpis; i++)
		idc.Add(pub.GetMPIs()[i].GetInternalID());
	if (nmpis & 1)
		idc.Add(DrewID());

	idc.ToChunks(c+1);
	ks->b->WriteChunks(fchunk, c, nchunks+1);
	delete[] c;
}

static void store_subkey(drew_opgp_keystore_t ks, const drew_opgp_id_t id,
		const PublicKey *pub)
{
	if (!pub)
		return;
	store_pubkey(ks, id, NULL, *pub, CHUNK_ID_PUBSUBKEY, 0);
}

static void store_key(drew_opgp_keystore_t ks, const drew_opgp_id_t id,
		const Key *key)
{
	if (!key)
		return;
	store_pubkey(ks, id, key, key->GetPublicMainKey(), CHUNK_ID_PUBKEY,
			key->GetPublicKeys().size());
}

static void store_mpi(drew_opgp_keystore_t ks, const drew_opgp_id_t id,
		const MPI *mpi)
{
	if (!mpi)
		return;
	KeyChunk fchunk;
	memcpy(fchunk, id, sizeof(drew_opgp_id_t));
	fchunk[0x20] = CHUNK_TYPE_ID;
	fchunk[0x21] = CHUNK_ID_MPI;
	fchunk[0x22] = ks->major;
	fchunk[0x23] = ks->minor;

	uint32_t nbytes = mpi->GetByteLength();
	uint32_t nchunks = DivideAndRoundUp(nbytes, 0x40);
	Chunk *c = new Chunk[nchunks + 1];
	// Number of subsequent chunks.
	E::Convert(c[0], nchunks);
	E::Convert<uint32_t>(c[0]+0x04, mpi->GetBitLength());
	E::Convert<uint32_t>(c[0]+0x08, nbytes);

	for (size_t i = 1, off = 0; i <= nchunks; i++, off += 0x40)
		memcpy(c[i], mpi->GetData()+off, std::min<size_t>(0x40, nbytes-off));
	ks->b->WriteChunks(fchunk, c, nchunks+1);
	delete[] c;
}

static void store_subpackets1(Chunk *c, const drew_opgp_subpacket_group_t *spg,
		size_t &off, size_t &offset)
{
	for (size_t i = 0; i < spg->nsubpkts; i++, offset += 0x4) {
		if (offset == 0x40) {
			off++;
			offset = 0x00;
		}
		E::Convert<uint16_t>(c[off]+offset+0x00, spg->subpkts[i].len);
		c[off][offset+0x02] = spg->subpkts[i].type |
			(spg->subpkts[i].critical ? 0x80 : 0);
		c[off][offset+0x03] = spg->subpkts[i].lenoflen;
	}
	if (offset)
		off++;
	offset = 0x00;
}

static void store_subpackets2(Chunk *c, const drew_opgp_subpacket_group_t *spg,
		size_t &off)
{
	for (size_t j = 0; j < spg->nsubpkts; j++)
		for (size_t i = off, offset = 0; offset < spg->subpkts[j].len;
				i++, offset += 0x40)
			memcpy(c[i], spg->subpkts[j].data+offset,
					std::min<size_t>(0x40, spg->subpkts[j].len-offset));
}

static void store_subpackets3(Chunk *c, const drew_opgp_subpacket_group_t *spg,
		size_t &off)
{
	for (size_t i = off, offset = 0; offset < spg->len;
			i++, offset += 0x40)
		memcpy(c[i], spg->data+offset, std::min<size_t>(0x40, spg->len-offset));
}

static void store_sig(drew_opgp_keystore_t ks, const drew_opgp_id_t id,
		const Signature *sig)
{
	if (!sig)
		return;
	KeyChunk fchunk;
	memcpy(fchunk, id, sizeof(drew_opgp_id_t));
	fchunk[0x20] = CHUNK_TYPE_ID;
	fchunk[0x21] = CHUNK_ID_SIG;
	fchunk[0x22] = ks->major;
	fchunk[0x23] = ks->minor;

	uint32_t nmpis = GetNumberOfMPIs(*sig);
	uint32_t hchunks = 0, uchunks = 0;
	const drew_opgp_subpacket_group_t &hashed = sig->GetHashedSubpackets();
	const drew_opgp_subpacket_group_t &unhashed = sig->GetUnhashedSubpackets();
	const selfsig_t &selfsig = sig->GetSelfSignature();
	for (size_t i = 0; i < hashed.nsubpkts; i++)
		hchunks += DivideAndRoundUp(hashed.subpkts[i].len, 0x40);
	for (size_t i = 0; i < unhashed.nsubpkts; i++)
		uchunks += DivideAndRoundUp(unhashed.subpkts[i].len, 0x40);
	uint32_t nhashedlens = DivideAndRoundUp(hashed.nsubpkts * 4, 0x40);
	uint32_t nunhashedlens = DivideAndRoundUp(unhashed.nsubpkts * 4, 0x40);
	uint32_t nhashed = DivideAndRoundUp(hashed.len, 0x40);
	uint32_t nunhashed = DivideAndRoundUp(unhashed.len, 0x40);
	uint32_t nchunks = nhashedlens + nunhashedlens + nhashed + nunhashed +
		hchunks + uchunks + ROUND(nmpis) + 3;
	Chunk *c = new Chunk[nchunks + 2];
	// Number of subsequent chunks.
	E::Convert(c[0], nchunks + 1);
	c[0][0x04] = sig->GetVersion();
	c[0][0x05] = sig->GetType();
	c[0][0x06] = sig->GetPublicKeyAlgorithm();
	c[0][0x07] = sig->GetDigestAlgorithm();
	E::Convert<uint32_t>(c[0]+0x08, sig->GetCreationTime());
	E::Convert<uint32_t>(c[0]+0x0c, sig->GetExpirationTime());
	memcpy(c[0]+0x10, sig->GetKeyID(), 8);
	E::Convert<uint32_t>(c[0]+0x18, sig->GetFlags());
	E::Convert<uint32_t>(c[0]+0x20, selfsig.keyflags);
	E::Convert<uint32_t>(c[0]+0x24, selfsig.keyexp);
	c[0][0x28] = sig->GetLeft2()[0];
	c[0][0x29] = sig->GetLeft2()[1];
	// Two empty bytes.
	c[0][0x2c] = selfsig.prefs[0].len;
	c[0][0x2d] = selfsig.prefs[1].len;
	c[0][0x2e] = selfsig.prefs[2].len;
	c[0][0x2f] = nmpis;
	E::Convert<uint32_t>(c[0]+0x30, hashed.nsubpkts);
	E::Convert<uint32_t>(c[0]+0x34, unhashed.nsubpkts);
	E::Convert<uint32_t>(c[0]+0x38, hashed.len);
	E::Convert<uint32_t>(c[0]+0x3c, unhashed.len);

	memcpy(c[1], sig->GetHash(), 0x40);

	size_t off = 2, offset = 0;
	store_subpackets1(c, &hashed, off, offset);
	store_subpackets1(c, &unhashed, off, offset);

	store_subpackets2(c, &hashed, off);
	store_subpackets2(c, &unhashed, off);

	store_subpackets3(c, &hashed, off);
	store_subpackets3(c, &unhashed, off);

	for (size_t i = 0; i < 3; i++, off++)
		memcpy(c[off], selfsig.prefs[i].vals,
				sizeof(selfsig.prefs[i].vals));

	IDConverter idc;
	for (size_t i = 0; i < nmpis; i++)
		idc.Add(DrewID(sig->GetMPIs()[i].GetInternalID()));
	if (nmpis & 1)
		idc.Add(DrewID());

	idc.ToChunks(c+off);
	ks->b->WriteChunks(fchunk, c, nchunks+2);
	delete[] c;
}

static void store_uid(drew_opgp_keystore_t ks, const drew_opgp_id_t id,
		const UserID *uid)
{
	if (!uid)
		return;
	KeyChunk fchunk;
	memcpy(fchunk, id, sizeof(drew_opgp_id_t));
	fchunk[0x20] = CHUNK_TYPE_ID;
	fchunk[0x21] = CHUNK_ID_UID;
	fchunk[0x22] = ks->major;
	fchunk[0x23] = ks->minor;

	typedef UserID::SignatureStore::const_iterator sigit_t;
	typedef UserID::SelfSignatureStore::const_iterator ssigit_t;
	const UserID::SignatureStore &sigstore = uid->GetSignatures();
	const UserID::SelfSignatureStore &selfsigstore = uid->GetSelfSignatures();
	uint32_t nchunks = ROUND(sigstore.size()) +
		DivideAndRoundUp(uid->GetText().size() + 1, 0x40);
	Chunk *c = new Chunk[nchunks + 1];
	// Number of subsequent chunks.
	E::Convert(c[0], nchunks);
	E::Convert<uint32_t>(c[0]+0x04, sigstore.size());
	E::Convert<uint32_t>(c[0]+0x08, selfsigstore.size());
	E::Convert<uint32_t>(c[0]+0x0c, uid->GetText().size());

	IDConverter idc;
	const InternalID &theselfsig = uid->GetPrimarySelfSignature();
	if (theselfsig && sigstore.size())
		idc.Add(theselfsig);

	for (ssigit_t it = selfsigstore.begin(); it != selfsigstore.end(); it++)
		if (theselfsig != *it)
			idc.Add(*it);

	for (sigit_t it = sigstore.begin(); it != sigstore.end(); it++) {
		bool found = false;
		for (ssigit_t sit = selfsigstore.begin(); sit != selfsigstore.end();
				sit++)
			if (it->first == *sit) {
				found = true;
				break;
			}
		if (!found)
			idc.Add(it->first);
	}
	if (sigstore.size() & 1)
		idc.Add(DrewID());

	const std::string &text = uid->GetText();
	for (size_t i = ROUND(sigstore.size()) + 1, off = 0; i <= nchunks;
			i++, off += 0x40)
		memcpy(c[i], text.c_str()+off,
				std::min<size_t>(0x40, (text.size()+1)-off));

	idc.ToChunks(c+1);
	ks->b->WriteChunks(fchunk, c, nchunks+1);
	delete[] c;
}

static void set_header(drew_opgp_keystore_t ks, KeyChunk &chunk)
{
	chunk[0x20] = CHUNK_TYPE_HEADER;
	chunk[0x21] = CHUNK_HEADER_CONSTANT;
	chunk[0x22] = ks->major;
	chunk[0x23] = ks->minor;
	chunk[0x28] = 'D';
	chunk[0x29] = 'r';
	chunk[0x2a] = 'e';
	chunk[0x2b] = 'w';
	// Special signature.  Left part of the SHA-256 value of
	// "\xbc\xdb\x00\x00DrewEngine".
	chunk[0x30] = 0x6d;
	chunk[0x31] = 0x86;
	chunk[0x32] = 0x6b;
	chunk[0x33] = 0x1a;
	chunk[0x34] = 0xa1;
	chunk[0x35] = 0xb3;
	chunk[0x36] = 0x03;
	chunk[0x37] = 0x96;
	chunk[0x38] = 0x2f;
	chunk[0x39] = 0x54;
	chunk[0x3a] = 0x56;
	chunk[0x3b] = 0x38;
	chunk[0x3c] = 0xf8;
	chunk[0x3d] = 0x4c;
	chunk[0x3e] = 0x01;
	chunk[0x3f] = 0x6f;
}

static int load_header(drew_opgp_keystore_t ks)
{
	KeyChunk chunk, k;
	set_header(ks, k);
	ks->b->ReadKeyChunk(chunk);
	return memcmp(k.chunk, chunk.chunk, sizeof(k.chunk)) ? -DREW_ERR_INVALID :
		0;
}

static void store_header(drew_opgp_keystore_t ks)
{
	KeyChunk chunk;
	set_header(ks, chunk);
	ks->b->WriteChunks(chunk, 0, 0);
}

static int load_pubkey(drew_opgp_keystore_t ks, PublicKey *pub,
		Key *key, const Chunk &kchunk, const Chunk *c,
		size_t nchunks, drew_opgp_id_t missingid)
{
	pub->SetInternalID(kchunk);

	uint32_t nmpis = 0, npubsubs = 0, nuids = 0, nsigs = 0;
	pub->GetFlags() = E::Convert<uint16_t>(c[0]+0x04);
	pub->SetVersion(c[0][0x06]);
	pub->SetAlgorithm(c[0][0x07]);
	pub->SetCreationTime(E::Convert<uint32_t>(c[0]+0x08));
	pub->SetExpirationTime(E::Convert<uint32_t>(c[0]+0x0c));
	nuids = E::Convert<uint32_t>(c[0]+0x10);
	nsigs = E::Convert<uint32_t>(c[0]+0x14);
	memcpy(pub->GetKeyID(), c[0]+0x18, 8);
	memcpy(pub->GetFingerprint(), c[0]+0x20, pub->GetVersion() == 4 ? 20 : 16);
	npubsubs = E::Convert<uint32_t>(c[0]+0x34);
	nmpis = E::Convert<uint32_t>(c[0]+0x38);

	size_t off = 1, offset = 0x00;
	for (size_t i = 0; i < nuids; i++, offset += 0x20) {
		if (offset == 0x40) {
			off++;
			offset = 0x00;
		}
		DrewID id(c[off]+offset);
		Item &item = ks->items[id];
		if (!item.uid) {
			memcpy(missingid, c[off]+offset, sizeof(drew_opgp_id_t));
			return -DREW_ERR_MORE_INFO;
		}
		if (!i)
			pub->SetPrimaryUserID(id);
		pub->GetUserIDs()[id] = *item.uid;
	}

	if (offset)
		off++;
	offset = 0x00;

	for (size_t i = 0; i < nsigs; i++, offset += 0x20) {
		if (offset == 0x40) {
			off++;
			offset = 0x00;
		}
		DrewID id(c[off]+offset);
		Item &item = ks->items[id];
		if (!item.sig) {
			memcpy(missingid, c[off]+offset, sizeof(drew_opgp_id_t));
			return -DREW_ERR_MORE_INFO;
		}
		pub->GetSignatures()[id] = *item.sig;
	}

	if (offset)
		off++;
	offset = 0x00;

	for (size_t i = 0; i < npubsubs; i++, offset += 0x20) {
		if (offset == 0x40) {
			off++;
			offset = 0x00;
		}
		DrewID id(c[off]+offset);
		Item &item = ks->items[id];
		if (!item.pub) {
			memcpy(missingid, c[off]+offset, sizeof(drew_opgp_id_t));
			return -DREW_ERR_MORE_INFO;
		}
		key->GetPublicKeys().push_back(*item.pub);
	}

	if (offset)
		off++;
	offset = 0x00;

	for (size_t i = 0, offset = 0; i < nmpis; i++, offset += 0x20) {
		if (offset == 0x40) {
			off++;
			offset = 0x00;
		}
		DrewID id(c[off]+offset);
		Item &item = ks->items[id];
		if (!item.mpi) {
			memcpy(missingid, c[off]+offset, sizeof(drew_opgp_id_t));
			return -DREW_ERR_MORE_INFO;
		}
		pub->GetMPIs()[i] = *item.mpi;
	}

	pub->SetInternalID(kchunk);
	return 0;
}

static int load_key(drew_opgp_keystore_t ks, const Chunk &kchunk,
		const Chunk *c, size_t nchunks, drew_opgp_id_t missingid)
{
	Key key;
	PublicKey &pub = key.GetPublicMainKey();
	key.SetLoader(ks->ldr);
	pub.SetLoader(ks->ldr);
	RETFAIL(load_pubkey(ks, &pub, &key, kchunk, c, nchunks, missingid));
	pub.SetIsMainPublicKey(true);
	ks->items[pub.GetInternalID()] = Item(key);
	return 0;
}

static int load_subkey(drew_opgp_keystore_t ks, const Chunk &key,
		const Chunk *c, size_t nchunks, drew_opgp_id_t missingid)
{
	PublicKey pub;
	pub.SetLoader(ks->ldr);
	RETFAIL(load_pubkey(ks, &pub, 0, key, c, nchunks, missingid));
	pub.SetIsMainPublicKey(false);
	ks->items[pub.GetInternalID()] = Item(pub);
	return 0;
}

static int load_uid(drew_opgp_keystore_t ks, const Chunk &key, const Chunk *c,
		size_t nchunks, drew_opgp_id_t missingid)
{
	UserID uid;

	uid.SetLoader(ks->ldr);
	uid.SetInternalID(key);

	uint32_t nsigs = E::Convert<uint32_t>(c[0]+0x04);
	uint32_t nselfsigs = E::Convert<uint32_t>(c[0]+0x08);
	uint32_t len = E::Convert<uint32_t>(c[0]+0x0c);

	size_t off = 1, offset = 0x00;
	for (size_t i = 0; i < nsigs; i++, offset += 0x20) {
		if (offset == 0x40) {
			off++;
			offset = 0x00;
		}
		DrewID id(c[off]+offset);
		Item &item = ks->items[id];
		if (!item.sig) {
			memcpy(missingid, c[off]+offset, sizeof(drew_opgp_id_t));
			return -DREW_ERR_MORE_INFO;
		}
		if (!i)
			uid.SetPrimarySelfSignature(id);
		if (i < nselfsigs)
			uid.GetSelfSignatures().push_back(id);
		uid.GetSignatures()[id] = *item.sig;
	}
	if (offset)
		off++;
	offset = 0x00;

	std::string text;
	for (size_t i = off; offset < (len+1); i++, offset += 0x40)
		text.append((const char *)(const uint8_t *)c[i],
				std::min<size_t>(0x40, (len+1)-offset));
	text.erase(text.size()-1);

	ks->items[uid.GetInternalID()] = Item(uid);
	return 0;
}

static void load_subpackets1(drew_opgp_subpacket_group_t *spg, const Chunk *c,
		size_t &off, size_t &offset)
{
	spg->subpkts = (drew_opgp_subpacket_t *)
		drew_mem_calloc(spg->nsubpkts, sizeof(*spg->subpkts));
	for (size_t i = 0; i < spg->nsubpkts; i++, offset += 0x4) {
		if (offset == 0x40) {
			off++;
			offset = 0x00;
		}
		spg->subpkts[i].len = E::Convert<uint16_t>(c[off]+offset+0x00);
		uint8_t type = c[off][offset+0x02];
		spg->subpkts[i].type = type & 0x7f;
		spg->subpkts[i].critical = type & 0x80;
		spg->subpkts[i].lenoflen = c[off][offset+0x03];
	}
	if (offset)
		off++;
	offset = 0x00;
}

static void load_subpackets2(drew_opgp_subpacket_group_t *spg, const Chunk *c,
		size_t &off)
{
	for (size_t j = 0; j < spg->nsubpkts; j++) {
		spg->subpkts[j].data = (uint8_t *)drew_mem_malloc(spg->subpkts[j].len);
		for (size_t i = off, offset = 0; offset < spg->subpkts[j].len;
				i++, offset += 0x40)
			memcpy(spg->subpkts[j].data+offset, c[i],
					std::min<size_t>(0x40, spg->subpkts[j].len-offset));
	}
}

static void load_subpackets3(drew_opgp_subpacket_group_t *spg, const Chunk *c,
		size_t &off)
{
	spg->data = (uint8_t *)drew_mem_malloc(spg->len);
	for (size_t i = off, offset = 0; offset < spg->len;
			i++, offset += 0x40)
		memcpy(spg->data+offset, c[i], std::min<size_t>(0x40, spg->len-offset));
}

static int load_sig(drew_opgp_keystore_t ks, const Chunk &key, const Chunk *c,
		size_t nchunks, drew_opgp_id_t missingid)
{
	Signature sig;

	sig.SetLoader(ks->ldr);
	sig.SetInternalID(key);

	selfsig_t &selfsig = sig.GetSelfSignature();
	drew_opgp_subpacket_group_t &hashed = sig.GetHashedSubpackets();
	drew_opgp_subpacket_group_t &unhashed = sig.GetUnhashedSubpackets();

	uint32_t nmpis = 0;
	// Number of subsequent chunks.
	sig.SetVersion(c[0][0x04]);
	sig.SetType(c[0][0x05]);
	sig.SetPublicKeyAlgorithm(c[0][0x06]);
	sig.SetDigestAlgorithm(c[0][0x07]);
	sig.SetCreationTime(E::Convert<uint32_t>(c[0]+0x08));
	sig.SetExpirationTime(E::Convert<uint32_t>(c[0]+0x0c));
	memcpy(sig.GetKeyID(), c[0]+0x10, 8);
	sig.GetFlags() = E::Convert<uint32_t>(c[0]+0x18);
	selfsig.keyflags = E::Convert<uint32_t>(c[0]+0x20);
	selfsig.keyexp = E::Convert<uint32_t>(c[0]+0x24);
	sig.GetLeft2()[0] = c[0][0x28];
	sig.GetLeft2()[1] = c[0][0x29];
	// Two empty bytes.
	selfsig.prefs[0].len = c[0][0x2c];
	selfsig.prefs[1].len = c[0][0x2d];
	selfsig.prefs[2].len = c[0][0x2e];
	nmpis = c[0][0x2f];
	hashed.nsubpkts = E::Convert<uint32_t>(c[0]+0x30);
	unhashed.nsubpkts = E::Convert<uint32_t>(c[0]+0x34);
	hashed.len = E::Convert<uint32_t>(c[0]+0x38);
	unhashed.len = E::Convert<uint32_t>(c[0]+0x3c);

	memcpy(sig.GetHash(), c[1], 0x40);

	size_t off = 2, offset = 0;
	load_subpackets1(&hashed, c, off, offset);
	load_subpackets1(&unhashed, c, off, offset);

	load_subpackets2(&hashed, c, off);
	load_subpackets2(&unhashed, c, off);

	load_subpackets3(&hashed, c, off);
	load_subpackets3(&unhashed, c, off);

	for (size_t i = 0; i < 3; i++, off++)
		memcpy(selfsig.prefs[i].vals, c[off], sizeof(selfsig.prefs[i].vals));

	for (size_t i = 0, offset = 0; i < nmpis; i++, offset += 0x20) {
		if (offset == 0x40) {
			off++;
			offset = 0x00;
		}
		DrewID id(c[off]+offset);
		Item &item = ks->items[id];
		if (!item.mpi) {
			memcpy(missingid, c[off]+offset, sizeof(drew_opgp_id_t));
			return -DREW_ERR_MORE_INFO;
		}
		sig.GetMPIs()[i] = *item.mpi;
	}
	ks->items[sig.GetInternalID()] = Item(sig);
	return 0;
}

static int load_mpi(drew_opgp_keystore_t ks, const Chunk &key, const Chunk *c,
		size_t nchunks)
{
	MPI mpio;
	drew_opgp_mpi_t mpi;
	size_t nbytes = 0;

	mpio.SetLoader(ks->ldr);
	mpi.len = E::Convert<uint32_t>(c[0]+0x04);
	nbytes = E::Convert<uint32_t>(c[0]+0x08);
	mpi.data = (uint8_t *)drew_mem_malloc(nbytes);
	if (!mpi.data)
		return -ENOMEM;
	for (size_t i = 1, off = 0; i < nchunks; i++, off += 0x40)
		memcpy(mpi.data+off, c[i], std::min<size_t>(0x40, nbytes-off));
	mpio.SetMPI(mpi);
	mpio.SetInternalID(key);
	ks->items[mpio.GetInternalID()] = Item(mpio);
	return 0;
}

static int load_item(drew_opgp_keystore_t ks, const Chunk &key, const Chunk *c,
		size_t nchunks, drew_opgp_id_t missingid)
{
	if (key[0x22] != ks->major)
		return -DREW_ERR_NOT_IMPL;
	switch (key[0x21]) {
		case CHUNK_ID_MPI:
			return load_mpi(ks, key, c, nchunks);
		case CHUNK_ID_SIG:
			return load_sig(ks, key, c, nchunks, missingid);
		case CHUNK_ID_UID:
			return load_uid(ks, key, c, nchunks, missingid);
		case CHUNK_ID_PUBSUBKEY:
			return load_subkey(ks, key, c, nchunks, missingid);
		case CHUNK_ID_PUBKEY:
			return load_key(ks, key, c, nchunks, missingid);
		default:
			return -DREW_ERR_NOT_IMPL;
	}
}

EXPORT()
extern "C"
int drew_opgp_keystore_load(drew_opgp_keystore_t ks, const char *filename,
		drew_opgp_id_t missingid)
{
	int res = 0;

	ks->b->Open(filename, false);

	if (!ks->b->IsOpen())
		return ks->b->GetError();

	RETFAIL(load_header(ks));
	if (!ks->b->IsRandomAccess()) {
		for (;;) {
			KeyChunk key;
			Chunk *c = 0;
			try {
				ks->b->ReadKeyChunk(key);
				size_t nchunks;
				c = ks->b->ReadChunks(key, nchunks);
				if (key[0x20] != CHUNK_TYPE_ID) {
					delete[] c;
					continue;
				}
				if ((res = load_item(ks, key, c, nchunks, missingid))) {
					delete[] c;
					return res;
				}
				delete[] c;	
			}
			catch (int e) {
				if (c)
					delete[] c;
				if (!e)
					break; // done.
				return e;
			}
		}
	}
	else {
		return -DREW_ERR_NOT_IMPL;
	}
	return 0;
}

extern "C"
int drew_opgp_keystore_store(drew_opgp_keystore_t ks, const char *filename)
{
	ks->b->Open(filename, true);

	if (!ks->b->IsOpen())
		return ks->b->GetError();

	store_header(ks);
	typedef ItemStore::iterator it_t;
	if (!ks->b->IsRandomAccess()) {
		// Because we need references to items to be resolvable, we store MPIs
		// first, then signatures, then user IDs, then pubkeys, and then keys.
		for (it_t it = ks->items.begin(); it != ks->items.end(); it++)
			store_mpi(ks, it->first.id, it->second.mpi);
		for (it_t it = ks->items.begin(); it != ks->items.end(); it++)
			store_sig(ks, it->first.id, it->second.sig);
		for (it_t it = ks->items.begin(); it != ks->items.end(); it++)
			store_uid(ks, it->first.id, it->second.uid);
		for (it_t it = ks->items.begin(); it != ks->items.end(); it++)
			store_subkey(ks, it->first.id, it->second.pub);
		for (it_t it = ks->items.begin(); it != ks->items.end(); it++)
			store_key(ks, it->first.id, it->second.key);
	}
	else {
		// We can efficiently access any arbitrary record, so use a one-pass
		// algorithm.
		for (it_t it = ks->items.begin(); it != ks->items.end(); it++) {
			store_mpi(ks, it->first.id, it->second.mpi);
			store_sig(ks, it->first.id, it->second.sig);
			store_uid(ks, it->first.id, it->second.uid);
			store_subkey(ks, it->first.id, it->second.pub);
			store_key(ks, it->first.id, it->second.key);
		}
	}
	return 0;
}

extern "C"
int drew_opgp_keystore_flush(drew_opgp_keystore_t ks, const char *filename)
{
	RETFAIL(drew_opgp_keystore_store(ks, filename));
	ks->items.clear();
	return 0;
}

extern "C"
int drew_opgp_keystore_update_sigs(drew_opgp_keystore_t ks,
		drew_opgp_sig_t *sigs, size_t nsigs, int flags)
{
	for (size_t i = 0; i < nsigs; i++) {
		Signature *sig = reinterpret_cast<Signature *>(sigs[i]);
		ks->items[sig->GetInternalID()] = Item(*sig);
		MPI *mpi = sig->GetMPIs();
		for (size_t j = 0; j < DREW_OPGP_MAX_MPIS && mpi[j].GetByteLength();
				j++)
			ks->items[mpi[j].GetInternalID()] = Item(mpi[j]);
	}
	return 0;
}

extern "C"
int drew_opgp_keystore_update_sig(drew_opgp_keystore_t ks, drew_opgp_sig_t sig,
		int flags)
{
	return drew_opgp_keystore_update_sigs(ks, &sig, 1, flags);
}

extern "C"
int drew_opgp_keystore_update_user_ids(drew_opgp_keystore_t ks,
		drew_opgp_uid_t *uids, size_t nuids, int flags)
{
	for (size_t i = 0; i < nuids; i++) {
		UserID *uid = reinterpret_cast<UserID *>(uids[i]);
		ks->items[uid->GetInternalID()] = Item(*uid);
		UserID::SignatureStore &sigs = uid->GetSignatures();
		typedef UserID::SignatureStore::iterator sigit_t;
		for (sigit_t it = sigs.begin(); it != sigs.end(); it++)
			drew_opgp_keystore_update_sig(ks, &it->second, flags);
	}
	return 0;
}

extern "C"
int drew_opgp_keystore_update_user_id(drew_opgp_keystore_t ks,
		drew_opgp_uid_t uid, int flags)
{
	return drew_opgp_keystore_update_user_ids(ks, &uid, 1, flags);
}

extern "C"
int drew_opgp_keystore_add_keys(drew_opgp_keystore_t ks,
		drew_opgp_key_t *keys, size_t nkeys, int flags)
{
	for (size_t i = 0; i < nkeys; i++)
		ks->items.insert(std::pair<DrewID, Item>(keys[i]->GetPublicMainKey().GetInternalID(), Item(*keys[i])));
	return 0;
}

extern "C"
int drew_opgp_keystore_add_key(drew_opgp_keystore_t ks, drew_opgp_key_t key,
		int flags)
{
	return drew_opgp_keystore_add_keys(ks, &key, 1, flags);
}
UNEXPORT()

static void update_pubkeys(drew_opgp_keystore_t ks, PublicKey *pub, int flags)
{
	ks->items[pub->GetInternalID()] = Item(*pub);
	MPI *mpi = pub->GetMPIs();
	for (size_t i = 0; i < DREW_OPGP_MAX_MPIS && mpi[i].GetByteLength(); i++)
		ks->items[mpi[i].GetInternalID()] = Item(mpi[i]);
	PublicKey::SignatureStore &sigs = pub->GetSignatures();
	typedef PublicKey::SignatureStore::iterator sigit_t;
	for (sigit_t it = sigs.begin(); it != sigs.end(); it++)
		drew_opgp_keystore_update_sig(ks, &it->second, flags);
}

EXPORT()
extern "C"
int drew_opgp_keystore_update_keys(drew_opgp_keystore_t ks,
		drew_opgp_key_t *keys, size_t nkeys, int flags)
{
	for (size_t i = 0; i < nkeys; i++) {
		Key *key = keys[i];
		PublicKey &pub = key->GetPublicMainKey();
		ks->items[pub.GetInternalID()] = Item(*key);
		std::vector<PublicKey> &pubs = key->GetPublicKeys();
		size_t npubsubs = pubs.size();
		size_t nmpis = GetNumberOfMPIs(pub);
		MPI *mpi = pub.GetMPIs();
		PublicKey::UserIDStore &uidstore = pub.GetUserIDs();
		PublicKey::SignatureStore &sigstore = pub.GetSignatures();
		for (size_t j = 0; j < npubsubs; j++)
			update_pubkeys(ks, &pubs[j], flags);
		for (PublicKey::UserIDStore::iterator it = uidstore.begin();
				it != uidstore.end(); it++)
			drew_opgp_keystore_update_user_id(ks, &it->second, flags);
		for (PublicKey::SignatureStore::iterator it = sigstore.begin();
				it != sigstore.end(); it++)
			drew_opgp_keystore_update_sig(ks, &it->second, flags);
		for (size_t j = 0; j < nmpis; j++)
			ks->items[mpi[j].GetInternalID()] = Item(mpi[j]);
	}
	return 0;
}

extern "C"
int drew_opgp_keystore_update_key(drew_opgp_keystore_t ks, drew_opgp_key_t key,
		int flags)
{
	return drew_opgp_keystore_update_keys(ks, &key, 1, flags);
}

extern "C"
int drew_opgp_keystore_lookup_by_id(drew_opgp_keystore_t ks,
		drew_opgp_key_t *key, drew_opgp_id_t id)
{
	ItemStore::iterator it;

	it = ks->items.find(DrewID(id));
	if (it == ks->items.end())
		return 0;
	if (key)
		*key = it->second.key;
	return 1;
}

// TODO: store a mapping from key ID to (sequence of) Drew ID in the store.
extern "C"
int drew_opgp_keystore_lookup_by_keyid(drew_opgp_keystore_t ks,
		drew_opgp_key_t *key, size_t nkeys, drew_opgp_keyid_t keyid)
{
	// TODO: look up subkeys, too.
	size_t nitems = 0;
	typedef ItemStore::iterator it_t;
	for (it_t it = ks->items.begin(); it != ks->items.end(); it++) {
		if (it->second.key) {
			Key *k = it->second.key;
			if (memcmp(k->GetPublicMainKey().GetKeyID(), keyid, 8))
				continue;
			if (key && nitems < nkeys)
				key[nitems] = it->second.key;
			nitems++;
		}
	}
	return nitems;
}

extern "C"
int drew_opgp_keystore_get_keys(drew_opgp_keystore_t ks, drew_opgp_key_t *key,
		size_t nkeys)
{
	// TODO: look up subkeys, too.
	size_t nitems = 0;
	typedef ItemStore::iterator it_t;
	for (it_t it = ks->items.begin(); it != ks->items.end(); it++) {
		if (it->second.key) {
			if (key && nitems < nkeys)
				key[nitems] = it->second.key;
			nitems++;
		}
	}
	return nitems;
}

extern "C"
int drew_opgp_keystore_check(drew_opgp_keystore_t ks, int flags)
{
	return -DREW_ERR_NOT_IMPL;
}
UNEXPORT()
UNHIDE()
