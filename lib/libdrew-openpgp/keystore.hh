#ifndef KEYSTORE_HH
#define KEYSTORE_HH


#include "util.hh"
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef FEATURE_TR1
#include <tr1/unordered_map>
#else
#include <map>
#endif
#include <vector>

struct drew_opgp_keystore_s;
#ifdef DREW_OPGP_BACKEND_BDB
#include <db.h>
#endif

#include <drew/drew.h>
#include <drew/mem.h>
#include <drew/plugin.h>

#include <drew-opgp/drew-opgp.h>
#include <drew-opgp/key.h>
#include <drew-opgp/keystore.h>


#include "structs.h"
#include "key.hh"

#define CHUNKSZ	64

#define DREW_OPGP_KEYSTORE_UNSYNCHRONIZED		(1 << 0)

#define TYPE_NIL	0
#define TYPE_KEY	1
#define TYPE_SIG	2
#define TYPE_UID	3
#define TYPE_SUB	4
#define TYPE_MPI	5

typedef BigEndian E;

using namespace drew;

#define ITEM_FLAG_MODIFIED	1
struct Item
{
	Item() : type(TYPE_NIL), key(0), sig(0), uid(0), pub(0), mpi(0), flags(0) {}
	explicit Item(const Key &keyp) :
		type(TYPE_KEY), key(new Key(keyp)), sig(0), uid(0), pub(0), mpi(0),
		flags(0) {}
	explicit Item(const Signature &sigp) :
		type(TYPE_SIG), key(0), sig(new Signature(sigp)), uid(0), pub(0),
		mpi(0), flags(0) {}
	explicit Item(const UserID &uidp) :
		type(TYPE_UID), key(0), sig(0), uid(new UserID(uidp)), pub(0), mpi(0),
		flags(0) {}
	explicit Item(const PublicKey &pubp) :
		type(TYPE_SUB), key(0), sig(0), uid(0), pub(new PublicKey(pubp)),
		mpi(0), flags(0) {}
	explicit Item(const MPI &mpip) :
		type(TYPE_MPI), key(0), sig(0), uid(0), pub(0), mpi(new MPI(mpip)),
		flags(0) {}
	Item(const Key &keyp, int f) :
		type(TYPE_KEY), key(new Key(keyp)), sig(0), uid(0), pub(0), mpi(0),
		flags(f) {}
	Item(const Signature &sigp, int f) :
		type(TYPE_SIG), key(0), sig(new Signature(sigp)), uid(0), pub(0),
		mpi(0), flags(f) {}
	Item(const UserID &uidp, int f) :
		type(TYPE_UID), key(0), sig(0), uid(new UserID(uidp)), pub(0), mpi(0),
		flags(f) {}
	Item(const PublicKey &pubp, int f) :
		type(TYPE_SUB), key(0), sig(0), uid(0), pub(new PublicKey(pubp)),
		mpi(0), flags(f) {}
	Item(const MPI &mpip, int f) :
		type(TYPE_MPI), key(0), sig(0), uid(0), pub(0), mpi(new MPI(mpip)),
		flags(f) {}
	Item(const Item &other)
	{
		type = other.type;
		key = other.key ? new Key(*other.key) : 0;
		sig = other.sig ? new Signature(*other.sig) : 0;
		uid = other.uid ? new UserID(*other.uid) : 0;
		pub = other.pub ? new PublicKey(*other.pub) : 0;
		mpi = other.mpi ? new MPI(*other.mpi) : 0;
	}
	Item &operator=(const Item &other)
	{
		type = other.type;
		key = other.key ? new Key(*other.key) : 0;
		sig = other.sig ? new Signature(*other.sig) : 0;
		uid = other.uid ? new UserID(*other.uid) : 0;
		pub = other.pub ? new PublicKey(*other.pub) : 0;
		mpi = other.mpi ? new MPI(*other.mpi) : 0;
		return *this;
	}
	~Item()
	{
		delete key;
		delete sig;
		delete uid;
		delete pub;
		delete mpi;
	}
	int type;
	Key *key;
	Signature *sig;
	UserID *uid;
	PublicKey *pub;
	MPI *mpi;
	int flags;
};

typedef drew::InternalID DrewID;

#ifdef FEATURE_TR1
namespace std {
	namespace tr1 {
		template<>
		struct hash<DrewID> : public unary_function<DrewID, size_t>
		{
			size_t operator()(const DrewID &id) const
			{
				return NativeEndian::Convert<size_t>(id.id);
			}
		};
	}
}

typedef std::tr1::unordered_map<DrewID, Item> ItemStore;
#else
typedef std::map<DrewID, Item> ItemStore;
#endif

typedef uint8_t chunk_t[64];

struct Chunk
{
	Chunk()
	{
		Reset();
	}
	void Reset()
	{
		memset(chunk, 0, sizeof(chunk));
	}
	operator uint8_t *()
	{
		return chunk;
	}
	uint8_t &operator[](int offset)
	{
		return chunk[offset];
	}
	operator const uint8_t *() const
	{
		return chunk;
	}
	const uint8_t &operator[](int offset) const
	{
		return chunk[offset];
	}
	chunk_t chunk;
};

struct KeyChunk : public Chunk
{
	KeyChunk()
	{
		this->Reset();
	}
};

class IDConverter
{
	public:
		void Add(DrewID id)
		{
			ids.push_back(id);
		}
		// Assumes that c is large enough and that ids.size() is even.
		void ToChunks(Chunk *c)
		{
			for (size_t i = 0, j = 0; i < ids.size(); i += 2, j++) {
				memcpy(c[j]+0x00, ids[i+0], 0x20);
				memcpy(c[j]+0x20, ids[i+1], 0x20);
			}
		}
		size_t GetSize() const
		{
			return ids.size();
		}
	protected:
	private:
		std::vector<DrewID> ids;
};

class Backend
{
	public:
		// Is it possible to access an arbitrary item immediately upon opening?
		virtual bool IsRandomAccess() const = 0;
		virtual void Open(const char *, bool) = 0;
		virtual void Close() = 0;
		virtual int GetError() const = 0;
		virtual bool IsOpen() const = 0;
		virtual void WriteChunks(const KeyChunk &, const Chunk *, size_t) = 0;
		// If this backend is not random-access, read the next key chunk.
		// Otherwise, do nothing.
		virtual void ReadKeyChunk(KeyChunk &) = 0;
		// Given the specified key chunk, read its data.  The key chunk must
		// have just been read by ReadKeyChunk.
		virtual Chunk *ReadChunks(const KeyChunk &, size_t &) = 0;
		// Given the specified key chunk, read its data.  If the backend is not
		// random-access, do nothing and return NULL.
		virtual Chunk *LoadChunks(const KeyChunk &, size_t &) = 0;
		virtual bool SetOption(const char *opturi, void *optval)
		{
			if (!strcmp(opturi,
						"http://ns.crustytoothpaste.net/drew/openpgp/backend/recovery")) {
				flags &= ~1;
				flags |= !!*static_cast<int *>(optval);
				return true;
			}
			return false;
		}
		virtual int GetFlags()
		{
			return flags;
		}
	protected:
		Backend() : flags(0) {}
		int flags;
	private:
};

class RandomAccessBackend : public Backend
{
	public:
		virtual bool IsRandomAccess() const
		{
			return true;
		}
		// Create a new transaction.
		virtual void StartTransaction()
		{
		}
		// Commit the current transaction.
		virtual void CommitTransaction()
		{
		}
		// Destroy the current transaction.
		virtual void EndTransaction()
		{
		}
	protected:
	private:
};

struct drew_opgp_keystore_s {
	int major, minor;
	int flags;
	const drew_loader_t *ldr;
	Backend *b;
	ItemStore items;
};

#define CHUNK_TYPE_HEADER			0xbc
#define CHUNK_TYPE_ID				0xbd
#define CHUNK_TYPE_FP16				0xbe
#define CHUNK_TYPE_FP20				0xbf

#define CHUNK_HEADER_CONSTANT		0xdb

#define CHUNK_ID_PUBKEY				0x69
#define CHUNK_ID_PUBSUBKEY			0x6a
#define CHUNK_ID_UID				0x6b
#define CHUNK_ID_SIG				0x6c
#define CHUNK_ID_MPI				0x6d

#ifdef DREW_OPGP_BACKEND_BDB
class BerkeleyDBBackend : public RandomAccessBackend
{
	public:
		BerkeleyDBBackend();
		~BerkeleyDBBackend();
		virtual bool IsRandomAccess() const;
		virtual void Open(const char *filename, bool write);
		virtual void Close();
		virtual int GetError() const;
		virtual bool IsOpen() const;
		virtual void WriteChunks(const KeyChunk &k, const Chunk *c,
				size_t nchunks);
		virtual void ReadKeyChunk(KeyChunk &k);
		virtual Chunk *ReadChunks(const KeyChunk &k, size_t &nchunks);
		virtual Chunk *LoadChunks(const KeyChunk &k, size_t &nchunks);
		virtual void StartTransaction();
		virtual void CommitTransaction();
		virtual void EndTransaction();
	protected:
		DB_ENV *dbenv;
		DB *dbp;
		DBC *dbc;
		DB_TXN *txn;
		int error;
	private:	
};
#endif

#endif
