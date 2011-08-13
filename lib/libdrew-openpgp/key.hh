#ifndef KEY_HH
#define KEY_HH

#include <fcntl.h>
#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include <drew-opgp/key.h>

struct drew_opgp_pubkey_s;

namespace drew {

class Hash
{
	public:
		Hash(const drew_loader_t *ldr, int algo);
		~Hash();
		void Update(const uint8_t *, size_t);
		template<class T>
		void Update(T);
		void Final(uint8_t *);
		static const char *GetAlgorithmName(int);
		static size_t GetAlgorithmLength(int);
		static size_t GetAlgorithmPrefixLength(int);
		static const uint8_t *GetAlgorithmPrefix(int);
	protected:
	private:
		const drew_loader_t *ldr;
		drew_hash_t hash;
};

struct InternalID
{
	InternalID()
	{
		Reset();
	}
	InternalID(const drew_opgp_id_t idp)
	{
		memcpy(this->id, idp, sizeof(this->id));
	}
	bool operator <(const InternalID & kid) const
	{
		return memcmp(this->id, kid.id, sizeof(this->id)) < 0;
	}
	bool operator <=(const InternalID & kid) const
	{
		return memcmp(this->id, kid.id, sizeof(this->id)) <= 0;
	}
	bool operator >(const InternalID & kid) const
	{
		return memcmp(this->id, kid.id, sizeof(this->id)) > 0;
	}
	bool operator >=(const InternalID & kid) const
	{
		return memcmp(this->id, kid.id, sizeof(this->id)) >= 0;
	}
	bool operator ==(const InternalID & kid) const
	{
		return !memcmp(this->id, kid.id, sizeof(this->id));
	}
	bool operator !=(const InternalID & kid) const
	{
		return memcmp(this->id, kid.id, sizeof(this->id));
	}
	void Reset()
	{
		memset(id, 0, sizeof(id));
	}
	void Write(int fd)
	{
		write(fd, id, sizeof(id));
	}
	operator uint8_t *()
	{
		return id;
	}
	operator const uint8_t *() const
	{
		return id;
	}
	uint8_t &operator[](int offset)
	{
		return id[offset];
	}
	const uint8_t &operator[](int offset) const
	{
		return id[offset];
	}
	drew_opgp_id_t id;
};

class Identifiable
{
	public:
		Identifiable()
		{
			memset(id, 0, sizeof(id));
		}
		Identifiable(drew_opgp_id_t from)
		{
			SetInternalID(from);
		}
		Identifiable(const InternalID &from)
		{
			SetInternalID(from);
		}
		Identifiable(const Identifiable &other)
		{
			SetInternalID(other.id);
		}
		const InternalID &GetInternalID() const
		{
			return id;
		}
		void SetInternalID(const drew_opgp_id_t from)
		{
			memcpy(id, from, sizeof(id));
		}
		void SetInternalID(const InternalID &from)
		{
			memcpy(id, from, sizeof(id));
		}
	protected:
		InternalID id;
	private:
};

class ContainsLoader
{
	public:
		void SetLoader(const drew_loader_t *l)
		{
			ldr = l;
		}
		const drew_loader_t *GetLoader() const
		{
			return ldr;
		}
	protected:
		const drew_loader_t *ldr;
	private:
};

class MPI : public Identifiable, public ContainsLoader
{
	public:
		MPI();
		MPI(const drew_opgp_mpi_t &);
		MPI(const MPI &);
		~MPI();
		MPI &operator=(const MPI &);
		size_t GetBitLength() const;
		size_t GetByteLength() const;
		const uint8_t *GetData() const;
		const drew_opgp_mpi_t &GetMPI() const;
		void SetMPI(const drew_opgp_mpi_t &);
		void SetMPI(const uint8_t *, size_t);
		void GenerateID();
	protected:
	private:
		drew_opgp_mpi_t mpi;
};

class PrivateKey
{
	public:
	protected:
	private:
};

class AttributeID
{
};

typedef ::drew_opgp_sig_s Signature;
typedef ::drew_opgp_uid_s UserID;
typedef ::drew_opgp_pubkey_s PublicKey;
typedef ::drew_opgp_key_s Key;

}

using namespace drew;

struct drew_opgp_sig_s : public Identifiable, public ContainsLoader
{
	public:
		drew_opgp_sig_s();
		drew_opgp_sig_s(const drew_opgp_sig_s &);
		~drew_opgp_sig_s();
		void SetCreationTime(time_t);
		time_t GetCreationTime() const;
		void SetExpirationTime(time_t);
		time_t GetExpirationTime() const;
		int GetVersion() const;
		void SetVersion(int);
		int GetType() const;
		void SetType(int);
		int GetPublicKeyAlgorithm() const;
		void SetPublicKeyAlgorithm(int);
		int GetDigestAlgorithm() const;
		void SetDigestAlgorithm(int);
		const uint8_t *GetKeyID() const;
		const MPI *GetMPIs() const;
		const drew_opgp_subpacket_group_t &GetHashedSubpackets() const;
		const drew_opgp_subpacket_group_t &GetUnhashedSubpackets() const;
		const uint8_t *GetLeft2() const;
		uint8_t *GetLeft2();
		uint8_t *GetKeyID();
		MPI *GetMPIs();
		drew_opgp_subpacket_group_t &GetHashedSubpackets();
		drew_opgp_subpacket_group_t &GetUnhashedSubpackets();
		void GenerateID();
		void Synchronize(int);
		void HashData(Hash &) const;
		const uint8_t *GetHash() const;
		uint8_t *GetHash();
		const int &GetFlags() const;
		int &GetFlags();
		const selfsig_t &GetSelfSignature() const;
		selfsig_t &GetSelfSignature();
		bool IsSelfSignature() const;
		void HashUserIDSignature(const PublicKey &pub, const UserID &uid);
		int ValidateSignature(const PublicKey &pub, bool is_selfsig);
		void SynchronizeUserIDSignature(const Key &key, const UserID &uid,
				int f);
	protected:
	private:
		int flags;
		int ver;
		int type;
		int pkalgo;
		int mdalgo;
		time_t ctime;
		time_t etime;
		drew_opgp_keyid_t keyid;
		drew_opgp_subpacket_group_t hashed;
		drew_opgp_subpacket_group_t unhashed;
		uint8_t left[2];
		selfsig_t selfsig;
		MPI mpi[DREW_OPGP_MAX_MPIS];
		drew_opgp_hash_t hash;
};

struct drew_opgp_uid_s : public Identifiable, public ContainsLoader
{
	public:
		typedef std::map<InternalID, Signature> SignatureStore;
		typedef std::vector<InternalID> SelfSignatureStore;
		void SetText(const std::string &);
		void SetText(const char *);
		void SetText(const uint8_t *, size_t);
		const std::string &GetText() const;
		const SignatureStore &GetSignatures() const;
		SignatureStore &GetSignatures();
		const InternalID &GetPrimarySelfSignature() const;
		void SetPrimarySelfSignature(const InternalID &);
		const SelfSignatureStore &GetSelfSignatures() const;
		SelfSignatureStore &GetSelfSignatures();
		void AddSignature(const Signature &);
		void GenerateID(const PublicKey &);
		void Synchronize(int);
		void HashData(Hash &) const;
	protected:
	private:
		std::string text;
		InternalID theselfsig;
		std::vector<InternalID> selfsigs;
		SignatureStore sigs;
};

struct drew_opgp_pubkey_s : public Identifiable, public ContainsLoader
{
	public:
		typedef std::map<InternalID, UserID> UserIDStore;
		typedef UserID::SignatureStore SignatureStore;
		drew_opgp_pubkey_s();
		drew_opgp_pubkey_s(bool is_main);
		drew_opgp_pubkey_s(const drew_opgp_pubkey_s &);
		void AddUserID(const UserID &);
		void AddSignature(const Signature &);
		void Merge(const PublicKey &);
		void Synchronize(int);
		const UserIDStore &GetUserIDs() const;
		const SignatureStore &GetSignatures() const;
		UserIDStore &GetUserIDs();
		SignatureStore &GetSignatures();
		const uint8_t *GetKeyID() const;
		const uint8_t *GetFingerprint() const;
		const MPI *GetMPIs() const;
		uint8_t *GetKeyID();
		uint8_t *GetFingerprint();
		MPI *GetMPIs();
		void SetCreationTime(time_t);
		time_t GetCreationTime() const;
		void SetExpirationTime(time_t);
		time_t GetExpirationTime() const;
		int GetVersion() const;
		int GetAlgorithm() const;
		void SetVersion(int);
		void SetAlgorithm(int);
		void GenerateID();
		void HashData(Hash &) const;
		const int &GetFlags() const;
		int &GetFlags();
		const InternalID &GetPrimaryUserID() const;
		void SetPrimaryUserID(const InternalID &);
	protected:
		void CalculateFingerprint();
		void CalculateFingerprintV3();
		void CalculateFingerprintV4();
	private:
		bool main;
		int flags;
		int ver;
		int algo;
		time_t ctime;
		time_t etime;
		MPI mpi[DREW_OPGP_MAX_MPIS];
		drew_opgp_keyid_t keyid;
		drew_opgp_fp_t fp;
		InternalID theuid;
		UserIDStore uids;
		SignatureStore sigs;
};

// The internal ID used here is only for serialization.  It is not used
// publicly; the ID of the main public key is used for that.
struct drew_opgp_key_s: public ContainsLoader
{
	public:
		void Synchronize(int);
		const PublicKey &GetPublicMainKey() const;
		const PrivateKey &GetPrivateMainKey() const;
		PublicKey &GetPublicMainKey();
		PrivateKey &GetPrivateMainKey();
		const std::vector<PublicKey> &GetPublicKeys() const;
		const std::vector<PrivateKey> &GetPrivateKeys() const;
		std::vector<PublicKey> &GetPublicKeys();
		std::vector<PrivateKey> &GetPrivateKeys();
	protected:
	private:
		PublicKey main;
		PrivateKey priv;
		std::vector<PublicKey> pubsubs;
		std::vector<PrivateKey> privsubs;
};

#endif
