#ifndef SP800_90_HH
#define SP800_90_HH

#include <sys/types.h>

#include <drew/block.h>
#include <drew/hash.h>
#include <drew/mode.h>

#include "prng.hh"

namespace drew {

class HashHelper
{
	public:
		HashHelper(const drew_hash_t *hash);
		~HashHelper();
		void AddData(const uint8_t *data, size_t len);
		void GetDigest(uint8_t *data, size_t len);
		size_t GetSeedLength() const;
		size_t GetDigestLength() const;
		size_t GetBlockSize() const;
		void Reset();
	private:
		const drew_hash_t *orighash;
		drew_hash_t *hash;
};

// An NIST-specified Deterministic Random Bit Generator (SP 800-90).
class DRBG : public SeededPRNG, public BlockPRNG
{
	public:
		virtual ~DRBG() {}
		virtual int AddRandomData(const uint8_t *buf, size_t len,
				size_t entropy);
	protected:
		DRBG();
		struct Personalization {
			pid_t pid, ppid, sid;
			uid_t uid, euid;
			gid_t gid, egid;
			struct timespec rt, mt, pt, tt;
		};
		static const size_t reseed_interval = 1024;
		virtual void Initialize();
		virtual void Initialize(const uint8_t *, size_t) = 0;
		virtual void Reseed(const uint8_t *, size_t) = 0;
		virtual void Stir();
		void GeneratePersonalizationString(uint8_t *buf, size_t *len);
		bool inited;
		size_t rc; // reseed_counter.

};

class HashDRBG : public DRBG
{
	public:
		HashDRBG(const drew_hash_t &);
		virtual ~HashDRBG();
		void GetBytes(uint8_t *, size_t);
	protected:
		void Initialize(const uint8_t *, size_t);
		void Reseed(const uint8_t *, size_t);
		void HashDF(const drew_hash_t *, const uint8_t *, size_t,
				uint8_t *, size_t);
		void HashGen(uint8_t *, size_t);
		// At least seedlen bits long.  We use 1024 bits just to make sure we
		// have enough room.
		uint8_t V[1024/8];
		uint8_t C[1024/8];
		size_t rc; // reseed_counter.
		const drew_hash_t *hash;
		size_t digestlen, seedlen;
};

class CounterDRBG : public DRBG
{
	public:
		CounterDRBG(const drew_mode_t &c, const drew_block_t &b, size_t outl,
				size_t keyl);
		virtual ~CounterDRBG();
		void GetBytes(uint8_t *, size_t);
	protected:
		void Update(const uint8_t *);
		void Initialize(const uint8_t *, size_t);
		void Reseed(const uint8_t *, size_t);
		void BlockCipherDF(const drew_block_t *, const uint8_t *, uint32_t,
				uint8_t *, uint32_t);
		void BCC(const drew_block_t *, const uint8_t *, size_t, uint8_t *);
		drew_block_t *block;
		drew_mode_t *ctr;
		size_t outlen, keylen, seedlen;
};

}

#endif
