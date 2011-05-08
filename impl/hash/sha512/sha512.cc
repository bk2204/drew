#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "sha512.hh"
#include "testcase.hh"
#include "hash-plugin.hh"

extern "C" {
PLUGIN_STRUCTURE(sha512, SHA512)
PLUGIN_STRUCTURE(sha384, SHA384)
PLUGIN_STRUCTURE2(sha512t, SHA512t)
PLUGIN_DATA_START()
PLUGIN_DATA(sha512, "SHA-512")
PLUGIN_DATA(sha384, "SHA-384")
PLUGIN_DATA(sha512t, "SHA-512/t")
PLUGIN_DATA_END()
PLUGIN_INTERFACE(sha512)

static int sha512t_get_digest_size(const drew_param_t *param)
{
	size_t tval = 0, digestsizeval = 0, result = 0;

	for (const drew_param_t *p = param; p; p = p->next) {
		if (!p->name)
			continue;
		// This is in bytes...
		if (!digestsizeval && !strcmp(p->name, "digestSize"))
			digestsizeval = p->param.number;
		// and this is in bits.
		if (!tval && !strcmp(p->name, "t"))
			tval = p->param.number / 8;
	}
	if (digestsizeval)
		result = digestsizeval;
	else if (tval)
		result = tval;
	if (!result)
		return -DREW_ERR_MORE_INFO;
	if ((result < (512 / 8)) && (result != (384 / 8)))
		return result;
	return -DREW_ERR_INVALID;
}

static int sha512tinfo(int op, void *p)
{
	using namespace drew;
	const drew_param_t *param = reinterpret_cast<const drew_param_t *>(p);
	switch (op) {
		case DREW_HASH_VERSION:
			return 2;
		case DREW_HASH_QUANTUM:
			return sizeof(SHA512t::quantum_t);
		case DREW_HASH_SIZE:
			return sha512t_get_digest_size(param);
		case DREW_HASH_BLKSIZE:
			return SHA512t::block_size;
		case DREW_HASH_BUFSIZE:
			return SHA512t::buffer_size;
		case DREW_HASH_INTSIZE:
			return sizeof(SHA512t);
		case DREW_HASH_ENDIAN:
			return SHA512t::endian_t::GetEndianness();
		default:
			return -DREW_ERR_INVALID;
	}
}

static int sha512tinit(drew_hash_t *ctx, int flags, const drew_loader_t *,
		const drew_param_t *param)
{
	using namespace drew;
	SHA512t *p;
	int size = sha512t_get_digest_size(param);
	if (size <= 0)
		return size;
	if (flags & DREW_HASH_FIXED)
		p = new (ctx->ctx) SHA512t(size);
	else
		p = new SHA512t(size);
	ctx->ctx = p;
	ctx->functbl = &sha512tfunctbl;
	return 0;
}

static int sha512ttest(void *, const drew_loader_t *)
{
	int res = 0;

	using namespace drew;
	typedef VariableSizedHashTestCase<SHA512t, 224/8> TestCase224;
	typedef VariableSizedHashTestCase<SHA512t, 256/8> TestCase256;
	
	res |= !TestCase224("abc", 1).Test("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
	res <<= 1;
	res |= !TestCase224("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1).Test("23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9");
	res <<= 1;
	res |= !TestCase256("abc", 1).Test("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
	res <<= 1;
	res |= !TestCase256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1).Test("3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a");

	return res;
}

static int sha512test(void *, const drew_loader_t *)
{
	int res = 0;
	uint8_t zero[] = {0x00};

	using namespace drew;
	
	res |= !HashTestCase<SHA512>("", 0).Test("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
	res <<= 1;
	res |= !HashTestCase<SHA512>("a", 1).Test("1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75");
	res <<= 1;
	res |= !HashTestCase<SHA512>("abc", 1).Test("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
	res <<= 1;
	res |= !HashTestCase<SHA512>("message digest", 1).Test("107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c");
	res <<= 1;
	res |= !HashTestCase<SHA512>("abcdefghijklmnopqrstuvwxyz", 1).Test("4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1");
	res <<= 1;
	res |= !HashTestCase<SHA512>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894");
	res <<= 1;
	res |= !HashTestCase<SHA512>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843");
	res <<= 1;
	res |= !HashTestCase<SHA512>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
	res <<= 1;
	res |= !HashTestCase<SHA512>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1).Test("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
	res <<= 1;
	res |= !HashTestCase<SHA512>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
	res <<= 1;
	// The following test vectors are from
	// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA2_Additional.pdf
	// The same document contains testcases for SHA-224, SHA-256, SHA-384, and
	// SHA-512.
	res |= !HashTestCase<SHA512>(zero, 1, 111).Test("77ddd3a542e530fd047b8977c657ba6ce72f1492e360b2b2212cd264e75ec03882e4ff0525517ab4207d14c70c2259ba88d4d335ee0e7e20543d22102ab1788c");
	res <<= 1;
	res |= !HashTestCase<SHA512>(zero, 1, 112).Test("2be2e788c8a8adeaa9c89a7f78904cacea6e39297d75e0573a73c756234534d6627ab4156b48a6657b29ab8beb73334040ad39ead81446bb09c70704ec707952");
	res <<= 1;
	res |= !HashTestCase<SHA512>(zero, 1, 113).Test("0e67910bcf0f9ccde5464c63b9c850a12a759227d16b040d98986d54253f9f34322318e56b8feb86c5fb2270ed87f31252f7f68493ee759743909bd75e4bb544");
	res <<= 1;
	res |= !HashTestCase<SHA512>(zero, 1, 122).Test("4f3f095d015be4a7a7cc0b8c04da4aa09e74351e3a97651f744c23716ebd9b3e822e5077a01baa5cc0ed45b9249e88ab343d4333539df21ed229da6f4a514e0f");
	res <<= 1;
	res |= !HashTestCase<SHA512>(zero, 1, 1000).Test("ca3dff61bb23477aa6087b27508264a6f9126ee3a004f53cb8db942ed345f2f2d229b4b59c859220a1cf1913f34248e3803bab650e849a3d9a709edc09ae4a76");
	res <<= 1;
	res |= !HashTestCase<SHA512>("A", 1000).Test("329c52ac62d1fe731151f2b895a00475445ef74f50b979c6f7bb7cae349328c1d4cb4f7261a0ab43f936a24b000651d4a824fcdd577f211aef8f806b16afe8af");
	res <<= 1;
	res |= !HashTestCase<SHA512>("U", 1005).Test("59f5e54fe299c6a8764c6b199e44924a37f59e2b56c3ebad939b7289210dc8e4c21b9720165b0f4d4374c90f1bf4fb4a5ace17a1161798015052893a48c3d161");
	res <<= 1;
	res |= !HashTestCase<SHA512>(zero, 1, 1000000).Test("ce044bc9fd43269d5bbc946cbebc3bb711341115cc4abdf2edbc3ff2c57ad4b15deb699bda257fea5aef9c6e55fcf4cf9dc25a8c3ce25f2efe90908379bff7ed");
	res <<= 1;
	res |= !HashTestCase<SHA512>("Z", 0x20000000).Test("da172279f3ebbda95f6b6e1e5f0ebec682c25d3d93561a1624c2fa9009d64c7e9923f3b46bcaf11d39a531f43297992ba4155c7e827bd0f1e194ae7ed6de4cac");
	res <<= 1;
	res |= !HashTestCase<SHA512>(zero, 1, 0x41000000).Test("14b1be901cb43549b4d831e61e5f9df1c791c85b50e85f9d6bc64135804ad43ce8402750edbe4e5c0fc170b99cf78b9f4ecb9c7e02a157911d1bd1832d76784f");
	res <<= 1;
	res |= !HashTestCase<SHA512>("B", 0x6000003e).Test("fd05e13eb771f05190bd97d62647157ea8f1f6949a52bb6daaedbad5f578ec59b1b8d6c4a7ecb2feca6892b4dc138771670a0f3bd577eea326aed40ab7dd58b1");
	res <<= 1;
	res |= !HashTestCase<SHA512>::MaintenanceTest("2b237afa2664b8f340cdcd819861b477d55ca41b3538a12e961bb3eb5365f1078a88d993cf38ec080fcae5f43024660fb25264befbb79a2b1036e34908ba170c");

	return res;
}

static int sha384test(void *, const drew_loader_t *)
{
	int res = 0;
	uint8_t zero[] = {0x00};

	using namespace drew;

	res |= !HashTestCase<SHA384>("", 0).Test("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
	res <<= 1;
	res |= !HashTestCase<SHA384>("a", 1).Test("54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31");
	res <<= 1;
	res |= !HashTestCase<SHA384>("abc", 1).Test("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
	res <<= 1;
	res |= !HashTestCase<SHA384>("message digest", 1).Test("473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5");
	res <<= 1;
	res |= !HashTestCase<SHA384>("abcdefghijklmnopqrstuvwxyz", 1).Test("feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4");
	res <<= 1;
	res |= !HashTestCase<SHA384>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84");
	res <<= 1;
	res |= !HashTestCase<SHA384>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026");
	res <<= 1;
	res |= !HashTestCase<SHA384>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
	res <<= 1;
	res |= !HashTestCase<SHA384>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1).Test("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
	res <<= 1;
	res |= !HashTestCase<SHA384>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985");
	res <<= 1;
	res |= !HashTestCase<SHA384>(zero, 1, 111).Test("435770712c611be7293a66dd0dc8d1450dc7ff7337bfe115bf058ef2eb9bed09cee85c26963a5bcc0905dc2df7cc6a76");
	res <<= 1;
	res |= !HashTestCase<SHA384>(zero, 1, 112).Test("3e0cbf3aee0e3aa70415beae1bd12dd7db821efa446440f12132edffce76f635e53526a111491e75ee8e27b9700eec20");
	res <<= 1;
	res |= !HashTestCase<SHA384>(zero, 1, 113).Test("6be9af2cf3cd5dd12c8d9399ec2b34e66034fbd699d4e0221d39074172a380656089caafe8f39963f94cc7c0a07e3d21");
	res <<= 1;
	res |= !HashTestCase<SHA384>(zero, 1, 122).Test("12a72ae4972776b0db7d73d160a15ef0d19645ec96c7f816411ab780c794aa496a22909d941fe671ed3f3caee900bdd5");
	res <<= 1;
	res |= !HashTestCase<SHA384>(zero, 1, 1000).Test("aae017d4ae5b6346dd60a19d52130fb55194b6327dd40b89c11efc8222292de81e1a23c9b59f9f58b7f6ad463fa108ca");
	res <<= 1;
	res |= !HashTestCase<SHA384>("A", 1000).Test("7df01148677b7f18617eee3a23104f0eed6bb8c90a6046f715c9445ff43c30d69e9e7082de39c3452fd1d3afd9ba0689");
	res <<= 1;
	res |= !HashTestCase<SHA384>("U", 1005).Test("1bb8e256da4a0d1e87453528254f223b4cb7e49c4420dbfa766bba4adba44eeca392ff6a9f565bc347158cc970ce44ec");
	res <<= 1;
	res |= !HashTestCase<SHA384>(zero, 1, 1000000).Test("8a1979f9049b3fff15ea3a43a4cf84c634fd14acad1c333fecb72c588b68868b66a994386dc0cd1687b9ee2e34983b81");
	res <<= 1;
	res |= !HashTestCase<SHA384>("Z", 0x20000000).Test("18aded227cc6b562cc7fb259e8f404549e52914531aa1c5d85167897c779cc4b25d0425fd1590e40bd763ec3f4311c1a");
	res <<= 1;
	res |= !HashTestCase<SHA384>(zero, 1, 0x41000000).Test("83ab05ca483abe3faa597ad524d31291ae827c5be2b3efcb6391bfed31ccd937b6135e0378c6c7f598857a7c516f207a");
	res <<= 1;
	res |= !HashTestCase<SHA384>("B", 0x6000003e).Test("cf852304f8d80209351b37ce69ca7dcf34972b4edb7817028ec55ab67ad3bc96eecb8241734258a85d2afce65d4571e2");
	res <<= 1;
	res |= !HashTestCase<SHA384>::MaintenanceTest("03a953c09e78a5e0de89c9767037c56e86f2ba5575375355ac8607214452dadc710bacf3f50ec40a0de85cba01755b41");

	return res;
}
}

/* 32-bit rotate-right. */
static inline uint64_t ROR(uint64_t x, int n)
{
	return ((x>>n)|(x<<(64-n)));
}

static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z)
{
	return (z^(x&(y^z)));
}
static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z)
{
	return (x&y)^(x&z)^(y&z);
}
static inline uint64_t S0(uint64_t x)
{
	return ROR(x, 28)^ROR(x, 34)^ROR(x, 39);
}
static inline uint64_t S1(uint64_t x)
{
	return ROR(x, 14)^ROR(x, 18)^ROR(x, 41);
}
static inline uint64_t s0(uint64_t x)
{
	return ROR(x, 1)^ROR(x, 8)^(x>>7);
}
static inline uint64_t s1(uint64_t x)
{
	return ROR(x, 19)^ROR(x, 61)^(x>>6);
}

static const uint64_t k[]={
	0x428a2f98d728ae22, 0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019,
	0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
	0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210,
	0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926,
	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001,
	0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910,
	0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60,
	0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9,
	0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

drew::SHA512::SHA512()
{
	Reset();
}

void drew::SHA512::Reset()
{
	m_hash[0] = 0x6a09e667f3bcc908;
	m_hash[1] = 0xbb67ae8584caa73b;
	m_hash[2] = 0x3c6ef372fe94f82b;
	m_hash[3] = 0xa54ff53a5f1d36f1;
	m_hash[4] = 0x510e527fade682d1;
	m_hash[5] = 0x9b05688c2b3e6c1f;
	m_hash[6] = 0x1f83d9abfb41bd6b;
	m_hash[7] = 0x5be0cd19137e2179;
	Initialize();
}

drew::SHA512t::SHA512t(size_t t_) : t(t_)
{
	Reset();
}

void drew::SHA512t::Reset()
{
	char buf[64];

	m_hash[0] = 0x6a09e667f3bcc908 ^ 0xa5a5a5a5a5a5a5a5;
	m_hash[1] = 0xbb67ae8584caa73b ^ 0xa5a5a5a5a5a5a5a5;
	m_hash[2] = 0x3c6ef372fe94f82b ^ 0xa5a5a5a5a5a5a5a5;
	m_hash[3] = 0xa54ff53a5f1d36f1 ^ 0xa5a5a5a5a5a5a5a5;
	m_hash[4] = 0x510e527fade682d1 ^ 0xa5a5a5a5a5a5a5a5;
	m_hash[5] = 0x9b05688c2b3e6c1f ^ 0xa5a5a5a5a5a5a5a5;
	m_hash[6] = 0x1f83d9abfb41bd6b ^ 0xa5a5a5a5a5a5a5a5;
	m_hash[7] = 0x5be0cd19137e2179 ^ 0xa5a5a5a5a5a5a5a5;
	Initialize();

	int nbytes = snprintf(buf, sizeof(buf), "SHA-512/%zu", t * 8);
	Update(reinterpret_cast<uint8_t *>(buf), nbytes);
	Pad();
	Initialize();
}

drew::SHA384::SHA384()
{
	Reset();
}

void drew::SHA384::Reset()
{
	m_hash[0] = 0xcbbb9d5dc1059ed8;
	m_hash[1] = 0x629a292a367cd507;
	m_hash[2] = 0x9159015a3070dd17;
	m_hash[3] = 0x152fecd8f70e5939;
	m_hash[4] = 0x67332667ffc00b31;
	m_hash[5] = 0x8eb44a8768581511;
	m_hash[6] = 0xdb0c2e0d64f98fa7;
	m_hash[7] = 0x47b5481dbefa4fa4;
	Initialize();
}

#define ROUND(a, b, c, d, e, f, g, h, k, blk) \
	h+=S1(e)+Ch(e, f, g)+k+blk; \
	d+=h; \
	h+=S0(a)+Maj(a, b, c)

#define ROUND2(a, b, c, d, e, f, g, h, k, i) \
	blk[i] = s1(blk[i-2]) + blk[i-7] + s0(blk[i-15]) + blk[i-16]; \
	ROUND(a, b, c, d, e, f, g, h, k, blk[i]); \

void drew::SHA512Transform::Transform(uint64_t *state, const uint8_t *block)
{
	// This is normally defined automatically by Hash.
	const size_t block_size = 128;
	const size_t words = block_size / sizeof(uint64_t);
	uint64_t blk[80];
	size_t i;
	uint64_t a, b, c, d, e, f, g, h;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	endian::Copy(blk, block, block_size);

	for (i = 0; i < words; i += 8) {
		ROUND(a, b, c, d, e, f, g, h, k[i  ], blk[i  ]);
		ROUND(h, a, b, c, d, e, f, g, k[i+1], blk[i+1]);
		ROUND(g, h, a, b, c, d, e, f, k[i+2], blk[i+2]);
		ROUND(f, g, h, a, b, c, d, e, k[i+3], blk[i+3]);
		ROUND(e, f, g, h, a, b, c, d, k[i+4], blk[i+4]);
		ROUND(d, e, f, g, h, a, b, c, k[i+5], blk[i+5]);
		ROUND(c, d, e, f, g, h, a, b, k[i+6], blk[i+6]);
		ROUND(b, c, d, e, f, g, h, a, k[i+7], blk[i+7]);
	}
	for (i = words; i < 80; i += 8) {
		ROUND2(a, b, c, d, e, f, g, h, k[i  ], i  );
		ROUND2(h, a, b, c, d, e, f, g, k[i+1], i+1);
		ROUND2(g, h, a, b, c, d, e, f, k[i+2], i+2);
		ROUND2(f, g, h, a, b, c, d, e, k[i+3], i+3);
		ROUND2(e, f, g, h, a, b, c, d, k[i+4], i+4);
		ROUND2(d, e, f, g, h, a, b, c, k[i+5], i+5);
		ROUND2(c, d, e, f, g, h, a, b, k[i+6], i+6);
		ROUND2(b, c, d, e, f, g, h, a, k[i+7], i+7);
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}
