#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "tiger.hh"
#include "testcase.hh"
#include "hash-plugin.hh"

extern "C" {
PLUGIN_STRUCTURE(tiger, drew::Tiger, Tiger)
PLUGIN_DATA_START()
PLUGIN_DATA(tiger, "Tiger")
PLUGIN_DATA_END()
PLUGIN_INTERFACE()

static int tigertest(void *, drew_loader_t *)
{
	int res = 0;

	using namespace drew;
	
	res |= !HashTestCase<Tiger>("", 0).Test("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3");
	res <<= 1;
	res |= !HashTestCase<Tiger>("a", 1).Test("77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809");
	res <<= 1;
	res |= !HashTestCase<Tiger>("abc", 1).Test("2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93");
	res <<= 1;
	res |= !HashTestCase<Tiger>("message digest", 1).Test("d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6");
	res <<= 1;
	res |= !HashTestCase<Tiger>("abcdefghijklmnopqrstuvwxyz", 1).Test("1714a472eee57d30040412bfcc55032a0b11602ff37beee9");
	res <<= 1;
	res |= !HashTestCase<Tiger>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1).Test("8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc");
	res <<= 1;
	res |= !HashTestCase<Tiger>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 1).Test("1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd");
	res <<= 1;
	res |= !HashTestCase<Tiger>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1).Test("0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e");
	res <<= 1;
	res |= !HashTestCase<Tiger>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 15625).Test("6db0e2729cbead93d715c6a7d36302e9b3cee0d2bc314b41");
	res <<= 1;
	res |= !HashTestCase<Tiger>::MaintenanceTest("58802ec374ab6292b262916354020e67f8f10c0a50174d96");

	return res;
}

}

typedef drew::Tiger::endian_t E;

drew::Tiger::Tiger()
{
	m_hash[0] = 0x0123456789abcdef;
	m_hash[1] = 0xfedcba9876543210;
	m_hash[2] = 0xf096a5b4c3b2e187;
	Initialize();
}

#define ROUND(a, b, c, x, k) do { c ^= x;\
	a -= t1[E::GetByte(c, 0)] ^ t2[E::GetByte(c, 2)] ^ t3[E::GetByte(c, 4)] ^ \
		t4[E::GetByte(c, 6)]; \
	b += t4[E::GetByte(c, 1)] ^ t3[E::GetByte(c, 3)] ^ t2[E::GetByte(c, 5)] ^ \
		t1[E::GetByte(c, 7)]; \
	b *= k; } while (0)
	

#define PASS(a, b, c, x, k) do { \
	ROUND(a, b, c, x[0], k); \
	ROUND(b, c, a, x[1], k); \
	ROUND(c, a, b, x[2], k); \
	ROUND(a, b, c, x[3], k); \
	ROUND(b, c, a, x[4], k); \
	ROUND(c, a, b, x[5], k); \
	ROUND(a, b, c, x[6], k); \
	ROUND(b, c, a, x[7], k); } while (0)

#define SCHEDULE(x) do { \
	x[0] -= x[7] ^ 0xa5a5a5a5a5a5a5a5; \
	x[1] ^= x[0]; \
	x[2] += x[1]; \
	x[3] -= x[2] ^ ((~x[1]) << 19); \
	x[4] ^= x[3]; \
	x[5] += x[4]; \
	x[6] -= x[5] ^ ((~x[4]) >> 23); \
	x[7] ^= x[6]; \
	x[0] += x[7]; \
	x[1] -= x[0] ^ ((~x[7]) << 19); \
	x[2] ^= x[1]; \
	x[3] += x[2]; \
	x[4] -= x[3] ^ ((~x[2]) >> 23); \
	x[5] ^= x[4]; \
	x[6] += x[5]; \
	x[7] -= x[6] ^ 0x0123456789abcdef; \
	} while (0)

void drew::Tiger::Transform(uint64_t *state, const uint8_t *block)
{
	uint64_t x[8];
	uint64_t a, b, c, aa, bb, cc;

	E::Copy(x, block, sizeof(x));

	a = aa = state[0];
	b = bb = state[1];
	c = cc = state[2];

	PASS(a, b, c, x, 5);
	SCHEDULE(x);
	PASS(c, a, b, x, 7);
	SCHEDULE(x);
	PASS(b, c, a, x, 9);

	state[0] = a ^ aa;
	state[1] = b - bb;
	state[2] = c + cc;
}

void drew::Tiger::Pad()
{
	uint32_t len[2];

	const size_t lenoff = m_len[0];
	const size_t trip = block_size - sizeof(len);
	const bool is_big =
		NativeEndian::GetEndianness() == BigEndian::GetEndianness();
	const size_t noff = lenoff % block_size;
	size_t off = noff + 1;
	uint8_t *buf = m_buf;
	/* Convert bytes to bits. */
	len[!is_big] = (m_len[1]<<3)|(m_len[0]>>((sizeof(m_len[0])*8)-3));
	len[is_big] = m_len[0]<<3;
	
	/* There is always at least one byte free. */
	buf[noff] = 0x01;
	if (noff >= trip) {
		memset(buf+off, 0, block_size-off);
		Transform(buf);
		off = 0;
	}
	memset(buf+off, 0, trip-off);
	E::Copy(buf+trip, len, sizeof(len), sizeof(len));
	Transform(buf);
}

const uint64_t drew::Tiger::t1[] = {
    0x02aab17cf7e90c5eLL,    0xac424b03e243a8ecLL,
    0x72cd5be30dd5fcd3LL,    0x6d019b93f6f97f3aLL,
    0xcd9978ffd21f9193LL,    0x7573a1c9708029e2LL,
    0xb164326b922a83c3LL,    0x46883eee04915870LL,
    0xeaace3057103ece6LL,    0xc54169b808a3535cLL,
    0x4ce754918ddec47cLL,    0x0aa2f4dfdc0df40cLL,
    0x10b76f18a74dbefaLL,    0xc6ccb6235ad1ab6aLL,
    0x13726121572fe2ffLL,    0x1a488c6f199d921eLL,
    0x4bc9f9f4da0007caLL,    0x26f5e6f6e85241c7LL,
    0x859079dbea5947b6LL,    0x4f1885c5c99e8c92LL,
    0xd78e761ea96f864bLL,    0x8e36428c52b5c17dLL,
    0x69cf6827373063c1LL,    0xb607c93d9bb4c56eLL,
    0x7d820e760e76b5eaLL,    0x645c9cc6f07fdc42LL,
    0xbf38a078243342e0LL,    0x5f6b343c9d2e7d04LL,
    0xf2c28aeb600b0ec6LL,    0x6c0ed85f7254bcacLL,
    0x71592281a4db4fe5LL,    0x1967fa69ce0fed9fLL,
    0xfd5293f8b96545dbLL,    0xc879e9d7f2a7600bLL,
    0x860248920193194eLL,    0xa4f9533b2d9cc0b3LL,
    0x9053836c15957613LL,    0xdb6dcf8afc357bf1LL,
    0x18beea7a7a370f57LL,    0x037117ca50b99066LL,
    0x6ab30a9774424a35LL,    0xf4e92f02e325249bLL,
    0x7739db07061ccae1LL,    0xd8f3b49ceca42a05LL,
    0xbd56be3f51382f73LL,    0x45faed5843b0bb28LL,
    0x1c813d5c11bf1f83LL,    0x8af0e4b6d75fa169LL,
    0x33ee18a487ad9999LL,    0x3c26e8eab1c94410LL,
    0xb510102bc0a822f9LL,    0x141eef310ce6123bLL,
    0xfc65b90059ddb154LL,    0xe0158640c5e0e607LL,
    0x884e079826c3a3cfLL,    0x930d0d9523c535fdLL,
    0x35638d754e9a2b00LL,    0x4085fccf40469dd5LL,
    0xc4b17ad28be23a4cLL,    0xcab2f0fc6a3e6a2eLL,
    0x2860971a6b943fcdLL,    0x3dde6ee212e30446LL,
    0x6222f32ae01765aeLL,    0x5d550bb5478308feLL,
    0xa9efa98da0eda22aLL,    0xc351a71686c40da7LL,
    0x1105586d9c867c84LL,    0xdcffee85fda22853LL,
    0xccfbd0262c5eef76LL,    0xbaf294cb8990d201LL,
    0xe69464f52afad975LL,    0x94b013afdf133e14LL,
    0x06a7d1a32823c958LL,    0x6f95fe5130f61119LL,
    0xd92ab34e462c06c0LL,    0xed7bde33887c71d2LL,
    0x79746d6e6518393eLL,    0x5ba419385d713329LL,
    0x7c1ba6b948a97564LL,    0x31987c197bfdac67LL,
    0xde6c23c44b053d02LL,    0x581c49fed002d64dLL,
    0xdd474d6338261571LL,    0xaa4546c3e473d062LL,
    0x928fce349455f860LL,    0x48161bbacaab94d9LL,
    0x63912430770e6f68LL,    0x6ec8a5e602c6641cLL,
    0x87282515337ddd2bLL,    0x2cda6b42034b701bLL,
    0xb03d37c181cb096dLL,    0xe108438266c71c6fLL,
    0x2b3180c7eb51b255LL,    0xdf92b82f96c08bbcLL,
    0x5c68c8c0a632f3baLL,    0x5504cc861c3d0556LL,
    0xabbfa4e55fb26b8fLL,    0x41848b0ab3baceb4LL,
    0xb334a273aa445d32LL,    0xbca696f0a85ad881LL,
    0x24f6ec65b528d56cLL,    0x0ce1512e90f4524aLL,
    0x4e9dd79d5506d35aLL,    0x258905fac6ce9779LL,
    0x2019295b3e109b33LL,    0xf8a9478b73a054ccLL,
    0x2924f2f934417eb0LL,    0x3993357d536d1bc4LL,
    0x38a81ac21db6ff8bLL,    0x47c4fbf17d6016bfLL,
    0x1e0faadd7667e3f5LL,    0x7abcff62938beb96LL,
    0xa78dad948fc179c9LL,    0x8f1f98b72911e50dLL,
    0x61e48eae27121a91LL,    0x4d62f7ad31859808LL,
    0xeceba345ef5ceaebLL,    0xf5ceb25ebc9684ceLL,
    0xf633e20cb7f76221LL,    0xa32cdf06ab8293e4LL,
    0x985a202ca5ee2ca4LL,    0xcf0b8447cc8a8fb1LL,
    0x9f765244979859a3LL,    0xa8d516b1a1240017LL,
    0x0bd7ba3ebb5dc726LL,    0xe54bca55b86adb39LL,
    0x1d7a3afd6c478063LL,    0x519ec608e7669eddLL,
    0x0e5715a2d149aa23LL,    0x177d4571848ff194LL,
    0xeeb55f3241014c22LL,    0x0f5e5ca13a6e2ec2LL,
    0x8029927b75f5c361LL,    0xad139fabc3d6e436LL,
    0x0d5df1a94ccf402fLL,    0x3e8bd948bea5dfc8LL,
    0xa5a0d357bd3ff77eLL,    0xa2d12e251f74f645LL,
    0x66fd9e525e81a082LL,    0x2e0c90ce7f687a49LL,
    0xc2e8bcbeba973bc5LL,    0x000001bce509745fLL,
    0x423777bbe6dab3d6LL,    0xd1661c7eaef06eb5LL,
    0xa1781f354daacfd8LL,    0x2d11284a2b16affcLL,
    0xf1fc4f67fa891d1fLL,    0x73ecc25dcb920adaLL,
    0xae610c22c2a12651LL,    0x96e0a810d356b78aLL,
    0x5a9a381f2fe7870fLL,    0xd5ad62ede94e5530LL,
    0xd225e5e8368d1427LL,    0x65977b70c7af4631LL,
    0x99f889b2de39d74fLL,    0x233f30bf54e1d143LL,
    0x9a9675d3d9a63c97LL,    0x5470554ff334f9a8LL,
    0x166acb744a4f5688LL,    0x70c74caab2e4aeadLL,
    0xf0d091646f294d12LL,    0x57b82a89684031d1LL,
    0xefd95a5a61be0b6bLL,    0x2fbd12e969f2f29aLL,
    0x9bd37013feff9fe8LL,    0x3f9b0404d6085a06LL,
    0x4940c1f3166cfe15LL,    0x09542c4dcdf3defbLL,
    0xb4c5218385cd5ce3LL,    0xc935b7dc4462a641LL,
    0x3417f8a68ed3b63fLL,    0xb80959295b215b40LL,
    0xf99cdaef3b8c8572LL,    0x018c0614f8fcb95dLL,
    0x1b14accd1a3acdf3LL,    0x84d471f200bb732dLL,
    0xc1a3110e95e8da16LL,    0x430a7220bf1a82b8LL,
    0xb77e090d39df210eLL,    0x5ef4bd9f3cd05e9dLL,
    0x9d4ff6da7e57a444LL,    0xda1d60e183d4a5f8LL,
    0xb287c38417998e47LL,    0xfe3edc121bb31886LL,
    0xc7fe3ccc980ccbefLL,    0xe46fb590189bfd03LL,
    0x3732fd469a4c57dcLL,    0x7ef700a07cf1ad65LL,
    0x59c64468a31d8859LL,    0x762fb0b4d45b61f6LL,
    0x155baed099047718LL,    0x68755e4c3d50baa6LL,
    0xe9214e7f22d8b4dfLL,    0x2addbf532eac95f4LL,
    0x32ae3909b4bd0109LL,    0x834df537b08e3450LL,
    0xfa209da84220728dLL,    0x9e691d9b9efe23f7LL,
    0x0446d288c4ae8d7fLL,    0x7b4cc524e169785bLL,
    0x21d87f0135ca1385LL,    0xcebb400f137b8aa5LL,
    0x272e2b66580796beLL,    0x3612264125c2b0deLL,
    0x057702bdad1efbb2LL,    0xd4babb8eacf84be9LL,
    0x91583139641bc67bLL,    0x8bdc2de08036e024LL,
    0x603c8156f49f68edLL,    0xf7d236f7dbef5111LL,
    0x9727c4598ad21e80LL,    0xa08a0896670a5fd7LL,
    0xcb4a8f4309eba9cbLL,    0x81af564b0f7036a1LL,
    0xc0b99aa778199abdLL,    0x959f1ec83fc8e952LL,
    0x8c505077794a81b9LL,    0x3acaaf8f056338f0LL,
    0x07b43f50627a6778LL,    0x4a44ab49f5eccc77LL,
    0x3bc3d6e4b679ee98LL,    0x9cc0d4d1cf14108cLL,
    0x4406c00b206bc8a0LL,    0x82a18854c8d72d89LL,
    0x67e366b35c3c432cLL,    0xb923dd61102b37f2LL,
    0x56ab2779d884271dLL,    0xbe83e1b0ff1525afLL,
    0xfb7c65d4217e49a9LL,    0x6bdbe0e76d48e7d4LL,
    0x08df828745d9179eLL,    0x22ea6a9add53bd34LL,
    0xe36e141c5622200aLL,    0x7f805d1b8cb750eeLL,
    0xafe5c7a59f58e837LL,    0xe27f996a4fb1c23cLL,
    0xd3867dfb0775f0d0LL,    0xd0e673de6e88891aLL,
    0x123aeb9eafb86c25LL,    0x30f1d5d5c145b895LL,
    0xbb434a2dee7269e7LL,    0x78cb67ecf931fa38LL,
    0xf33b0372323bbf9cLL,    0x52d66336fb279c74LL,
    0x505f33ac0afb4eaaLL,    0xe8a5cd99a2cce187LL,
    0x534974801e2d30bbLL,    0x8d2d5711d5876d90LL,
    0x1f1a412891bc038eLL,    0xd6e2e71d82e56648LL,
    0x74036c3a497732b7LL,    0x89b67ed96361f5abLL,
    0xffed95d8f1ea02a2LL,    0xe72b3bd61464d43dLL,
    0xa6300f170bdc4820LL,    0xebc18760ed78a77aLL
};

const uint64_t drew::Tiger::t2[] = {
    0xe6a6be5a05a12138LL,    0xb5a122a5b4f87c98LL,
    0x563c6089140b6990LL,    0x4c46cb2e391f5dd5LL,
    0xd932addbc9b79434LL,    0x08ea70e42015aff5LL,
    0xd765a6673e478cf1LL,    0xc4fb757eab278d99LL,
    0xdf11c6862d6e0692LL,    0xddeb84f10d7f3b16LL,
    0x6f2ef604a665ea04LL,    0x4a8e0f0ff0e0dfb3LL,
    0xa5edeef83dbcba51LL,    0xfc4f0a2a0ea4371eLL,
    0xe83e1da85cb38429LL,    0xdc8ff882ba1b1ce2LL,
    0xcd45505e8353e80dLL,    0x18d19a00d4db0717LL,
    0x34a0cfeda5f38101LL,    0x0be77e518887caf2LL,
    0x1e341438b3c45136LL,    0xe05797f49089ccf9LL,
    0xffd23f9df2591d14LL,    0x543dda228595c5cdLL,
    0x661f81fd99052a33LL,    0x8736e641db0f7b76LL,
    0x15227725418e5307LL,    0xe25f7f46162eb2faLL,
    0x48a8b2126c13d9feLL,    0xafdc541792e76eeaLL,
    0x03d912bfc6d1898fLL,    0x31b1aafa1b83f51bLL,
    0xf1ac2796e42ab7d9LL,    0x40a3a7d7fcd2ebacLL,
    0x1056136d0afbbcc5LL,    0x7889e1dd9a6d0c85LL,
    0xd33525782a7974aaLL,    0xa7e25d09078ac09bLL,
    0xbd4138b3eac6edd0LL,    0x920abfbe71eb9e70LL,
    0xa2a5d0f54fc2625cLL,    0xc054e36b0b1290a3LL,
    0xf6dd59ff62fe932bLL,    0x3537354511a8ac7dLL,
    0xca845e9172fadcd4LL,    0x84f82b60329d20dcLL,
    0x79c62ce1cd672f18LL,    0x8b09a2add124642cLL,
    0xd0c1e96a19d9e726LL,    0x5a786a9b4ba9500cLL,
    0x0e020336634c43f3LL,    0xc17b474aeb66d822LL,
    0x6a731ae3ec9baac2LL,    0x8226667ae0840258LL,
    0x67d4567691caeca5LL,    0x1d94155c4875adb5LL,
    0x6d00fd985b813fdfLL,    0x51286efcb774cd06LL,
    0x5e8834471fa744afLL,    0xf72ca0aee761ae2eLL,
    0xbe40e4cdaee8e09aLL,    0xe9970bbb5118f665LL,
    0x726e4beb33df1964LL,    0x703b000729199762LL,
    0x4631d816f5ef30a7LL,    0xb880b5b51504a6beLL,
    0x641793c37ed84b6cLL,    0x7b21ed77f6e97d96LL,
    0x776306312ef96b73LL,    0xae528948e86ff3f4LL,
    0x53dbd7f286a3f8f8LL,    0x16cadce74cfc1063LL,
    0x005c19bdfa52c6ddLL,    0x68868f5d64d46ad3LL,
    0x3a9d512ccf1e186aLL,    0x367e62c2385660aeLL,
    0xe359e7ea77dcb1d7LL,    0x526c0773749abe6eLL,
    0x735ae5f9d09f734bLL,    0x493fc7cc8a558ba8LL,
    0xb0b9c1533041ab45LL,    0x321958ba470a59bdLL,
    0x852db00b5f46c393LL,    0x91209b2bd336b0e5LL,
    0x6e604f7d659ef19fLL,    0xb99a8ae2782ccb24LL,
    0xccf52ab6c814c4c7LL,    0x4727d9afbe11727bLL,
    0x7e950d0c0121b34dLL,    0x756f435670ad471fLL,
    0xf5add442615a6849LL,    0x4e87e09980b9957aLL,
    0x2acfa1df50aee355LL,    0xd898263afd2fd556LL,
    0xc8f4924dd80c8fd6LL,    0xcf99ca3d754a173aLL,
    0xfe477bacaf91bf3cLL,    0xed5371f6d690c12dLL,
    0x831a5c285e687094LL,    0xc5d3c90a3708a0a4LL,
    0x0f7f903717d06580LL,    0x19f9bb13b8fdf27fLL,
    0xb1bd6f1b4d502843LL,    0x1c761ba38fff4012LL,
    0x0d1530c4e2e21f3bLL,    0x8943ce69a7372c8aLL,
    0xe5184e11feb5ce66LL,    0x618bdb80bd736621LL,
    0x7d29bad68b574d0bLL,    0x81bb613e25e6fe5bLL,
    0x071c9c10bc07913fLL,    0xc7beeb7909ac2d97LL,
    0xc3e58d353bc5d757LL,    0xeb017892f38f61e8LL,
    0xd4effb9c9b1cc21aLL,    0x99727d26f494f7abLL,
    0xa3e063a2956b3e03LL,    0x9d4a8b9a4aa09c30LL,
    0x3f6ab7d500090fb4LL,    0x9cc0f2a057268ac0LL,
    0x3dee9d2dedbf42d1LL,    0x330f49c87960a972LL,
    0xc6b2720287421b41LL,    0x0ac59ec07c00369cLL,
    0xef4eac49cb353425LL,    0xf450244eef0129d8LL,
    0x8acc46e5caf4deb6LL,    0x2ffeab63989263f7LL,
    0x8f7cb9fe5d7a4578LL,    0x5bd8f7644e634635LL,
    0x427a7315bf2dc900LL,    0x17d0c4aa2125261cLL,
    0x3992486c93518e50LL,    0xb4cbfee0a2d7d4c3LL,
    0x7c75d6202c5ddd8dLL,    0xdbc295d8e35b6c61LL,
    0x60b369d302032b19LL,    0xce42685fdce44132LL,
    0x06f3ddb9ddf65610LL,    0x8ea4d21db5e148f0LL,
    0x20b0fce62fcd496fLL,    0x2c1b912358b0ee31LL,
    0xb28317b818f5a308LL,    0xa89c1e189ca6d2cfLL,
    0x0c6b18576aaadbc8LL,    0xb65deaa91299fae3LL,
    0xfb2b794b7f1027e7LL,    0x04e4317f443b5bebLL,
    0x4b852d325939d0a6LL,    0xd5ae6beefb207ffcLL,
    0x309682b281c7d374LL,    0xbae309a194c3b475LL,
    0x8cc3f97b13b49f05LL,    0x98a9422ff8293967LL,
    0x244b16b01076ff7cLL,    0xf8bf571c663d67eeLL,
    0x1f0d6758eee30da1LL,    0xc9b611d97adeb9b7LL,
    0xb7afd5887b6c57a2LL,    0x6290ae846b984fe1LL,
    0x94df4cdeacc1a5fdLL,    0x058a5bd1c5483affLL,
    0x63166cc142ba3c37LL,    0x8db8526eb2f76f40LL,
    0xe10880036f0d6d4eLL,    0x9e0523c9971d311dLL,
    0x45ec2824cc7cd691LL,    0x575b8359e62382c9LL,
    0xfa9e400dc4889995LL,    0xd1823ecb45721568LL,
    0xdafd983b8206082fLL,    0xaa7d29082386a8cbLL,
    0x269fcd4403b87588LL,    0x1b91f5f728bdd1e0LL,
    0xe4669f39040201f6LL,    0x7a1d7c218cf04adeLL,
    0x65623c29d79ce5ceLL,    0x2368449096c00bb1LL,
    0xab9bf1879da503baLL,    0xbc23ecb1a458058eLL,
    0x9a58df01bb401eccLL,    0xa070e868a85f143dLL,
    0x4ff188307df2239eLL,    0x14d565b41a641183LL,
    0xee13337452701602LL,    0x950e3dcf3f285e09LL,
    0x59930254b9c80953LL,    0x3bf299408930da6dLL,
    0xa955943f53691387LL,    0xa15edecaa9cb8784LL,
    0x29142127352be9a0LL,    0x76f0371fff4e7afbLL,
    0x0239f450274f2228LL,    0xbb073af01d5e868bLL,
    0xbfc80571c10e96c1LL,    0xd267088568222e23LL,
    0x9671a3d48e80b5b0LL,    0x55b5d38ae193bb81LL,
    0x693ae2d0a18b04b8LL,    0x5c48b4ecadd5335fLL,
    0xfd743b194916a1caLL,    0x2577018134be98c4LL,
    0xe77987e83c54a4adLL,    0x28e11014da33e1b9LL,
    0x270cc59e226aa213LL,    0x71495f756d1a5f60LL,
    0x9be853fb60afef77LL,    0xadc786a7f7443dbfLL,
    0x0904456173b29a82LL,    0x58bc7a66c232bd5eLL,
    0xf306558c673ac8b2LL,    0x41f639c6b6c9772aLL,
    0x216defe99fda35daLL,    0x11640cc71c7be615LL,
    0x93c43694565c5527LL,    0xea038e6246777839LL,
    0xf9abf3ce5a3e2469LL,    0x741e768d0fd312d2LL,
    0x0144b883ced652c6LL,    0xc20b5a5ba33f8552LL,
    0x1ae69633c3435a9dLL,    0x97a28ca4088cfdecLL,
    0x8824a43c1e96f420LL,    0x37612fa66eeea746LL,
    0x6b4cb165f9cf0e5aLL,    0x43aa1c06a0abfb4aLL,
    0x7f4dc26ff162796bLL,    0x6cbacc8e54ed9b0fLL,
    0xa6b7ffefd2bb253eLL,    0x2e25bc95b0a29d4fLL,
    0x86d6a58bdef1388cLL,    0xded74ac576b6f054LL,
    0x8030bdbc2b45805dLL,    0x3c81af70e94d9289LL,
    0x3eff6dda9e3100dbLL,    0xb38dc39fdfcc8847LL,
    0x123885528d17b87eLL,    0xf2da0ed240b1b642LL,
    0x44cefadcd54bf9a9LL,    0x1312200e433c7ee6LL,
    0x9ffcc84f3a78c748LL,    0xf0cd1f72248576bbLL,
    0xec6974053638cfe4LL,    0x2ba7b67c0cec4e4cLL,
    0xac2f4df3e5ce32edLL,    0xcb33d14326ea4c11LL,
    0xa4e9044cc77e58bcLL,    0x5f513293d934fcefLL,
    0x5dc9645506e55444LL,    0x50de418f317de40aLL,
    0x388cb31a69dde259LL,    0x2db4a83455820a86LL,
    0x9010a91e84711ae9LL,    0x4df7f0b7b1498371LL,
    0xd62a2eabc0977179LL,    0x22fac097aa8d5c0eLL
};

const uint64_t drew::Tiger::t3[] = {
    0xf49fcc2ff1daf39bLL,    0x487fd5c66ff29281LL,
    0xe8a30667fcdca83fLL,    0x2c9b4be3d2fcce63LL,
    0xda3ff74b93fbbbc2LL,    0x2fa165d2fe70ba66LL,
    0xa103e279970e93d4LL,    0xbecdec77b0e45e71LL,
    0xcfb41e723985e497LL,    0xb70aaa025ef75017LL,
    0xd42309f03840b8e0LL,    0x8efc1ad035898579LL,
    0x96c6920be2b2abc5LL,    0x66af4163375a9172LL,
    0x2174abdcca7127fbLL,    0xb33ccea64a72ff41LL,
    0xf04a4933083066a5LL,    0x8d970acdd7289af5LL,
    0x8f96e8e031c8c25eLL,    0xf3fec02276875d47LL,
    0xec7bf310056190ddLL,    0xf5adb0aebb0f1491LL,
    0x9b50f8850fd58892LL,    0x4975488358b74de8LL,
    0xa3354ff691531c61LL,    0x0702bbe481d2c6eeLL,
    0x89fb24057deded98LL,    0xac3075138596e902LL,
    0x1d2d3580172772edLL,    0xeb738fc28e6bc30dLL,
    0x5854ef8f63044326LL,    0x9e5c52325add3bbeLL,
    0x90aa53cf325c4623LL,    0xc1d24d51349dd067LL,
    0x2051cfeea69ea624LL,    0x13220f0a862e7e4fLL,
    0xce39399404e04864LL,    0xd9c42ca47086fcb7LL,
    0x685ad2238a03e7ccLL,    0x066484b2ab2ff1dbLL,
    0xfe9d5d70efbf79ecLL,    0x5b13b9dd9c481854LL,
    0x15f0d475ed1509adLL,    0x0bebcd060ec79851LL,
    0xd58c6791183ab7f8LL,    0xd1187c5052f3eee4LL,
    0xc95d1192e54e82ffLL,    0x86eea14cb9ac6ca2LL,
    0x3485beb153677d5dLL,    0xdd191d781f8c492aLL,
    0xf60866baa784ebf9LL,    0x518f643ba2d08c74LL,
    0x8852e956e1087c22LL,    0xa768cb8dc410ae8dLL,
    0x38047726bfec8e1aLL,    0xa67738b4cd3b45aaLL,
    0xad16691cec0dde19LL,    0xc6d4319380462e07LL,
    0xc5a5876d0ba61938LL,    0x16b9fa1fa58fd840LL,
    0x188ab1173ca74f18LL,    0xabda2f98c99c021fLL,
    0x3e0580ab134ae816LL,    0x5f3b05b773645abbLL,
    0x2501a2be5575f2f6LL,    0x1b2f74004e7e8ba9LL,
    0x1cd7580371e8d953LL,    0x7f6ed89562764e30LL,
    0xb15926ff596f003dLL,    0x9f65293da8c5d6b9LL,
    0x6ecef04dd690f84cLL,    0x4782275fff33af88LL,
    0xe41433083f820801LL,    0xfd0dfe409a1af9b5LL,
    0x4325a3342cdb396bLL,    0x8ae77e62b301b252LL,
    0xc36f9e9f6655615aLL,    0x85455a2d92d32c09LL,
    0xf2c7dea949477485LL,    0x63cfb4c133a39ebaLL,
    0x83b040cc6ebc5462LL,    0x3b9454c8fdb326b0LL,
    0x56f56a9e87ffd78cLL,    0x2dc2940d99f42bc6LL,
    0x98f7df096b096e2dLL,    0x19a6e01e3ad852bfLL,
    0x42a99ccbdbd4b40bLL,    0xa59998af45e9c559LL,
    0x366295e807d93186LL,    0x6b48181bfaa1f773LL,
    0x1fec57e2157a0a1dLL,    0x4667446af6201ad5LL,
    0xe615ebcacfb0f075LL,    0xb8f31f4f68290778LL,
    0x22713ed6ce22d11eLL,    0x3057c1a72ec3c93bLL,
    0xcb46acc37c3f1f2fLL,    0xdbb893fd02aaf50eLL,
    0x331fd92e600b9fcfLL,    0xa498f96148ea3ad6LL,
    0xa8d8426e8b6a83eaLL,    0xa089b274b7735cdcLL,
    0x87f6b3731e524a11LL,    0x118808e5cbc96749LL,
    0x9906e4c7b19bd394LL,    0xafed7f7e9b24a20cLL,
    0x6509eadeeb3644a7LL,    0x6c1ef1d3e8ef0edeLL,
    0xb9c97d43e9798fb4LL,    0xa2f2d784740c28a3LL,
    0x7b8496476197566fLL,    0x7a5be3e6b65f069dLL,
    0xf96330ed78be6f10LL,    0xeee60de77a076a15LL,
    0x2b4bee4aa08b9bd0LL,    0x6a56a63ec7b8894eLL,
    0x02121359ba34fef4LL,    0x4cbf99f8283703fcLL,
    0x398071350caf30c8LL,    0xd0a77a89f017687aLL,
    0xf1c1a9eb9e423569LL,    0x8c7976282dee8199LL,
    0x5d1737a5dd1f7abdLL,    0x4f53433c09a9fa80LL,
    0xfa8b0c53df7ca1d9LL,    0x3fd9dcbc886ccb77LL,
    0xc040917ca91b4720LL,    0x7dd00142f9d1dcdfLL,
    0x8476fc1d4f387b58LL,    0x23f8e7c5f3316503LL,
    0x032a2244e7e37339LL,    0x5c87a5d750f5a74bLL,
    0x082b4cc43698992eLL,    0xdf917becb858f63cLL,
    0x3270b8fc5bf86ddaLL,    0x10ae72bb29b5dd76LL,
    0x576ac94e7700362bLL,    0x1ad112dac61efb8fLL,
    0x691bc30ec5faa427LL,    0xff246311cc327143LL,
    0x3142368e30e53206LL,    0x71380e31e02ca396LL,
    0x958d5c960aad76f1LL,    0xf8d6f430c16da536LL,
    0xc8ffd13f1be7e1d2LL,    0x7578ae66004ddbe1LL,
    0x05833f01067be646LL,    0xbb34b5ad3bfe586dLL,
    0x095f34c9a12b97f0LL,    0x247ab64525d60ca8LL,
    0xdcdbc6f3017477d1LL,    0x4a2e14d4decad24dLL,
    0xbdb5e6d9be0a1eebLL,    0x2a7e70f7794301abLL,
    0xdef42d8a270540fdLL,    0x01078ec0a34c22c1LL,
    0xe5de511af4c16387LL,    0x7ebb3a52bd9a330aLL,
    0x77697857aa7d6435LL,    0x004e831603ae4c32LL,
    0xe7a21020ad78e312LL,    0x9d41a70c6ab420f2LL,
    0x28e06c18ea1141e6LL,    0xd2b28cbd984f6b28LL,
    0x26b75f6c446e9d83LL,    0xba47568c4d418d7fLL,
    0xd80badbfe6183d8eLL,    0x0e206d7f5f166044LL,
    0xe258a43911cbca3eLL,    0x723a1746b21dc0bcLL,
    0xc7caa854f5d7cdd3LL,    0x7cac32883d261d9cLL,
    0x7690c26423ba942cLL,    0x17e55524478042b8LL,
    0xe0be477656a2389fLL,    0x4d289b5e67ab2da0LL,
    0x44862b9c8fbbfd31LL,    0xb47cc8049d141365LL,
    0x822c1b362b91c793LL,    0x4eb14655fb13dfd8LL,
    0x1ecbba0714e2a97bLL,    0x6143459d5cde5f14LL,
    0x53a8fbf1d5f0ac89LL,    0x97ea04d81c5e5b00LL,
    0x622181a8d4fdb3f3LL,    0xe9bcd341572a1208LL,
    0x1411258643cce58aLL,    0x9144c5fea4c6e0a4LL,
    0x0d33d06565cf620fLL,    0x54a48d489f219ca1LL,
    0xc43e5eac6d63c821LL,    0xa9728b3a72770dafLL,
    0xd7934e7b20df87efLL,    0xe35503b61a3e86e5LL,
    0xcae321fbc819d504LL,    0x129a50b3ac60bfa6LL,
    0xcd5e68ea7e9fb6c3LL,    0xb01c90199483b1c7LL,
    0x3de93cd5c295376cLL,    0xaed52edf2ab9ad13LL,
    0x2e60f512c0a07884LL,    0xbc3d86a3e36210c9LL,
    0x35269d9b163951ceLL,    0x0c7d6e2ad0cdb5faLL,
    0x59e86297d87f5733LL,    0x298ef221898db0e7LL,
    0x55000029d1a5aa7eLL,    0x8bc08ae1b5061b45LL,
    0xc2c31c2b6c92703aLL,    0x94cc596baf25ef42LL,
    0x0a1d73db22540456LL,    0x04b6a0f9d9c4179aLL,
    0xeffdafa2ae3d3c60LL,    0xf7c8075bb49496c4LL,
    0x9cc5c7141d1cd4e3LL,    0x78bd1638218e5534LL,
    0xb2f11568f850246aLL,    0xedfabcfa9502bc29LL,
    0x796ce5f2da23051bLL,    0xaae128b0dc93537cLL,
    0x3a493da0ee4b29aeLL,    0xb5df6b2c416895d7LL,
    0xfcabbd25122d7f37LL,    0x70810b58105dc4b1LL,
    0xe10fdd37f7882a90LL,    0x524dcab5518a3f5cLL,
    0x3c9e85878451255bLL,    0x4029828119bd34e2LL,
    0x74a05b6f5d3ceccbLL,    0xb610021542e13ecaLL,
    0x0ff979d12f59e2acLL,    0x6037da27e4f9cc50LL,
    0x5e92975a0df1847dLL,    0xd66de190d3e623feLL,
    0x5032d6b87b568048LL,    0x9a36b7ce8235216eLL,
    0x80272a7a24f64b4aLL,    0x93efed8b8c6916f7LL,
    0x37ddbff44cce1555LL,    0x4b95db5d4b99bd25LL,
    0x92d3fda169812fc0LL,    0xfb1a4a9a90660bb6LL,
    0x730c196946a4b9b2LL,    0x81e289aa7f49da68LL,
    0x64669a0f83b1a05fLL,    0x27b3ff7d9644f48bLL,
    0xcc6b615c8db675b3LL,    0x674f20b9bcebbe95LL,
    0x6f31238275655982LL,    0x5ae488713e45cf05LL,
    0xbf619f9954c21157LL,    0xeabac46040a8eae9LL,
    0x454c6fe9f2c0c1cdLL,    0x419cf6496412691cLL,
    0xd3dc3bef265b0f70LL,    0x6d0e60f5c3578a9eLL
};

const uint64_t drew::Tiger::t4[] = {
    0x5b0e608526323c55LL,    0x1a46c1a9fa1b59f5LL,
    0xa9e245a17c4c8ffaLL,    0x65ca5159db2955d7LL,
    0x05db0a76ce35afc2LL,    0x81eac77ea9113d45LL,
    0x528ef88ab6ac0a0dLL,    0xa09ea253597be3ffLL,
    0x430ddfb3ac48cd56LL,    0xc4b3a67af45ce46fLL,
    0x4ececfd8fbe2d05eLL,    0x3ef56f10b39935f0LL,
    0x0b22d6829cd619c6LL,    0x17fd460a74df2069LL,
    0x6cf8cc8e8510ed40LL,    0xd6c824bf3a6ecaa7LL,
    0x61243d581a817049LL,    0x048bacb6bbc163a2LL,
    0xd9a38ac27d44cc32LL,    0x7fddff5baaf410abLL,
    0xad6d495aa804824bLL,    0xe1a6a74f2d8c9f94LL,
    0xd4f7851235dee8e3LL,    0xfd4b7f886540d893LL,
    0x247c20042aa4bfdaLL,    0x096ea1c517d1327cLL,
    0xd56966b4361a6685LL,    0x277da5c31221057dLL,
    0x94d59893a43acff7LL,    0x64f0c51ccdc02281LL,
    0x3d33bcc4ff6189dbLL,    0xe005cb184ce66af1LL,
    0xff5ccd1d1db99beaLL,    0xb0b854a7fe42980fLL,
    0x7bd46a6a718d4b9fLL,    0xd10fa8cc22a5fd8cLL,
    0xd31484952be4bd31LL,    0xc7fa975fcb243847LL,
    0x4886ed1e5846c407LL,    0x28cddb791eb70b04LL,
    0xc2b00be2f573417fLL,    0x5c9590452180f877LL,
    0x7a6bddfff370eb00LL,    0xce509e38d6d9d6a4LL,
    0xebeb0f00647fa702LL,    0x1dcc06cf76606f06LL,
    0xe4d9f28ba286ff0aLL,    0xd85a305dc918c262LL,
    0x475b1d8732225f54LL,    0x2d4fb51668ccb5feLL,
    0xa679b9d9d72bba20LL,    0x53841c0d912d43a5LL,
    0x3b7eaa48bf12a4e8LL,    0x781e0e47f22f1ddfLL,
    0xeff20ce60ab50973LL,    0x20d261d19dffb742LL,
    0x16a12b03062a2e39LL,    0x1960eb2239650495LL,
    0x251c16fed50eb8b8LL,    0x9ac0c330f826016eLL,
    0xed152665953e7671LL,    0x02d63194a6369570LL,
    0x5074f08394b1c987LL,    0x70ba598c90b25ce1LL,
    0x794a15810b9742f6LL,    0x0d5925e9fcaf8c6cLL,
    0x3067716cd868744eLL,    0x910ab077e8d7731bLL,
    0x6a61bbdb5ac42f61LL,    0x93513efbf0851567LL,
    0xf494724b9e83e9d5LL,    0xe887e1985c09648dLL,
    0x34b1d3c675370cfdLL,    0xdc35e433bc0d255dLL,
    0xd0aab84234131be0LL,    0x08042a50b48b7eafLL,
    0x9997c4ee44a3ab35LL,    0x829a7b49201799d0LL,
    0x263b8307b7c54441LL,    0x752f95f4fd6a6ca6LL,
    0x927217402c08c6e5LL,    0x2a8ab754a795d9eeLL,
    0xa442f7552f72943dLL,    0x2c31334e19781208LL,
    0x4fa98d7ceaee6291LL,    0x55c3862f665db309LL,
    0xbd0610175d53b1f3LL,    0x46fe6cb840413f27LL,
    0x3fe03792df0cfa59LL,    0xcfe700372eb85e8fLL,
    0xa7be29e7adbce118LL,    0xe544ee5cde8431ddLL,
    0x8a781b1b41f1873eLL,    0xa5c94c78a0d2f0e7LL,
    0x39412e2877b60728LL,    0xa1265ef3afc9a62cLL,
    0xbcc2770c6a2506c5LL,    0x3ab66dd5dce1ce12LL,
    0xe65499d04a675b37LL,    0x7d8f523481bfd216LL,
    0x0f6f64fcec15f389LL,    0x74efbe618b5b13c8LL,
    0xacdc82b714273e1dLL,    0xdd40bfe003199d17LL,
    0x37e99257e7e061f8LL,    0xfa52626904775aaaLL,
    0x8bbbf63a463d56f9LL,    0xf0013f1543a26e64LL,
    0xa8307e9f879ec898LL,    0xcc4c27a4150177ccLL,
    0x1b432f2cca1d3348LL,    0xde1d1f8f9f6fa013LL,
    0x606602a047a7ddd6LL,    0xd237ab64cc1cb2c7LL,
    0x9b938e7225fcd1d3LL,    0xec4e03708e0ff476LL,
    0xfeb2fbda3d03c12dLL,    0xae0bced2ee43889aLL,
    0x22cb8923ebfb4f43LL,    0x69360d013cf7396dLL,
    0x855e3602d2d4e022LL,    0x073805bad01f784cLL,
    0x33e17a133852f546LL,    0xdf4874058ac7b638LL,
    0xba92b29c678aa14aLL,    0x0ce89fc76cfaadcdLL,
    0x5f9d4e0908339e34LL,    0xf1afe9291f5923b9LL,
    0x6e3480f60f4a265fLL,    0xeebf3a2ab29b841cLL,
    0xe21938a88f91b4adLL,    0x57dfeff845c6d3c3LL,
    0x2f006b0bf62caaf2LL,    0x62f479ef6f75ee78LL,
    0x11a55ad41c8916a9LL,    0xf229d29084fed453LL,
    0x42f1c27b16b000e6LL,    0x2b1f76749823c074LL,
    0x4b76eca3c2745360LL,    0x8c98f463b91691bdLL,
    0x14bcc93cf1ade66aLL,    0x8885213e6d458397LL,
    0x8e177df0274d4711LL,    0xb49b73b5503f2951LL,
    0x10168168c3f96b6bLL,    0x0e3d963b63cab0aeLL,
    0x8dfc4b5655a1db14LL,    0xf789f1356e14de5cLL,
    0x683e68af4e51dac1LL,    0xc9a84f9d8d4b0fd9LL,
    0x3691e03f52a0f9d1LL,    0x5ed86e46e1878e80LL,
    0x3c711a0e99d07150LL,    0x5a0865b20c4e9310LL,
    0x56fbfc1fe4f0682eLL,    0xea8d5de3105edf9bLL,
    0x71abfdb12379187aLL,    0x2eb99de1bee77b9cLL,
    0x21ecc0ea33cf4523LL,    0x59a4d7521805c7a1LL,
    0x3896f5eb56ae7c72LL,    0xaa638f3db18f75dcLL,
    0x9f39358dabe9808eLL,    0xb7defa91c00b72acLL,
    0x6b5541fd62492d92LL,    0x6dc6dee8f92e4d5bLL,
    0x353f57abc4beea7eLL,    0x735769d6da5690ceLL,
    0x0a234aa642391484LL,    0xf6f9508028f80d9dLL,
    0xb8e319a27ab3f215LL,    0x31ad9c1151341a4dLL,
    0x773c22a57bef5805LL,    0x45c7561a07968633LL,
    0xf913da9e249dbe36LL,    0xda652d9b78a64c68LL,
    0x4c27a97f3bc334efLL,    0x76621220e66b17f4LL,
    0x967743899acd7d0bLL,    0xf3ee5bcae0ed6782LL,
    0x409f753600c879fcLL,    0x06d09a39b5926db6LL,
    0x6f83aeb0317ac588LL,    0x01e6ca4a86381f21LL,
    0x66ff3462d19f3025LL,    0x72207c24ddfd3bfbLL,
    0x4af6b6d3e2ece2ebLL,    0x9c994dbec7ea08deLL,
    0x49ace597b09a8bc4LL,    0xb38c4766cf0797baLL,
    0x131b9373c57c2a75LL,    0xb1822cce61931e58LL,
    0x9d7555b909ba1c0cLL,    0x127fafdd937d11d2LL,
    0x29da3badc66d92e4LL,    0xa2c1d57154c2ecbcLL,
    0x58c5134d82f6fe24LL,    0x1c3ae3515b62274fLL,
    0xe907c82e01cb8126LL,    0xf8ed091913e37fcbLL,
    0x3249d8f9c80046c9LL,    0x80cf9bede388fb63LL,
    0x1881539a116cf19eLL,    0x5103f3f76bd52457LL,
    0x15b7e6f5ae47f7a8LL,    0xdbd7c6ded47e9ccfLL,
    0x44e55c410228bb1aLL,    0xb647d4255edb4e99LL,
    0x5d11882bb8aafc30LL,    0xf5098bbb29d3212aLL,
    0x8fb5ea14e90296b3LL,    0x677b942157dd025aLL,
    0xfb58e7c0a390acb5LL,    0x89d3674c83bd4a01LL,
    0x9e2da4df4bf3b93bLL,    0xfcc41e328cab4829LL,
    0x03f38c96ba582c52LL,    0xcad1bdbd7fd85db2LL,
    0xbbb442c16082ae83LL,    0xb95fe86ba5da9ab0LL,
    0xb22e04673771a93fLL,    0x845358c9493152d8LL,
    0xbe2a488697b4541eLL,    0x95a2dc2dd38e6966LL,
    0xc02c11ac923c852bLL,    0x2388b1990df2a87bLL,
    0x7c8008fa1b4f37beLL,    0x1f70d0c84d54e503LL,
    0x5490adec7ece57d4LL,    0x002b3c27d9063a3aLL,
    0x7eaea3848030a2bfLL,    0xc602326ded2003c0LL,
    0x83a7287d69a94086LL,    0xc57a5fcb30f57a8aLL,
    0xb56844e479ebe779LL,    0xa373b40f05dcbce9LL,
    0xd71a786e88570ee2LL,    0x879cbacdbde8f6a0LL,
    0x976ad1bcc164a32fLL,    0xab21e25e9666d78bLL,
    0x901063aae5e5c33cLL,    0x9818b34448698d90LL,
    0xe36487ae3e1e8abbLL,    0xafbdf931893bdcb4LL,
    0x6345a0dc5fbbd519LL,    0x8628fe269b9465caLL,
    0x1e5d01603f9c51ecLL,    0x4de44006a15049b7LL,
    0xbf6c70e5f776cbb1LL,    0x411218f2ef552bedLL,
    0xcb0c0708705a36a3LL,    0xe74d14754f986044LL,
    0xcd56d9430ea8280eLL,    0xc12591d7535f5065LL,
    0xc83223f1720aef96LL,    0xc3a0396f7363a51fLL
};
