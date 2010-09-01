/*-
 * This code (which is in the public domain) comes from libcrypto++ 5.6.0.  The
 * original code was written by Phil Karn and Wei Dei, with contributions from
 * Jim Gillogly and Richard Outerbridge.  brian m. carlson converted it to a
 * drew block cipher plugin.
 */

#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include <block.h>
#include "block-plugin.hh"
#include "des.hh"

static void str2bytes(uint8_t *bytes, const char *s, size_t len = 0)
{
	if (!len)
		len = strlen(s);

	unsigned x;
	for (size_t i = 0; i < (len / 2); i++) {
		sscanf(s+(i*2), "%02x", &x);
		bytes[i] = x;
	}
}

template<class T>
static bool test(const char *key, const char *plain, const char *cipher,
		size_t keybytes = 0)
{
	const size_t blocksz = 8;
	uint8_t kb[32], pb[32], cb[32], buf[32];
	str2bytes(kb, key, keybytes * 2);
	str2bytes(pb, plain, blocksz * 2);
	str2bytes(cb, cipher, blocksz * 2);

	if (!keybytes)
		keybytes = 16;

	T ctx;
	ctx.SetKey(kb, keybytes);
	ctx.Encrypt(buf, pb);

	if (memcmp(buf, cb, blocksz))
		return false;

	ctx.SetKey(kb, keybytes);
	ctx.Decrypt(buf, cb);

	return !memcmp(buf, pb, blocksz);
}


extern "C" {

static const int deskeysz[] =
{
	8
};

static const int desedekeysz[] =
{
	16, 24
};

static bool testd(const char *key, const char *plain, const char *cipher,
		size_t keybytes = 0)
{
	char k3[16 * 3 + 1];
	memcpy(k3 +  0, key, 16);
	memcpy(k3 + 16, key, 16);
	memcpy(k3 + 32, key, 16);
	k3[48] = 0;
	return test<drew::DES>(key, plain, cipher, keybytes) &&
		test<drew::TripleDES>(k3, plain, cipher, 24) &&
		test<drew::TripleDES>(k3, plain, cipher, 16);
}

static bool test3(const char *key, const char *plain, const char *cipher,
		size_t keybytes = 0)
{
	return test<drew::TripleDES>(key, plain, cipher, keybytes);
}

static int desedetest(void *)
{
	int res = 0;

	const char *key = "0123456789abcdef23456789abcdef0456789abcdef0123";

	res |= test3(key, "5468652071756663", "a826fd8ce53b855f");
	res <<= 1;
	res |= test3(key, "6b2062726f776e20", "cce21c8112256fe6");
	res <<= 1;
	res |= test3(key, "666f78206a756d70", "68d5c05dd9b6b900");

	return res;
}

static int destest(void *)
{
	int res = 0;

	res |= testd("0101010101010101", "95F8A5E5DD31D900", "8000000000000000");
	res |= testd("0101010101010101", "DD7F121CA5015619", "4000000000000000");
	res |= testd("0101010101010101", "2E8653104F3834EA", "2000000000000000");
	res |= testd("0101010101010101", "4BD388FF6CD81D4F", "1000000000000000");
	res |= testd("0101010101010101", "20B9E767B2FB1456", "0800000000000000");
	res |= testd("0101010101010101", "55579380D77138EF", "0400000000000000");
	res |= testd("0101010101010101", "6CC5DEFAAF04512F", "0200000000000000");
	res |= testd("0101010101010101", "0D9F279BA5D87260", "0100000000000000");
	res |= testd("0101010101010101", "D9031B0271BD5A0A", "0080000000000000");
	res <<= 1;
	res |= testd("0101010101010101", "424250B37C3DD951", "0040000000000000");
	res |= testd("0101010101010101", "B8061B7ECD9A21E5", "0020000000000000");
	res |= testd("0101010101010101", "F15D0F286B65BD28", "0010000000000000");
	res |= testd("0101010101010101", "ADD0CC8D6E5DEBA1", "0008000000000000");
	res |= testd("0101010101010101", "E6D5F82752AD63D1", "0004000000000000");
	res |= testd("0101010101010101", "ECBFE3BD3F591A5E", "0002000000000000");
	res |= testd("0101010101010101", "F356834379D165CD", "0001000000000000");
	res |= testd("0101010101010101", "2B9F982F20037FA9", "0000800000000000");
	res <<= 1;
	res |= testd("0101010101010101", "889DE068A16F0BE6", "0000400000000000");
	res |= testd("0101010101010101", "E19E275D846A1298", "0000200000000000");
	res |= testd("0101010101010101", "329A8ED523D71AEC", "0000100000000000");
	res |= testd("0101010101010101", "E7FCE22557D23C97", "0000080000000000");
	res |= testd("0101010101010101", "12A9F5817FF2D65D", "0000040000000000");
	res |= testd("0101010101010101", "A484C3AD38DC9C19", "0000020000000000");
	res |= testd("0101010101010101", "FBE00A8A1EF8AD72", "0000010000000000");
	res |= testd("0101010101010101", "750D079407521363", "0000008000000000");
	res <<= 1;
	res |= testd("0101010101010101", "64FEED9C724C2FAF", "0000004000000000");
	res |= testd("0101010101010101", "F02B263B328E2B60", "0000002000000000");
	res |= testd("0101010101010101", "9D64555A9A10B852", "0000001000000000");
	res |= testd("0101010101010101", "D106FF0BED5255D7", "0000000800000000");
	res |= testd("0101010101010101", "E1652C6B138C64A5", "0000000400000000");
	res |= testd("0101010101010101", "E428581186EC8F46", "0000000200000000");
	res |= testd("0101010101010101", "AEB5F5EDE22D1A36", "0000000100000000");
	res |= testd("0101010101010101", "E943D7568AEC0C5C", "0000000080000000");
	res <<= 1;
	res |= testd("0101010101010101", "DF98C8276F54B04B", "0000000040000000");
	res |= testd("0101010101010101", "B160E4680F6C696F", "0000000020000000");
	res |= testd("0101010101010101", "FA0752B07D9C4AB8", "0000000010000000");
	res |= testd("0101010101010101", "CA3A2B036DBC8502", "0000000008000000");
	res |= testd("0101010101010101", "5E0905517BB59BCF", "0000000004000000");
	res |= testd("0101010101010101", "814EEB3B91D90726", "0000000002000000");
	res |= testd("0101010101010101", "4D49DB1532919C9F", "0000000001000000");
	res |= testd("0101010101010101", "25EB5FC3F8CF0621", "0000000000800000");
	res <<= 1;
	res |= testd("0101010101010101", "AB6A20C0620D1C6F", "0000000000400000");
	res |= testd("0101010101010101", "79E90DBC98F92CCA", "0000000000200000");
	res |= testd("0101010101010101", "866ECEDD8072BB0E", "0000000000100000");
	res |= testd("0101010101010101", "8B54536F2F3E64A8", "0000000000080000");
	res |= testd("0101010101010101", "EA51D3975595B86B", "0000000000040000");
	res |= testd("0101010101010101", "CAFFC6AC4542DE31", "0000000000020000");
	res |= testd("0101010101010101", "8DD45A2DDF90796C", "0000000000010000");
	res |= testd("0101010101010101", "1029D55E880EC2D0", "0000000000008000");
	res <<= 1;
	res |= testd("0101010101010101", "5D86CB23639DBEA9", "0000000000004000");
	res |= testd("0101010101010101", "1D1CA853AE7C0C5F", "0000000000002000");
	res |= testd("0101010101010101", "CE332329248F3228", "0000000000001000");
	res |= testd("0101010101010101", "8405D1ABE24FB942", "0000000000000800");
	res |= testd("0101010101010101", "E643D78090CA4207", "0000000000000400");
	res |= testd("0101010101010101", "48221B9937748A23", "0000000000000200");
	res |= testd("0101010101010101", "DD7C0BBD61FAFD54", "0000000000000100");
	res |= testd("0101010101010101", "2FBC291A570DB5C4", "0000000000000080");
	res <<= 1;
	res |= testd("0101010101010101", "E07C30D7E4E26E12", "0000000000000040");
	res |= testd("0101010101010101", "0953E2258E8E90A1", "0000000000000020");
	res |= testd("0101010101010101", "5B711BC4CEEBF2EE", "0000000000000010");
	res |= testd("0101010101010101", "CC083F1E6D9E85F6", "0000000000000008");
	res |= testd("0101010101010101", "D2FD8867D50D2DFE", "0000000000000004");
	res |= testd("0101010101010101", "06E7EA22CE92708F", "0000000000000002");
	res |= testd("0101010101010101", "166B40B44ABA4BD6", "0000000000000001");
	res |= testd("0101010101010101", "8000000000000000", "95F8A5E5DD31D900");
	res <<= 1;
	res |= testd("0101010101010101", "4000000000000000", "DD7F121CA5015619");
	res |= testd("0101010101010101", "2000000000000000", "2E8653104F3834EA");
	res |= testd("0101010101010101", "1000000000000000", "4BD388FF6CD81D4F");
	res |= testd("0101010101010101", "0800000000000000", "20B9E767B2FB1456");
	res |= testd("0101010101010101", "0400000000000000", "55579380D77138EF");
	res |= testd("0101010101010101", "0200000000000000", "6CC5DEFAAF04512F");
	res |= testd("0101010101010101", "0100000000000000", "0D9F279BA5D87260");
	res |= testd("0101010101010101", "0080000000000000", "D9031B0271BD5A0A");
	res <<= 1;
	res |= testd("0101010101010101", "0040000000000000", "424250B37C3DD951");
	res |= testd("0101010101010101", "0020000000000000", "B8061B7ECD9A21E5");
	res |= testd("0101010101010101", "0010000000000000", "F15D0F286B65BD28");
	res |= testd("0101010101010101", "0008000000000000", "ADD0CC8D6E5DEBA1");
	res |= testd("0101010101010101", "0004000000000000", "E6D5F82752AD63D1");
	res |= testd("0101010101010101", "0002000000000000", "ECBFE3BD3F591A5E");
	res |= testd("0101010101010101", "0001000000000000", "F356834379D165CD");
	res |= testd("0101010101010101", "0000800000000000", "2B9F982F20037FA9");
	res <<= 1;
	res |= testd("0101010101010101", "0000400000000000", "889DE068A16F0BE6");
	res |= testd("0101010101010101", "0000200000000000", "E19E275D846A1298");
	res |= testd("0101010101010101", "0000100000000000", "329A8ED523D71AEC");
	res |= testd("0101010101010101", "0000080000000000", "E7FCE22557D23C97");
	res |= testd("0101010101010101", "0000040000000000", "12A9F5817FF2D65D");
	res |= testd("0101010101010101", "0000020000000000", "A484C3AD38DC9C19");
	res |= testd("0101010101010101", "0000010000000000", "FBE00A8A1EF8AD72");
	res |= testd("0101010101010101", "0000008000000000", "750D079407521363");
	res <<= 1;
	res |= testd("0101010101010101", "0000004000000000", "64FEED9C724C2FAF");
	res |= testd("0101010101010101", "0000002000000000", "F02B263B328E2B60");
	res |= testd("0101010101010101", "0000001000000000", "9D64555A9A10B852");
	res |= testd("0101010101010101", "0000000800000000", "D106FF0BED5255D7");
	res |= testd("0101010101010101", "0000000400000000", "E1652C6B138C64A5");
	res |= testd("0101010101010101", "0000000200000000", "E428581186EC8F46");
	res |= testd("0101010101010101", "0000000100000000", "AEB5F5EDE22D1A36");
	res |= testd("0101010101010101", "0000000080000000", "E943D7568AEC0C5C");
	res <<= 1;
	res |= testd("0101010101010101", "0000000040000000", "DF98C8276F54B04B");
	res |= testd("0101010101010101", "0000000020000000", "B160E4680F6C696F");
	res |= testd("0101010101010101", "0000000010000000", "FA0752B07D9C4AB8");
	res |= testd("0101010101010101", "0000000008000000", "CA3A2B036DBC8502");
	res |= testd("0101010101010101", "0000000004000000", "5E0905517BB59BCF");
	res |= testd("0101010101010101", "0000000002000000", "814EEB3B91D90726");
	res |= testd("0101010101010101", "0000000001000000", "4D49DB1532919C9F");
	res |= testd("0101010101010101", "0000000000800000", "25EB5FC3F8CF0621");
	res <<= 1;
	res |= testd("0101010101010101", "0000000000400000", "AB6A20C0620D1C6F");
	res |= testd("0101010101010101", "0000000000200000", "79E90DBC98F92CCA");
	res |= testd("0101010101010101", "0000000000100000", "866ECEDD8072BB0E");
	res |= testd("0101010101010101", "0000000000080000", "8B54536F2F3E64A8");
	res |= testd("0101010101010101", "0000000000040000", "EA51D3975595B86B");
	res |= testd("0101010101010101", "0000000000020000", "CAFFC6AC4542DE31");
	res |= testd("0101010101010101", "0000000000010000", "8DD45A2DDF90796C");
	res |= testd("0101010101010101", "0000000000008000", "1029D55E880EC2D0");
	res <<= 1;
	res |= testd("0101010101010101", "0000000000004000", "5D86CB23639DBEA9");
	res |= testd("0101010101010101", "0000000000002000", "1D1CA853AE7C0C5F");
	res |= testd("0101010101010101", "0000000000001000", "CE332329248F3228");
	res |= testd("0101010101010101", "0000000000000800", "8405D1ABE24FB942");
	res |= testd("0101010101010101", "0000000000000400", "E643D78090CA4207");
	res |= testd("0101010101010101", "0000000000000200", "48221B9937748A23");
	res |= testd("0101010101010101", "0000000000000100", "DD7C0BBD61FAFD54");
	res |= testd("0101010101010101", "0000000000000080", "2FBC291A570DB5C4");
	res <<= 1;
	res |= testd("0101010101010101", "0000000000000040", "E07C30D7E4E26E12");
	res |= testd("0101010101010101", "0000000000000020", "0953E2258E8E90A1");
	res |= testd("0101010101010101", "0000000000000010", "5B711BC4CEEBF2EE");
	res |= testd("0101010101010101", "0000000000000008", "CC083F1E6D9E85F6");
	res |= testd("0101010101010101", "0000000000000004", "D2FD8867D50D2DFE");
	res |= testd("0101010101010101", "0000000000000002", "06E7EA22CE92708F");
	res |= testd("0101010101010101", "0000000000000001", "166B40B44ABA4BD6");
	res |= testd("8001010101010101", "0000000000000000", "95A8D72813DAA94D");
	res <<= 1;
	res |= testd("4001010101010101", "0000000000000000", "0EEC1487DD8C26D5");
	res |= testd("2001010101010101", "0000000000000000", "7AD16FFB79C45926");
	res |= testd("1001010101010101", "0000000000000000", "D3746294CA6A6CF3");
	res |= testd("0801010101010101", "0000000000000000", "809F5F873C1FD761");
	res |= testd("0401010101010101", "0000000000000000", "C02FAFFEC989D1FC");
	res |= testd("0201010101010101", "0000000000000000", "4615AA1D33E72F10");
	res |= testd("0180010101010101", "0000000000000000", "2055123350C00858");
	res |= testd("0140010101010101", "0000000000000000", "DF3B99D6577397C8");
	res <<= 1;
	res |= testd("0120010101010101", "0000000000000000", "31FE17369B5288C9");
	res |= testd("0110010101010101", "0000000000000000", "DFDD3CC64DAE1642");
	res |= testd("0108010101010101", "0000000000000000", "178C83CE2B399D94");
	res |= testd("0104010101010101", "0000000000000000", "50F636324A9B7F80");
	res |= testd("0102010101010101", "0000000000000000", "A8468EE3BC18F06D");
	res |= testd("0101800101010101", "0000000000000000", "A2DC9E92FD3CDE92");
	res |= testd("0101400101010101", "0000000000000000", "CAC09F797D031287");
	res |= testd("0101200101010101", "0000000000000000", "90BA680B22AEB525");
	res <<= 1;
	res |= testd("0101100101010101", "0000000000000000", "CE7A24F350E280B6");
	res |= testd("0101080101010101", "0000000000000000", "882BFF0AA01A0B87");
	res |= testd("0101040101010101", "0000000000000000", "25610288924511C2");
	res |= testd("0101020101010101", "0000000000000000", "C71516C29C75D170");
	res |= testd("0101018001010101", "0000000000000000", "5199C29A52C9F059");
	res |= testd("0101014001010101", "0000000000000000", "C22F0A294A71F29F");
	res |= testd("0101012001010101", "0000000000000000", "EE371483714C02EA");
	res |= testd("0101011001010101", "0000000000000000", "A81FBD448F9E522F");
	res <<= 1;
	res |= testd("0101010801010101", "0000000000000000", "4F644C92E192DFED");
	res |= testd("0101010401010101", "0000000000000000", "1AFA9A66A6DF92AE");
	res |= testd("0101010201010101", "0000000000000000", "B3C1CC715CB879D8");
	res |= testd("0101010180010101", "0000000000000000", "19D032E64AB0BD8B");
	res |= testd("0101010140010101", "0000000000000000", "3CFAA7A7DC8720DC");
	res |= testd("0101010120010101", "0000000000000000", "B7265F7F447AC6F3");
	res |= testd("0101010110010101", "0000000000000000", "9DB73B3C0D163F54");
	res |= testd("0101010108010101", "0000000000000000", "8181B65BABF4A975");
	res <<= 1;
	res |= testd("0101010104010101", "0000000000000000", "93C9B64042EAA240");
	res |= testd("0101010102010101", "0000000000000000", "5570530829705592");
	res |= testd("0101010101800101", "0000000000000000", "8638809E878787A0");
	res |= testd("0101010101400101", "0000000000000000", "41B9A79AF79AC208");
	res |= testd("0101010101200101", "0000000000000000", "7A9BE42F2009A892");
	res |= testd("0101010101100101", "0000000000000000", "29038D56BA6D2745");
	res |= testd("0101010101080101", "0000000000000000", "5495C6ABF1E5DF51");
	res |= testd("0101010101040101", "0000000000000000", "AE13DBD561488933");
	res <<= 1;
	res |= testd("0101010101020101", "0000000000000000", "024D1FFA8904E389");
	res |= testd("0101010101018001", "0000000000000000", "D1399712F99BF02E");
	res |= testd("0101010101014001", "0000000000000000", "14C1D7C1CFFEC79E");
	res |= testd("0101010101012001", "0000000000000000", "1DE5279DAE3BED6F");
	res |= testd("0101010101011001", "0000000000000000", "E941A33F85501303");
	res |= testd("0101010101010801", "0000000000000000", "DA99DBBC9A03F379");
	res |= testd("0101010101010401", "0000000000000000", "B7FC92F91D8E92E9");
	res |= testd("0101010101010201", "0000000000000000", "AE8E5CAA3CA04E85");
	res <<= 1;
	res |= testd("0101010101010180", "0000000000000000", "9CC62DF43B6EED74");
	res |= testd("0101010101010140", "0000000000000000", "D863DBB5C59A91A0");
	res |= testd("0101010101010120", "0000000000000000", "A1AB2190545B91D7");
	res |= testd("0101010101010110", "0000000000000000", "0875041E64C570F7");
	res |= testd("0101010101010108", "0000000000000000", "5A594528BEBEF1CC");
	res |= testd("0101010101010104", "0000000000000000", "FCDB3291DE21F0C0");
	res |= testd("0101010101010102", "0000000000000000", "869EFD7F9F265A09");
	res |= testd("8001010101010101", "0000000000000000", "95A8D72813DAA94D");
	res <<= 1;
	res |= testd("4001010101010101", "0000000000000000", "0EEC1487DD8C26D5");
	res |= testd("2001010101010101", "0000000000000000", "7AD16FFB79C45926");
	res |= testd("1001010101010101", "0000000000000000", "D3746294CA6A6CF3");
	res |= testd("0801010101010101", "0000000000000000", "809F5F873C1FD761");
	res |= testd("0401010101010101", "0000000000000000", "C02FAFFEC989D1FC");
	res |= testd("0201010101010101", "0000000000000000", "4615AA1D33E72F10");
	res |= testd("0180010101010101", "0000000000000000", "2055123350C00858");
	res |= testd("0140010101010101", "0000000000000000", "DF3B99D6577397C8");
	res <<= 1;
	res |= testd("0120010101010101", "0000000000000000", "31FE17369B5288C9");
	res |= testd("0110010101010101", "0000000000000000", "DFDD3CC64DAE1642");
	res |= testd("0108010101010101", "0000000000000000", "178C83CE2B399D94");
	res |= testd("0104010101010101", "0000000000000000", "50F636324A9B7F80");
	res |= testd("0102010101010101", "0000000000000000", "A8468EE3BC18F06D");
	res |= testd("0101800101010101", "0000000000000000", "A2DC9E92FD3CDE92");
	res |= testd("0101400101010101", "0000000000000000", "CAC09F797D031287");
	res |= testd("0101200101010101", "0000000000000000", "90BA680B22AEB525");
	res <<= 1;
	res |= testd("0101100101010101", "0000000000000000", "CE7A24F350E280B6");
	res |= testd("0101080101010101", "0000000000000000", "882BFF0AA01A0B87");
	res |= testd("0101040101010101", "0000000000000000", "25610288924511C2");
	res |= testd("0101020101010101", "0000000000000000", "C71516C29C75D170");
	res |= testd("0101018001010101", "0000000000000000", "5199C29A52C9F059");
	res |= testd("0101014001010101", "0000000000000000", "C22F0A294A71F29F");
	res |= testd("0101012001010101", "0000000000000000", "EE371483714C02EA");
	res |= testd("0101011001010101", "0000000000000000", "A81FBD448F9E522F");
	res <<= 1;
	res |= testd("0101010801010101", "0000000000000000", "4F644C92E192DFED");
	res |= testd("0101010401010101", "0000000000000000", "1AFA9A66A6DF92AE");
	res |= testd("0101010201010101", "0000000000000000", "B3C1CC715CB879D8");
	res |= testd("0101010180010101", "0000000000000000", "19D032E64AB0BD8B");
	res |= testd("0101010140010101", "0000000000000000", "3CFAA7A7DC8720DC");
	res |= testd("0101010120010101", "0000000000000000", "B7265F7F447AC6F3");
	res |= testd("0101010110010101", "0000000000000000", "9DB73B3C0D163F54");
	res |= testd("0101010108010101", "0000000000000000", "8181B65BABF4A975");
	res <<= 1;
	res |= testd("0101010104010101", "0000000000000000", "93C9B64042EAA240");
	res |= testd("0101010102010101", "0000000000000000", "5570530829705592");
	res |= testd("0101010101800101", "0000000000000000", "8638809E878787A0");
	res |= testd("0101010101400101", "0000000000000000", "41B9A79AF79AC208");
	res |= testd("0101010101200101", "0000000000000000", "7A9BE42F2009A892");
	res |= testd("0101010101100101", "0000000000000000", "29038D56BA6D2745");
	res |= testd("0101010101080101", "0000000000000000", "5495C6ABF1E5DF51");
	res |= testd("0101010101040101", "0000000000000000", "AE13DBD561488933");
	res <<= 1;
	res |= testd("0101010101020101", "0000000000000000", "024D1FFA8904E389");
	res |= testd("0101010101018001", "0000000000000000", "D1399712F99BF02E");
	res |= testd("0101010101014001", "0000000000000000", "14C1D7C1CFFEC79E");
	res |= testd("0101010101012001", "0000000000000000", "1DE5279DAE3BED6F");
	res |= testd("0101010101011001", "0000000000000000", "E941A33F85501303");
	res |= testd("0101010101010801", "0000000000000000", "DA99DBBC9A03F379");
	res |= testd("0101010101010401", "0000000000000000", "B7FC92F91D8E92E9");
	res |= testd("0101010101010201", "0000000000000000", "AE8E5CAA3CA04E85");
	res <<= 1;
	res |= testd("0101010101010180", "0000000000000000", "9CC62DF43B6EED74");
	res |= testd("0101010101010140", "0000000000000000", "D863DBB5C59A91A0");
	res |= testd("0101010101010120", "0000000000000000", "A1AB2190545B91D7");
	res |= testd("0101010101010110", "0000000000000000", "0875041E64C570F7");
	res |= testd("0101010101010108", "0000000000000000", "5A594528BEBEF1CC");
	res |= testd("0101010101010104", "0000000000000000", "FCDB3291DE21F0C0");
	res |= testd("0101010101010102", "0000000000000000", "869EFD7F9F265A09");
	res |= testd("1046913489980131", "0000000000000000", "88D55E54F54C97B4");
	res <<= 1;
	res |= testd("1007103489988020", "0000000000000000", "0C0CC00C83EA48FD");
	res |= testd("10071034C8980120", "0000000000000000", "83BC8EF3A6570183");
	res |= testd("1046103489988020", "0000000000000000", "DF725DCAD94EA2E9");
	res |= testd("1086911519190101", "0000000000000000", "E652B53B550BE8B0");
	res |= testd("1086911519580101", "0000000000000000", "AF527120C485CBB0");
	res |= testd("5107B01519580101", "0000000000000000", "0F04CE393DB926D5");
	res |= testd("1007B01519190101", "0000000000000000", "C9F00FFC74079067");
	res |= testd("3107915498080101", "0000000000000000", "7CFD82A593252B4E");
	res <<= 1;
	res |= testd("3107919498080101", "0000000000000000", "CB49A2F9E91363E3");
	res |= testd("10079115B9080140", "0000000000000000", "00B588BE70D23F56");
	res |= testd("3107911598080140", "0000000000000000", "406A9A6AB43399AE");
	res |= testd("1007D01589980101", "0000000000000000", "6CB773611DCA9ADA");
	res |= testd("9107911589980101", "0000000000000000", "67FD21C17DBB5D70");
	res |= testd("9107D01589190101", "0000000000000000", "9592CB4110430787");
	res |= testd("1007D01598980120", "0000000000000000", "A6B7FF68A318DDD3");
	res |= testd("1007940498190101", "0000000000000000", "4D102196C914CA16");
	res <<= 1;
	res |= testd("0107910491190401", "0000000000000000", "2DFA9F4573594965");
	res |= testd("0107910491190101", "0000000000000000", "B46604816C0E0774");
	res |= testd("0107940491190401", "0000000000000000", "6E7E6221A4F34E87");
	res |= testd("19079210981A0101", "0000000000000000", "AA85E74643233199");
	res |= testd("1007911998190801", "0000000000000000", "2E5A19DB4D1962D6");
	res |= testd("10079119981A0801", "0000000000000000", "23A866A809D30894");
	res |= testd("1007921098190101", "0000000000000000", "D812D961F017D320");
	res |= testd("100791159819010B", "0000000000000000", "055605816E58608F");
	res <<= 1;
	res |= testd("1004801598190101", "0000000000000000", "ABD88E8B1B7716F1");
	res |= testd("1004801598190102", "0000000000000000", "537AC95BE69DA1E1");
	res |= testd("1004801598190108", "0000000000000000", "AED0F6AE3C25CDD8");
	res |= testd("1002911498100104", "0000000000000000", "B3E35A5EE53E7B8D");
	res |= testd("1002911598190104", "0000000000000000", "61C79C71921A2EF8");
	res |= testd("1002911598100201", "0000000000000000", "E2F5728F0995013C");
	res |= testd("1002911698100101", "0000000000000000", "1AEAC39A61F0A464");
	res |= testd("7CA110454A1A6E57", "01A1D6D039776742", "690F5B0D9A26939B");
	res <<= 1;
	res |= testd("0131D9619DC1376E", "5CD54CA83DEF57DA", "7A389D10354BD271");
	res |= testd("07A1133E4A0B2686", "0248D43806F67172", "868EBB51CAB4599A");
	res |= testd("3849674C2602319E", "51454B582DDF440A", "7178876E01F19B2A");
	res |= testd("04B915BA43FEB5B6", "42FD443059577FA2", "AF37FB421F8C4095");
	res |= testd("0113B970FD34F2CE", "059B5E0851CF143A", "86A560F10EC6D85B");
	res |= testd("0170F175468FB5E6", "0756D8E0774761D2", "0CD3DA020021DC09");
	res |= testd("43297FAD38E373FE", "762514B829BF486A", "EA676B2CB7DB2B7A");
	res |= testd("07A7137045DA2A16", "3BDD119049372802", "DFD64A815CAF1A0F");
	res <<= 1;
	res |= testd("04689104C2FD3B2F", "26955F6835AF609A", "5C513C9C4886C088");
	res |= testd("37D06BB516CB7546", "164D5E404F275232", "0A2AEEAE3FF4AB77");
	res |= testd("1F08260D1AC2465E", "6B056E18759F5CCA", "EF1BF03E5DFA575A");
	res |= testd("584023641ABA6176", "004BD6EF09176062", "88BF0DB6D70DEE56");
	res |= testd("025816164629B007", "480D39006EE762F2", "A1F9915541020B56");
	res |= testd("49793EBC79B3258F", "437540C8698F3CFA", "6FBF1CAFCFFD0556");
	res |= testd("4FB05E1515AB73A7", "072D43A077075292", "2F22E49BAB7CA1AC");
	res |= testd("49E95D6D4CA229BF", "02FE55778117F12A", "5A6B612CC26CCE4A");
	res <<= 1;
	res |= testd("018310DC409B26D6", "1D9D5C5018F728C2", "5F4C038ED12B2E41");
	res |= testd("1C587F1C13924FEF", "305532286D6F295A", "63FAC0D034D9F793");

	return res;
}

	PLUGIN_STRUCTURE(des, drew::DES)
	PLUGIN_STRUCTURE(desede, drew::TripleDES)
	PLUGIN_DATA_START()
	PLUGIN_DATA(des, "DES")
	PLUGIN_DATA(desede, "DESede")
	PLUGIN_DATA_END()
	PLUGIN_INTERFACE()
}


/* permuted choice table (key) */
static const uint8_t pc1[] = {
	   57, 49, 41, 33, 25, 17,  9,
		1, 58, 50, 42, 34, 26, 18,
	   10,  2, 59, 51, 43, 35, 27,
	   19, 11,  3, 60, 52, 44, 36,

	   63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
	   14,  6, 61, 53, 45, 37, 29,
	   21, 13,  5, 28, 20, 12,  4
};

/* number left rotations of pc1 */
static const uint8_t totrot[] = {
	   1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28
};

/* permuted choice key (table) */
static const uint8_t pc2[] = {
	   14, 17, 11, 24,  1,  5,
		3, 28, 15,  6, 21, 10,
	   23, 19, 12,  4, 26,  8,
	   16,  7, 27, 20, 13,  2,
	   41, 52, 31, 37, 47, 55,
	   30, 40, 51, 45, 33, 48,
	   44, 49, 39, 56, 34, 53,
	   46, 42, 50, 36, 29, 32
};

/* End of DES-defined tables */

/* bit 0 is left-most in byte */
static const int bytebit[] = {
	   0200,0100,040,020,010,04,02,01
};

static inline uint32_t rol(uint32_t x, size_t n)
{
	return (x << n) | (x >> (32-n));
}

static inline uint32_t ror(uint32_t x, size_t n)
{
	return (x >> n) | (x << (32-n));
}

static inline void IPERM(uint32_t &left, uint32_t &right)
{
	uint32_t work;

	right = rol(right, 4U);
	work = (left ^ right) & 0xf0f0f0f0;
	left ^= work;
	right = ror(right^work, 20U);
	work = (left ^ right) & 0xffff0000;
	left ^= work;
	right = ror(right^work, 18U);
	work = (left ^ right) & 0x33333333;
	left ^= work;
	right = ror(right^work, 6U);
	work = (left ^ right) & 0x00ff00ff;
	left ^= work;
	right = rol(right^work, 9U);
	work = (left ^ right) & 0xaaaaaaaa;
	left = rol(left^work, 1U);
	right ^= work;
}

static inline void FPERM(uint32_t &left, uint32_t &right)
{
	uint32_t work;

	right = ror(right, 1U);
	work = (left ^ right) & 0xaaaaaaaa;
	right ^= work;
	left = ror(left^work, 9U);
	work = (left ^ right) & 0x00ff00ff;
	right ^= work;
	left = rol(left^work, 6U);
	work = (left ^ right) & 0x33333333;
	right ^= work;
	left = rol(left^work, 18U);
	work = (left ^ right) & 0xffff0000;
	right ^= work;
	left = rol(left^work, 20U);
	work = (left ^ right) & 0xf0f0f0f0;
	right ^= work;
	left = ror(left^work, 4U);
}

typedef drew::DES::endian_t E;

drew::DES::DES()
{
}

drew::TripleDES::TripleDES()
{
}

void drew::DES::SetKey(const uint8_t *key, size_t len)
{
	uint8_t buffer[56+56+8];
	uint8_t *const pc1m = buffer;
	uint8_t *const pcr = pc1m + 56;
	uint8_t *const ks = pcr+56;
	
	for (int j = 0; j < 56; j++) {
		int l = pc1[j] - 1;
		int m = l & 07;
		pc1m[j] = (key[l>>3] & bytebit[m]) ? 1 : 0;
	}
	for (int i = 0; i < 16; i++) {
		memset(ks, 0, 8);
		for (int j = 0; j < 56; j++) {
			int l;
			pcr[j] = pc1m[(l=j+totrot[i])<(j<28? 28 : 56) ? l: l-28];
		}
		for (int j = 0; j < 48; j++) {
			if (pcr[pc2[j]-1]) {
				int l = j % 6;
				ks[j/6] |= bytebit[l] >> 2;
			}
		}
		m_k[2*i] = ((uint32_t)ks[0] << 24)
			| ((uint32_t)ks[2] << 16)
			| ((uint32_t)ks[4] << 8)
			| ((uint32_t)ks[6]);
		m_k[2*i+1] = ((uint32_t)ks[1] << 24)
			| ((uint32_t)ks[3] << 16)
			| ((uint32_t)ks[5] << 8)
			| ((uint32_t)ks[7]);
	}

	memcpy(m_kd, m_k, sizeof(m_k));
	for (int i = 0; i < 16; i += 2)
	{
		std::swap(m_kd[i], m_kd[32-2-i]);
		std::swap(m_kd[i+1], m_kd[32-1-i]);
	}
}

void drew::TripleDES::SetKey(const uint8_t *key, size_t len)
{
	m_des1.SetKey(key, 8);
	m_des2.SetKey(key+8, 8);
	m_des3.SetKey(key+(len == 24 ? 16 : 0), 8);

}

void drew::DES::ProcessBlock(const uint32_t *k, uint32_t &m, uint32_t &s) const
{
	uint32_t l = m, r = s;
	const uint32_t *kptr = k;

	for (unsigned i = 0; i < 8; i++, kptr += 4)
	{
		uint32_t work = ror(r, 4) ^ kptr[0];
		l ^= Spbox[6][(work) & 0x3f]
		  ^  Spbox[4][(work >> 8) & 0x3f]
		  ^  Spbox[2][(work >> 16) & 0x3f]
		  ^  Spbox[0][(work >> 24) & 0x3f];
		work = r ^ kptr[1];
		l ^= Spbox[7][(work) & 0x3f]
		  ^  Spbox[5][(work >> 8) & 0x3f]
		  ^  Spbox[3][(work >> 16) & 0x3f]
		  ^  Spbox[1][(work >> 24) & 0x3f];

		work = ror(l, 4) ^ kptr[2];
		r ^= Spbox[6][(work) & 0x3f]
		  ^  Spbox[4][(work >> 8) & 0x3f]
		  ^  Spbox[2][(work >> 16) & 0x3f]
		  ^  Spbox[0][(work >> 24) & 0x3f];
		work = l ^ kptr[3];
		r ^= Spbox[7][(work) & 0x3f]
		  ^  Spbox[5][(work >> 8) & 0x3f]
		  ^  Spbox[3][(work >> 16) & 0x3f]
		  ^  Spbox[1][(work >> 24) & 0x3f];
	}

	m = l; s = r;
}

void drew::DES::Encrypt(uint8_t *out, const uint8_t *in)
{
	uint32_t x[2];

	E::Copy(x, in, sizeof(x));
	IPERM(x[0], x[1]);
	ProcessBlock(m_k, x[0], x[1]);
	FPERM(x[0], x[1]);
	E::Copy(out, x, sizeof(x));
}

void drew::TripleDES::Encrypt(uint8_t *out, const uint8_t *in)
{
	uint32_t x[2];
	const drew::DES *d1 = &m_des1, *d2 = &m_des2, *d3 = &m_des3;

	E::Copy(x, in, sizeof(x));
	IPERM(x[0], x[1]);
	d1->ProcessBlock(d1->m_k, x[0], x[1]);
	d2->ProcessBlock(d2->m_kd, x[1], x[0]);
	d3->ProcessBlock(d3->m_k, x[0], x[1]);
	FPERM(x[0], x[1]);
	E::Copy(out, x, sizeof(x));
}

void drew::DES::Decrypt(uint8_t *out, const uint8_t *in)
{
	uint32_t x[2];

	E::Copy(x, in, sizeof(x));
	IPERM(x[0], x[1]);
	ProcessBlock(m_kd, x[0], x[1]);
	FPERM(x[0], x[1]);
	E::Copy(out, x, sizeof(x));
}

void drew::TripleDES::Decrypt(uint8_t *out, const uint8_t *in)
{
	uint32_t x[2];
	const drew::DES *d1 = &m_des3, *d2 = &m_des2, *d3 = &m_des1;

	E::Copy(x, in, sizeof(x));
	IPERM(x[0], x[1]);
	d1->ProcessBlock(d1->m_kd, x[0], x[1]);
	d2->ProcessBlock(d2->m_k, x[1], x[0]);
	d3->ProcessBlock(d3->m_kd, x[0], x[1]);
	FPERM(x[0], x[1]);
	E::Copy(out, x, sizeof(x));
}

const uint32_t drew::DES::Spbox[8][64] = {
{
0x01010400,0x00000000,0x00010000,0x01010404, 0x01010004,0x00010404,0x00000004,0x00010000,
0x00000400,0x01010400,0x01010404,0x00000400, 0x01000404,0x01010004,0x01000000,0x00000004,
0x00000404,0x01000400,0x01000400,0x00010400, 0x00010400,0x01010000,0x01010000,0x01000404,
0x00010004,0x01000004,0x01000004,0x00010004, 0x00000000,0x00000404,0x00010404,0x01000000,
0x00010000,0x01010404,0x00000004,0x01010000, 0x01010400,0x01000000,0x01000000,0x00000400,
0x01010004,0x00010000,0x00010400,0x01000004, 0x00000400,0x00000004,0x01000404,0x00010404,
0x01010404,0x00010004,0x01010000,0x01000404, 0x01000004,0x00000404,0x00010404,0x01010400,
0x00000404,0x01000400,0x01000400,0x00000000, 0x00010004,0x00010400,0x00000000,0x01010004},
{
0x80108020,0x80008000,0x00008000,0x00108020, 0x00100000,0x00000020,0x80100020,0x80008020,
0x80000020,0x80108020,0x80108000,0x80000000, 0x80008000,0x00100000,0x00000020,0x80100020,
0x00108000,0x00100020,0x80008020,0x00000000, 0x80000000,0x00008000,0x00108020,0x80100000,
0x00100020,0x80000020,0x00000000,0x00108000, 0x00008020,0x80108000,0x80100000,0x00008020,
0x00000000,0x00108020,0x80100020,0x00100000, 0x80008020,0x80100000,0x80108000,0x00008000,
0x80100000,0x80008000,0x00000020,0x80108020, 0x00108020,0x00000020,0x00008000,0x80000000,
0x00008020,0x80108000,0x00100000,0x80000020, 0x00100020,0x80008020,0x80000020,0x00100020,
0x00108000,0x00000000,0x80008000,0x00008020, 0x80000000,0x80100020,0x80108020,0x00108000},
{
0x00000208,0x08020200,0x00000000,0x08020008, 0x08000200,0x00000000,0x00020208,0x08000200,
0x00020008,0x08000008,0x08000008,0x00020000, 0x08020208,0x00020008,0x08020000,0x00000208,
0x08000000,0x00000008,0x08020200,0x00000200, 0x00020200,0x08020000,0x08020008,0x00020208,
0x08000208,0x00020200,0x00020000,0x08000208, 0x00000008,0x08020208,0x00000200,0x08000000,
0x08020200,0x08000000,0x00020008,0x00000208, 0x00020000,0x08020200,0x08000200,0x00000000,
0x00000200,0x00020008,0x08020208,0x08000200, 0x08000008,0x00000200,0x00000000,0x08020008,
0x08000208,0x00020000,0x08000000,0x08020208, 0x00000008,0x00020208,0x00020200,0x08000008,
0x08020000,0x08000208,0x00000208,0x08020000, 0x00020208,0x00000008,0x08020008,0x00020200},
{
0x00802001,0x00002081,0x00002081,0x00000080, 0x00802080,0x00800081,0x00800001,0x00002001,
0x00000000,0x00802000,0x00802000,0x00802081, 0x00000081,0x00000000,0x00800080,0x00800001,
0x00000001,0x00002000,0x00800000,0x00802001, 0x00000080,0x00800000,0x00002001,0x00002080,
0x00800081,0x00000001,0x00002080,0x00800080, 0x00002000,0x00802080,0x00802081,0x00000081,
0x00800080,0x00800001,0x00802000,0x00802081, 0x00000081,0x00000000,0x00000000,0x00802000,
0x00002080,0x00800080,0x00800081,0x00000001, 0x00802001,0x00002081,0x00002081,0x00000080,
0x00802081,0x00000081,0x00000001,0x00002000, 0x00800001,0x00002001,0x00802080,0x00800081,
0x00002001,0x00002080,0x00800000,0x00802001, 0x00000080,0x00800000,0x00002000,0x00802080},
{
0x00000100,0x02080100,0x02080000,0x42000100, 0x00080000,0x00000100,0x40000000,0x02080000,
0x40080100,0x00080000,0x02000100,0x40080100, 0x42000100,0x42080000,0x00080100,0x40000000,
0x02000000,0x40080000,0x40080000,0x00000000, 0x40000100,0x42080100,0x42080100,0x02000100,
0x42080000,0x40000100,0x00000000,0x42000000, 0x02080100,0x02000000,0x42000000,0x00080100,
0x00080000,0x42000100,0x00000100,0x02000000, 0x40000000,0x02080000,0x42000100,0x40080100,
0x02000100,0x40000000,0x42080000,0x02080100, 0x40080100,0x00000100,0x02000000,0x42080000,
0x42080100,0x00080100,0x42000000,0x42080100, 0x02080000,0x00000000,0x40080000,0x42000000,
0x00080100,0x02000100,0x40000100,0x00080000, 0x00000000,0x40080000,0x02080100,0x40000100},
{
0x20000010,0x20400000,0x00004000,0x20404010, 0x20400000,0x00000010,0x20404010,0x00400000,
0x20004000,0x00404010,0x00400000,0x20000010, 0x00400010,0x20004000,0x20000000,0x00004010,
0x00000000,0x00400010,0x20004010,0x00004000, 0x00404000,0x20004010,0x00000010,0x20400010,
0x20400010,0x00000000,0x00404010,0x20404000, 0x00004010,0x00404000,0x20404000,0x20000000,
0x20004000,0x00000010,0x20400010,0x00404000, 0x20404010,0x00400000,0x00004010,0x20000010,
0x00400000,0x20004000,0x20000000,0x00004010, 0x20000010,0x20404010,0x00404000,0x20400000,
0x00404010,0x20404000,0x00000000,0x20400010, 0x00000010,0x00004000,0x20400000,0x00404010,
0x00004000,0x00400010,0x20004010,0x00000000, 0x20404000,0x20000000,0x00400010,0x20004010},
{
0x00200000,0x04200002,0x04000802,0x00000000, 0x00000800,0x04000802,0x00200802,0x04200800,
0x04200802,0x00200000,0x00000000,0x04000002, 0x00000002,0x04000000,0x04200002,0x00000802,
0x04000800,0x00200802,0x00200002,0x04000800, 0x04000002,0x04200000,0x04200800,0x00200002,
0x04200000,0x00000800,0x00000802,0x04200802, 0x00200800,0x00000002,0x04000000,0x00200800,
0x04000000,0x00200800,0x00200000,0x04000802, 0x04000802,0x04200002,0x04200002,0x00000002,
0x00200002,0x04000000,0x04000800,0x00200000, 0x04200800,0x00000802,0x00200802,0x04200800,
0x00000802,0x04000002,0x04200802,0x04200000, 0x00200800,0x00000000,0x00000002,0x04200802,
0x00000000,0x00200802,0x04200000,0x00000800, 0x04000002,0x04000800,0x00000800,0x00200002},
{
0x10001040,0x00001000,0x00040000,0x10041040, 0x10000000,0x10001040,0x00000040,0x10000000,
0x00040040,0x10040000,0x10041040,0x00041000, 0x10041000,0x00041040,0x00001000,0x00000040,
0x10040000,0x10000040,0x10001000,0x00001040, 0x00041000,0x00040040,0x10040040,0x10041000,
0x00001040,0x00000000,0x00000000,0x10040040, 0x10000040,0x10001000,0x00041040,0x00040000,
0x00041040,0x00040000,0x10041000,0x00001000, 0x00000040,0x10040040,0x00001000,0x00041040,
0x10001000,0x00000040,0x10000040,0x10040000, 0x10040040,0x10000000,0x00040000,0x10001040,
0x00000000,0x10041040,0x00040040,0x10000040, 0x10040000,0x10001000,0x10001040,0x00000000,
0x10041040,0x00041000,0x00041000,0x00001040, 0x00001040,0x00040040,0x10000000,0x10041000}
};