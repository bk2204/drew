#include "internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <drew/plugin.h>

#include <drew-tls/priority.h>

#define M_NONE	0
#define M_HMAC	1
#define M_GOST	2
#define M_MAX	M_GOST

#define K_NONE	0
#define K_RSA	1
#define K_EDH	2
#define K_ECEDH	3
#define K_MAX	K_ECEDH

#define P_NONE		0
#define P_RSA		1
#define P_DSA		2
#define P_ECDSA		3
#define P_MAX		P_ECDSA

#define C_NONE			0
#define C_AES128		1
#define C_AES256		2
#define C_CAMELLIA128	3
#define C_CAMELLIA256	4
#define C_3DES			5
#define C_DES			6
#define C_RC4			7
#define C_RC2			8
#define C_IDEA			9
#define C_SEED			10
#define C_ARIA128		11
#define C_ARIA256		12
#define C_MAX			C_ARIA256

#define H_NONE		0
#define H_MD5		1
#define H_SHA1		2
#define H_SHA224	3
#define H_SHA256	4
#define H_SHA384	5
#define H_SHA512	6
#define H_MAX		H_SHA512

#define F_FORBIDDEN			(1 << 0)
#define F_EXPORT			(1 << 1)

struct item {
	uint8_t val[2];
	int flags;
	int mac;
	int keyex;
	int pkauth;
	int cipher;
	int hash;
};

static const char *macnames[M_MAX+1] = {
	[M_NONE] = NULL,
	[M_HMAC] = "HMAC",
	[M_GOST] = "GOST"
};

static const char *keyexnames[K_MAX+1] = {
	[K_NONE] = NULL,
	[K_RSA] = "RSA",
	[K_EDH] = "Diffie-Hellman",
	[K_ECEDH] = "Elliptic Curve Diffie-Hellman"
};

static const char *pubkeynames[P_MAX+1] = {
	[P_NONE] = NULL,
	[P_RSA] = "RSA",
	[P_DSA] = "DSA",
	[P_ECDSA] = "Elliptic Curve DSA"
};

static const char *ciphernames[C_MAX+1] = {
	[C_NONE] = NULL,
	[C_AES128] = "AES128",
	[C_AES256] = "AES256",
	[C_CAMELLIA128] = "Camellia",
	[C_CAMELLIA256] = "Camellia",
	[C_3DES] = "DESede",
	[C_DES] = "DES",
	[C_RC4] = "RC4",
	[C_RC2] = "RC2",
	[C_IDEA] = "IDEA",
	[C_SEED] = "SEED",
	[C_ARIA128] = "ARIA",
	[C_ARIA256] = "ARIA"
};

static const size_t ciphersizes[C_MAX+1] = {
	[C_NONE] = 0,
	[C_AES128] = 16,
	[C_AES256] = 32,
	[C_CAMELLIA128] = 16,
	[C_CAMELLIA256] = 32,
	[C_3DES] = 24,
	[C_DES] = 8,
	[C_RC4] = 16,
	[C_RC2] = 16,
	[C_IDEA] = 16,
	[C_SEED] = 16,
	[C_ARIA128] = 16,
	[C_ARIA256] = 32
};

static const char *hashnames[H_MAX+1] = {
	[H_NONE] = NULL,
	[H_MD5] = "MD5",
	[H_SHA1] = "SHA-1",
	[H_SHA224] = "SHA-224",
	[H_SHA256] = "SHA-256",
	[H_SHA384] = "SHA-384",
	[H_SHA512] = "SHA-512"
};

static const struct item implemented[] = {
	// We implement the identity algorithm only because it's used before
	// anything else is negotiated.
	{{0x00, 0x00}, F_FORBIDDEN, M_NONE, K_NONE, P_NONE, C_NONE, H_NONE},
	// Required for IMAP4rev1 (RFC 3501).
	{{0x00, 0x04}, 0, M_HMAC, K_RSA, P_RSA, C_RC4, H_MD5},
	{{0x00, 0x05}, 0, M_HMAC, K_RSA, P_RSA, C_RC4, H_SHA1},
	{{0x00, 0x0a}, 0, M_HMAC, K_RSA, P_RSA, C_3DES, H_SHA1},
	// Required for TLS 1.0 (RFC 2246); recommended for IMAP4rev1.
	{{0x00, 0x13}, 0, M_HMAC, K_EDH, P_DSA, C_3DES, H_SHA1},
	{{0x00, 0x16}, 0, M_HMAC, K_EDH, P_RSA, C_3DES, H_SHA1},
	// Required for TLS 1.2 (RFC 5246).
	{{0x00, 0x2f}, 0, M_HMAC, K_RSA, P_RSA, C_AES128, H_SHA1},
	{{0x00, 0x32}, 0, M_HMAC, K_EDH, P_DSA, C_AES128, H_SHA1},
	{{0x00, 0x33}, 0, M_HMAC, K_EDH, P_RSA, C_AES128, H_SHA1},
	{{0x00, 0x35}, 0, M_HMAC, K_RSA, P_RSA, C_AES256, H_SHA1},
	{{0x00, 0x38}, 0, M_HMAC, K_EDH, P_DSA, C_AES256, H_SHA1},
	{{0x00, 0x39}, 0, M_HMAC, K_EDH, P_RSA, C_AES256, H_SHA1},
	{{0x00, 0x3c}, 0, M_HMAC, K_RSA, P_RSA, C_AES128, H_SHA256},
	{{0x00, 0x3d}, 0, M_HMAC, K_RSA, P_RSA, C_AES256, H_SHA256},
	{{0x00, 0x40}, 0, M_HMAC, K_EDH, P_DSA, C_AES128, H_SHA256},
	{{0x00, 0x41}, 0, M_HMAC, K_RSA, P_RSA, C_CAMELLIA128, H_SHA1},
	{{0x00, 0x44}, 0, M_HMAC, K_EDH, P_DSA, C_CAMELLIA128, H_SHA1},
	{{0x00, 0x45}, 0, M_HMAC, K_EDH, P_RSA, C_CAMELLIA128, H_SHA1},
	{{0x00, 0x67}, 0, M_HMAC, K_EDH, P_RSA, C_AES128, H_SHA256},
	{{0x00, 0x6a}, 0, M_HMAC, K_EDH, P_DSA, C_AES256, H_SHA256},
	{{0x00, 0x6b}, 0, M_HMAC, K_EDH, P_RSA, C_AES256, H_SHA256},
	{{0x00, 0x84}, 0, M_HMAC, K_RSA, P_RSA, C_CAMELLIA256, H_SHA1},
	{{0x00, 0x87}, 0, M_HMAC, K_EDH, P_DSA, C_CAMELLIA256, H_SHA1},
	{{0x00, 0x88}, 0, M_HMAC, K_EDH, P_RSA, C_CAMELLIA256, H_SHA1},
};

#define FLAG_NONE		0
#define FLAG_REMOVED	1
#define FLAG_PURGED		2

struct entry {
	int flags;
	const struct item *cs;
};

struct drew_tls_priority_s {
	struct entry entries[DIM(implemented)];
	DREW_TLS_MUTEX_DECL()
};

int drew_tls_priority_init(drew_tls_priority_t *prio)
{
	drew_tls_priority_t p;
	if (!(p = malloc(sizeof(*p))))
		return -ENOMEM;

	DREW_TLS_MUTEX_INIT(p);

	for (size_t i = 0; i < DIM(implemented); i++) {
		const struct item *cs = implemented+i;
		p->entries[i].cs = cs;
		p->entries[i].flags = cs->flags & F_FORBIDDEN ? FLAG_PURGED : FLAG_NONE;
	}

	drew_tls_priority_set_sensible_default(p);

	*prio = p;

	return 0;
}

/* This is my opinion of a sensible default.  YMMV.
 *
 * An algorithm is sorted first by its cipher.  Ciphers are sorted first by
 * their length, then AES over Camellia over SEED over ARIA (AES is more
 * analyzed than Camellia, and so forth).  3DES is treated as 112 bits even
 * though 168 bits of key are used because the strength is equivalent, but 3DES
 * is always sorted over RC4, since RC4 is on its way out.
 *
 * Next algorithms are sorted by their hash size.  Bigger is better.
 *
 * RSA is sorted over DSA.
 *
 * Ephemeral Diffie-Hellman is sorted over other key exchange.
 */
static const int sensible_cipher[] = {
	-1000, /* C_NONE */
	-11, /* C_AES128 */
	-1, /* C_AES256 */
	-12, /* C_CAMELLIA128 */
	-2, /* C_CAMELLIA256 */
	-21, /* C_3DES */
	-400, /* C_DES */
	-22, /* C_RC4 */
	-500, /* C_RC2 */
	-16, /* C_IDEA */
	-15, /* C_SEED */
	-14, /* C_ARIA128 */
	-4 /* C_ARIA256 */
};

// We want to sort from most preferable to least preferable, so the comparison
// function should mark more desirable things as "smaller" and thus return -1.
#define COMPARE(x, y) do { \
	int tmp = (x) - (y); \
	if (tmp) return tmp < 0 ? 1 : -1; \
} while (0)

static int sensible_compare(const void *ap, const void *bp)
{
	const struct entry *a = ap, *b = bp;

	COMPARE(sensible_cipher[a->cs->cipher], sensible_cipher[b->cs->cipher]);
	COMPARE(a->cs->hash, b->cs->hash);
	COMPARE(-a->cs->pkauth, -b->cs->pkauth);
	COMPARE(a->cs->keyex, b->cs->keyex);

	// Uh, oh.  More criteria.
	return 0;
}

int drew_tls_priority_set_sensible_default(drew_tls_priority_t prio)
{
	LOCK(prio);

	qsort(prio->entries, DIM(prio->entries), sizeof(prio->entries[0]),
			sensible_compare);

	UNLOCK(prio);
	return 0;
}

int drew_tls_priority_fini(drew_tls_priority_t *prio)
{
	if (!prio)
		return -DREW_ERR_INVALID;

	DREW_TLS_MUTEX_FINI(*prio);

	free(*prio);
	return 0;
}

int drew_tls_priority_set_string(drew_tls_priority_t prio, const char *s)
{
	return -DREW_ERR_NOT_IMPL;
}

int drew_tls_priority_get_cipher_suite_info(drew_tls_priority_t prio,
		drew_tls_cipher_suite_info_t *info, const drew_tls_cipher_suite_t *cs)
{
	// This does not need a lock since it does not use prio.
	for (size_t i = 0; i < DIM(implemented); i++) {
		if (!memcmp(cs->val, implemented[i].val, sizeof(cs->val))) {
			info->flags = implemented[i].flags;
			info->mac = macnames[implemented[i].mac];
			info->keyex = keyexnames[implemented[i].keyex];
			info->pkauth = pubkeynames[implemented[i].pkauth];
			info->hash = hashnames[implemented[i].hash];
			info->cipher = ciphernames[implemented[i].cipher];
			info->cipher_key_len = ciphersizes[implemented[i].cipher];
			return 0;
		}
	}
	return -DREW_ERR_INVALID;
}

int drew_tls_priority_get_cipher_suites(drew_tls_priority_t prio,
		drew_tls_cipher_suite_t **suites, size_t *nsuites)
{
	int res = 0;
	LOCK(prio);

	// Yes, this is two-pass.
	size_t n = 0;

	for (size_t i = 0; i < DIM(prio->entries); i++)
		if (!prio->entries[i].flags)
			n++;

	drew_tls_cipher_suite_t *buf;
	if (!(buf = malloc(sizeof(*buf) * n)))
		URETFAIL(prio, -ENOMEM);
	
	for (size_t i = 0, j = 0; i < DIM(prio->entries); i++)
		if (!prio->entries[i].flags)
			memcpy(buf[j++].val, prio->entries[i].cs->val, sizeof(buf[j].val));

	*nsuites = n;
	*suites = buf;

	UNLOCK(prio);
	return 0;
}
