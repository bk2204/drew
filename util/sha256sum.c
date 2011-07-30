/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#define ALGO_PLUGIN_NAME	"sha256"
#define ALGO_NAME			"SHA-256"
#define ALGO_BLOCK_SIZE		64
#define ALGO_DIGEST_SIZE	(256 / 8)
#include "sum.c"
