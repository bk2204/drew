/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#define ALGO_PLUGIN_NAME	"sha512"
#define ALGO_NAME			"SHA-512"
#define ALGO_BLOCK_SIZE		128
#define ALGO_DIGEST_SIZE	(512 / 8)
#include "sum.c"
