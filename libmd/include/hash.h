/*-
 * brian m. carlson <sandals@crustytoothpaste.ath.cx> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
/* This code implements generic hash contexts.  This implementation
 * requires ANSI C.
 */

#ifndef BMC_HASH_H
#define BMC_HASH_H

#include <stddef.h>
#include <stdint.h>

/* This structure is only here for size purposes.  Do not access its members. */
#define DREW_LIBMD_HASH_STRUCT(name, quant, dlen, blen) \
typedef struct name { \
	quant hash[dlen/sizeof(quant)]; \
	quant len[2]; \
	uint8_t buf[blen]; \
} name;

#endif
