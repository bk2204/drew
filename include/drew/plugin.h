/*-
 * Copyright © 2010–2011 brian m. carlson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef DREW_PLUGIN_H
#define DREW_PLUGIN_H

#include <drew/drew.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* object is a URI or IRI. */
#define DREW_LOADER_MD_URI 0
#define DREW_LOADER_MD_IRI DREW_LOADER_MD_URI
/* object is a literal value. */
#define DREW_LOADER_MD_LITERAL 1
/* object is the name of a blank node. */
#define DREW_LOADER_MD_BLANK 2

typedef struct {
	int version;			// Must be one.
	const char *subject;	// Must be NULL (rdf:about="") or a blank node name.
	const char *predicate;	// The full IRI of an RDF predicate.
	int type;				// A DREW_LOADER_MD constant.
	const char *object;		// An IRI, literal value, or blank node name.
} drew_metadata_t;

struct drew_loader_s;
typedef struct drew_loader_s drew_loader_t;

#define DREW_LOADER_LOOKUP_NAME 2
#define DREW_LOADER_GET_NPLUGINS 3
#define DREW_LOADER_GET_TYPE 4
#define DREW_LOADER_GET_FUNCTBL_SIZE 5
#define DREW_LOADER_GET_FUNCTBL 6
#define DREW_LOADER_GET_NAME_SIZE 7
#define DREW_LOADER_GET_NAME 8
#define DREW_LOADER_GET_METADATA_SIZE 9
#define DREW_LOADER_GET_METADATA 10

#define DREW_TYPE_HASH 1
#define DREW_TYPE_BLOCK 2
#define DREW_TYPE_MODE 3
#define DREW_TYPE_MAC 4
#define DREW_TYPE_STREAM 5
#define DREW_TYPE_PRNG 6
#define DREW_TYPE_BIGNUM 7
#define DREW_TYPE_PKENC 8
#define DREW_TYPE_PKSIG 9
#define DREW_TYPE_KDF 10
#define DREW_TYPE_ECC 11

/* The system dynamic loader failed. */
#define DREW_ERR_RESOLUTION		0x10001
/* There was an error getting information from the plugin. */
#define DREW_ERR_ENUMERATION	0x10002
/* There was an error getting function information from the plugin. */
#define DREW_ERR_FUNCTION		0x10003
/* The behavior requested is not allowed on this object. */
#define DREW_ERR_NOT_ALLOWED	0x10004
/* The behavior requested is not implemented. */
#define DREW_ERR_NOT_IMPL		0x10005
/* The value passed was not valid. */
#define DREW_ERR_INVALID		0x10006
/* More information is needed to complete the request. */
#define DREW_ERR_MORE_INFO		0x10007
/* The implementation had an internal error. */
#define DREW_ERR_BUG			0x10008
/* More data is needed to complete the request. */
#define DREW_ERR_MORE_DATA		0x10009
/* There is no more of the requested item or the requested item does not exist.
 * Alternately, no item matching the criteria was available.
 */
#define DREW_ERR_NONEXISTENT	0x1000a
/* The operation failed.  If a verification, the MAC is wrong, the signature is
 * not valid, etc.  If a hardware PRNG, the hardware is broken, is out of
 * entropy, etc.
 */
#define DREW_ERR_FAILED			0x1000b
/* Retained for compatibility. */
#define DREW_ERR_VERIFY_FAILED	DREW_ERR_FAILED

DREW_SYM_PUBLIC
int drew_loader_new(drew_loader_t **ldr);
DREW_SYM_PUBLIC
int drew_loader_free(drew_loader_t **ldr);
DREW_SYM_PUBLIC
int drew_loader_load_plugin(drew_loader_t *ldr, const char *plugin,
		const char *path);
DREW_SYM_PUBLIC
int drew_loader_get_nplugins(const drew_loader_t *ldr, int id);
DREW_SYM_PUBLIC
int drew_loader_get_type(const drew_loader_t *ldr, int id);
DREW_SYM_PUBLIC
int drew_loader_get_functbl(const drew_loader_t *ldr, int id, const void **tbl);
DREW_SYM_PUBLIC
int drew_loader_get_algo_name(const drew_loader_t *ldr, int id,
		const char **namep);
DREW_SYM_PUBLIC
int drew_loader_lookup_by_name(const drew_loader_t *ldr, const char *name,
		int start, int end);
DREW_SYM_PUBLIC
int drew_loader_lookup_by_type(const drew_loader_t *ldr, int type, int start,
		int end);
DREW_SYM_PUBLIC
int drew_loader_get_metadata(const drew_loader_t *ldr, int id, int item,
		drew_metadata_t *meta);
DREW_SYM_PUBLIC
int drew_loader_get_search_path(const drew_loader_t *ldr, int num,
		const char **p);

#if defined(__cplusplus)
}
#endif

#endif
