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

#if defined(__cplusplus)
extern "C" {
#endif

#define DREW_LOADER_MD_URI 0
#define DREW_LOADER_MD_IRI DREW_LOADER_MD_URI
#define DREW_LOADER_MD_LITERAL 1

typedef struct {
	int version;	/* Must be zero. */
	char *predicate;
	int type;
	char *object;
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
/* The verification failed.  That is, the MAC is wrong, the signature is not
 * valid, etc.
 */
#define DREW_ERR_VERIFY_FAILED	0x1000b

int drew_loader_new(drew_loader_t **ldr);
int drew_loader_free(drew_loader_t **ldr);
int drew_loader_load_plugin(drew_loader_t *ldr, const char *plugin,
		const char *path);
int drew_loader_get_nplugins(const drew_loader_t *ldr, int id);
int drew_loader_get_type(const drew_loader_t *ldr, int id);
int drew_loader_get_functbl(const drew_loader_t *ldr, int id, const void **tbl);
int drew_loader_get_algo_name(const drew_loader_t *ldr, int id,
		const char **namep);
int drew_loader_lookup_by_name(const drew_loader_t *ldr, const char *name,
		int start, int end);
int drew_loader_lookup_by_type(const drew_loader_t *ldr, int type, int start,
		int end);
int drew_loader_get_metadata(const drew_loader_t *ldr, int id, int item,
		drew_metadata_t *meta);
int drew_loader_get_search_path(const drew_loader_t *ldr, int num,
		const char **p);

#if defined(__cplusplus)
}
#endif

#endif
