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

#if defined(DREW_IN_BUILD) && defined(DREW_IN_BUILD_PLUGIN_C)
typedef struct {
	int version;
	int flags;
	char *name;		/* Name of the plugin. */
	char *aname;	/* Algorithm name. */
	char *path;
	void *handle;
	drew_metadata_t *metadata;
	int nmeta;
	int id;
	int nplugins;
	int type;
	int size;
	void **functbl;
} drew_loader_entry_t;

typedef struct {
	int version;
	int flags;
	int nentries;
	drew_loader_entry_t *entry;
} drew_loader_t;
#elif defined(DREW_IN_BUILD)
struct drew_loader_s;
typedef struct drew_loader_s drew_loader_t;
#else
typedef void drew_loader_entry_t;
typedef void drew_loader_t;
#endif

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

#if defined(__cplusplus)
}
#endif

#endif
