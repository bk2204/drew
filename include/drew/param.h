#ifndef DREW_PARAM_H
#define DREW_PARAM_H

#include <stddef.h>

/* This structure is used for passing parameters to algorithms that need them.
 * The name of a parameter and its values are specified in SCAN.  Names are
 * case-sensitive.  Parameters specified as Integer or long in SCAN are stored
 * in number; those specified as String are passed in String; and those
 * specified as arrays or objects are specified as value.  Arrays of long in
 * SCAN are arrays of uint64_t; arrays of byte are uint8_t.
 *
 * Note that key lengths for symmetric ciphers are not specified in this manner
 * for compliance with SCAN.  Instead, they are passed via a separate argument.
 */

typedef struct drew_param_t {
	struct drew_param_t *next;
	const char *name;
	union {
		const char *string;
		size_t number;
		void *value;
	} param;
} drew_param_t;

#endif
