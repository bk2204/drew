/*-
 * Copyright © 2010 brian m. carlson
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
