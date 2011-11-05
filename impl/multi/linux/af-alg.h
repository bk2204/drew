/*-
 * Copyright © 2011 brian m. carlson
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
/* This uses the Linux crypto socket interface to perform crypto.  This can take
 * advantage of hardware implementations that cannot be used by userspace.
 */
#ifndef DREW_AF_ALG_H
#define DREW_AF_ALG_H
#ifdef __linux__

#ifdef __cplusplus
extern "C" {
#endif

#include <linux/if_alg.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

struct af_alg {
	int sockfd;
	int fd;
	struct sockaddr_alg sa;
};

int af_alg_initialize(struct af_alg *aas);
int af_alg_open_socket(struct af_alg *aas, const char *type, const char *algo);
int af_alg_set_key(struct af_alg *aas, const uint8_t *key, size_t len);
int af_alg_make_socket(struct af_alg *aas);
int af_alg_do_crypt(const struct af_alg *aas, uint8_t *out, const uint8_t *in,
		size_t len, int decrypt);

#ifdef __cplusplus
}
#endif

#endif
#endif
