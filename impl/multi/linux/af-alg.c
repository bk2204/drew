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
#ifdef __linux__
#include "internal.h"

#include <glib-2.0/glib.h>
#include <errno.h>
#include <unistd.h>
#include <linux/if_alg.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "af-alg.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

int af_alg_initialize(struct af_alg *aas)
{
	memset(aas, 0, sizeof(*aas));
	aas->sockfd = -1;
	aas->fd = -1;
	return 0;
}

int af_alg_open_socket(struct af_alg *aas, const char *type, const char *algo)
{
	memset(&aas->sa, 0, sizeof(aas->sa));
	aas->sa.salg_family = AF_ALG;
	memcpy(aas->sa.salg_type, type,
			MIN(strlen(type), sizeof(aas->sa.salg_type)));
	memcpy(aas->sa.salg_name, algo,
			MIN(strlen(algo), sizeof(aas->sa.salg_name)));
	if ((aas->sockfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
		return -errno;
	if (bind(aas->sockfd, (struct sockaddr *)&aas->sa, sizeof(aas->sa)))
		return -errno;
	return 0;
}

int af_alg_set_key(struct af_alg *aas, const uint8_t *key, size_t len)
{
	return setsockopt(aas->sockfd, SOL_ALG, ALG_SET_KEY, key, len);
}

int af_alg_make_socket(struct af_alg *aas)
{
	if ((aas->fd = accept(aas->sockfd, NULL, 0)) < 0)
		return -errno;
	return 0;
}

int af_alg_do_crypt(const struct af_alg *aas, uint8_t *out, const uint8_t *in,
		size_t len, int decrypt)
{
	uint32_t op = decrypt ? ALG_OP_DECRYPT : ALG_OP_ENCRYPT;
	uint8_t cbuf[CMSG_SPACE(sizeof(op))];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;

	memset(&msg, 0, sizeof(msg));
	memset(cbuf, 0, sizeof(cbuf));

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(op));
	memcpy(CMSG_DATA(cmsg), &op, sizeof(op));

	iov.iov_base = (void *)in;
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(aas->fd, &msg, 0) != len)
		RETFAIL(-errno);

	if (read(aas->fd, out, len) != len)
		RETFAIL(-errno);

	return 0;
}

#endif
