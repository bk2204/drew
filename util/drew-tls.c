#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <drew/drew.h>
#include <drew/plugin.h>

#include <drew-tls/session.h>

#include <drew-util/x509.h>

// WARNING: this does absolutely no certificate validation at all!  This is
// completely insecure!  Don't even think about using this in real code!
// Really!
int callback(drew_tls_cert_ctxt_t ctx, drew_tls_session_t sess,
		const drew_tls_encoded_cert_t *ecerts, const drew_tls_cert_t *dcerts,
		size_t ncerts)
{
	return 0;
}

void derr(int a, int x)
{
	if (x < 0)
		printf("error in %d: %d %d\n", a, -x, (-x) & 0xffff);
}

int main(void)
{
	drew_loader_t *ldr;
	drew_tls_session_t sess;
	drew_tls_priority_t prio;
	long sock;
	int res = 0;
	struct sockaddr_in sa;
	uint32_t addr = htonl(0x7f000001);

	// localhost:3001.
	sa.sin_family = AF_INET;
	sa.sin_port = htons(3001);
	memcpy(&sa.sin_addr, &addr, sizeof(addr));

	derr(0, drew_loader_new(&ldr));
	derr(1, drew_loader_load_plugin(ldr, NULL, NULL));

	derr(2, drew_tls_priority_init(&prio));
	derr(3, drew_tls_priority_set_sensible_default(prio));
	derr(4, drew_tls_session_init(&sess, ldr));
	derr(5, drew_tls_session_set_end(sess, 1));
	derr(6, drew_tls_session_set_priority(sess, prio));
	derr(6, drew_tls_session_set_cert_callback(sess, callback));

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket(2) failed");
		return 2;
	}
	if (connect(sock, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("connect(2) failed");
		return 3;
	}
	printf("sock is %ld\n", sock);

	derr(7, drew_tls_session_set_transport(sess, (drew_tls_data_in_func_t)read,
			(drew_tls_data_out_func_t)write, (void *)sock, (void *)sock));

	res = drew_tls_session_handshake(sess);
	if (res != 0)
		printf("handshake failed: %d %d\n", -res, (-res) & 0xffff);

	drew_tls_session_fini(&sess);
	drew_tls_priority_fini(&prio);
	drew_loader_free(&ldr);

	return 0;
}
