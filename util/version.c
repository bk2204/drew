#include <stddef.h>
#include <stdio.h>

#include <drew/drew.h>

int main(void)
{
	const char *p;
	int ver;

	ver = drew_get_version(0, &p, NULL);
	printf("Drew version %d (%s)\n", ver, p);
	return 0;
}
