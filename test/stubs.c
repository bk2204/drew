/*-
 * brian m. carlson <sandals@crustytoothpaste.net> wrote this source code.
 * This source code is in the public domain; you may do whatever you please with
 * it.  However, a credit in the documentation, although not required, would be
 * appreciated.
 */
#ifdef STUBS_EXTERNAL

const char *test_get_filename()
{
	return NULL;
}

char *test_get_id(void *data)
{
	return NULL;
}

void test_reset_data(void *p, int do_free)
{
}

void *test_create_data()
{
	return NULL;
}

void *test_clone_data(void *p, int flags)
{
	return NULL;
}

int test_execute(void *data, const char *name, const void *tbl,
		struct test_external *ldr)
{
	return TEST_NOT_IMPL;
}


int test_process_testcase(void *data, int type, const char *item,
		struct test_external *tep)
{
	return TEST_OK;
}
#endif

#ifdef STUBS_API

int test_api(const drew_loader_t *ldr, const char *name, const char *algo,
		const void *tbl)
{
	return -DREW_ERR_NOT_IMPL;
}

#endif
