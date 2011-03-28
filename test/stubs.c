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

int test_execute(void *data, const char *name, const void *tbl,
		const drew_loader_t *ldr)
{
	return TEST_NOT_IMPL;
}


int test_process_testcase(void *data, int type, const char *item)
{
	return TEST_OK;
}
