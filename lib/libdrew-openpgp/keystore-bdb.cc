#include "keystore.hh"

#define CHUNKSZ	64

BerkeleyDBBackend::BerkeleyDBBackend() : dbp(0), error(0)
{
}

BerkeleyDBBackend::~BerkeleyDBBackend()
{
	Close();
}

bool BerkeleyDBBackend::IsRandomAccess() const
{
	return true;
}

void BerkeleyDBBackend::Open(const char *filename, bool write)
{
	int flags = (write ? DB_CREATE : DB_RDONLY);
	db_create(&dbp, NULL, 0);
	error = dbp->open(dbp, NULL, filename, "openpgp", DB_HASH, flags,
			0600);
	if (error)
		return Close();
	dbp->cursor(dbp, 0, &dbc, 0);
}

void BerkeleyDBBackend::Close()
{
	if (dbc)
		dbc->close(dbc);
	dbc = NULL;
	dbp->close(dbp, 0);
	dbp = NULL;
}

int BerkeleyDBBackend::GetError() const
{
	return error;
}

bool BerkeleyDBBackend::IsOpen() const
{
	return dbp;
}

void BerkeleyDBBackend::WriteChunks(const KeyChunk &k, const Chunk *c,
		size_t nchunks)
{
	DBT key, data;
	uint8_t *buf = new uint8_t[sizeof(c[0].chunk) * nchunks];
	for (size_t i = 0; i < nchunks; i++)
		memcpy(buf+(i*sizeof(k.chunk)), c[i].chunk, sizeof(c[i].chunk));
	data.data = buf;
	data.size = sizeof(c[0].chunk) * nchunks;
	data.flags = 0;
	key.data = (void *)k.chunk;
	key.size = sizeof(k.chunk);
	key.flags = 0;
	dbp->put(dbp, NULL, &key, &data, 0);
	delete[] buf;
}

void BerkeleyDBBackend::ReadKeyChunk(KeyChunk &k)
{
	DBT key, data;
	int res = 0;

	key.data = k.chunk;
	key.size = sizeof(k.chunk);
	key.flags = 0;
	data.data = NULL;
	data.size = 0;
	data.flags = DB_DBT_MALLOC;

	res = dbc->get(dbc, &key, &data, DB_NEXT);
	free(data.data);
	if (res == DB_NOTFOUND)
		throw 0;
}

Chunk *BerkeleyDBBackend::ReadChunks(const KeyChunk &k, size_t &nchunks)
{
	return LoadChunks(k, nchunks);
}

Chunk *BerkeleyDBBackend::LoadChunks(const KeyChunk &k, size_t &nchunks)
{
	int res;
	DBT key, data;
	Chunk *c;

	key.data = (void *)k.chunk;
	key.size = sizeof(k.chunk);
	key.flags = 0;
	data.data = NULL;
	data.size = 0;
	data.flags = DB_DBT_MALLOC;
	res = dbp->get(dbp, NULL, &key, &data, 0);
	if (res == DB_NOTFOUND)
		return 0;

	uint8_t *p = (uint8_t *)data.data;

	nchunks = data.size / sizeof(c->chunk);
	c = new Chunk[nchunks];
	for (size_t i = 0, off = 0; i < nchunks; i++, off += sizeof(c->chunk))
		memcpy(c[i], p+off, sizeof(c->chunk));
	free(data.data);
	return c;
}
