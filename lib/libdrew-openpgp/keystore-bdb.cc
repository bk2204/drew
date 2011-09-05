#include "keystore.hh"

extern "C" {
EXPORT()
#include <sys/stat.h>
#include <sys/types.h>
UNEXPORT()
}

#define CHUNKSZ	64

BerkeleyDBBackend::BerkeleyDBBackend() :
	dbenv(0), dbp(0), dbc(0), txn(0), error(0)
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
	int envflags = DB_CREATE | DB_RECOVER | DB_INIT_TXN | DB_INIT_MPOOL;
	int flags = (write ? DB_CREATE : DB_RDONLY) | DB_AUTO_COMMIT;
	mkdir(filename, 0700);
	db_env_create(&dbenv, 0);
	error = dbenv->open(dbenv, filename, envflags, 0700);
	if (error)
		return Close();
	db_create(&dbp, dbenv, 0);
	error = dbp->open(dbp, NULL, "openpgp", "openpgp", DB_HASH, flags,
			0600);
	if (error)
		return Close();
	error = dbp->cursor(dbp, 0, &dbc, 0);
	if (error)
		return Close();
}

void BerkeleyDBBackend::Close()
{
	if (dbc)
		dbc->close(dbc);
	dbc = NULL;
	if (dbp)
		dbp->close(dbp, 0);
	dbp = NULL;
	if (dbenv)
		dbenv->close(dbenv, DB_FORCESYNC);
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
	dbp->put(dbp, txn, &key, &data, 0);
	delete[] buf;
}

void BerkeleyDBBackend::ReadKeyChunk(KeyChunk &k)
{
	DBT key, data;
	int res = 0;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	res = dbc->get(dbc, &key, &data, DB_NEXT);
	if (res == DB_NOTFOUND)
		throw 0;
	memcpy(k.chunk, key.data, sizeof(k.chunk));
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
	key.flags = DB_DBT_USERMEM;
	memset(&data, 0, sizeof(data));
	res = dbp->get(dbp, NULL, &key, &data, 0);
	if (res == DB_NOTFOUND)
		return 0;

	uint8_t *p = (uint8_t *)data.data;

	nchunks = data.size / sizeof(c->chunk);
	c = new Chunk[nchunks];
	for (size_t i = 0, off = 0; i < nchunks; i++, off += sizeof(c->chunk))
		memcpy(c[i], p+off, sizeof(c->chunk));
	return c;
}

void BerkeleyDBBackend::StartTransaction()
{
	dbenv->txn_begin(dbenv, NULL, &txn, DB_TXN_BULK);
}

void BerkeleyDBBackend::CommitTransaction()
{
	if (txn)
		txn->commit(txn, 0);
	txn = 0;
}

void BerkeleyDBBackend::EndTransaction()
{
	if (txn)
		txn->abort(txn);
	txn = 0;
}
