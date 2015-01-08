#include <cassert>
#include <iostream>
#include "leveldb/db.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include "common.h"

using namespace std;
using namespace leveldb;

int main(int argc, char *argv[]) {
	/* Variable declarations and some setup */
	DB* db;
	Options options;
	Status ret;
	WriteOptions write_options;
	string key, value;
	int i;

	options.create_if_missing = true;
	options.paranoid_checks = true;
	options.write_buffer_size = WRITE_BUFFER_SIZE;
	write_options.sync = true;

	/* Open the database */
	ret = DB::Open(options, "workload_dir/testdb", &db);
	assert(ret.ok());

	/* Put four rows into the database. Their keys and values are each strings
	 * corresponding to 0, 1, 2, and 3. All Puts are done synchronously. */
	for(i = 0; i < 4; i++) {
		key = string(gen_string(i, KEY_SIZE));
		value = string(gen_string(i, VALUE_SIZE));

		ret = db->Put(write_options, key, value);
		assert(ret.ok());
	}

	/* Close the database */
	delete db;
}
