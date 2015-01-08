#include <cstring>
#include <unistd.h>
#include <cassert>
#include "leveldb/db.h"

using namespace std;
using namespace leveldb;

#define WRITE_BUFFER_SIZE (4096) // The lowest effective value is 64K
#define KEY_SIZE (5000)
#define VALUE_SIZE (40000)
#define MAX_SIZE (100000)

/* Generates a string of the given size uniquely corresponding to the given number */
static const char *gen_string(int c, int size) {
	static char toret[MAX_SIZE + 1];
	assert(size <= MAX_SIZE);

	int i;
	for(i = 0; i < size; i++) {
		toret[i] = 'a' + c;
	}
	toret[i] = '\0';

	return toret;
}
