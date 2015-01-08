LEVELDB_SRC = leveldb-1.17.0
EXECUTABLES = workload checker init
DEPENDENCIES = common.h Makefile

all: $(EXECUTABLES)

%: %.cc $(LEVELDB_SRC) $(LEVELDB_SRC)/libleveldb.a $(DEPENDENCIES)
	g++ -g -o $@ $< $(LEVELDB_SRC)/libleveldb.a -I$(LEVELDB_SRC)/include -lpthread

clean:
	rm -f $(EXECUTABLES)
