LEVELDB_SRC = /root/leveldb-1.15.0
EXECUTABLES = workload checker init
DEPENDENCIES = common.h Makefile

all: $(EXECUTABLES)

%: %.cc $(LEVELDB_SRC) $(DEPENDENCIES)
	g++ -g -o $@ $< $(LEVELDB_SRC)/libleveldb.a -I$(LEVELDB_SRC)/include -lpthread

clean:
	rm -f $(EXECUTABLES)
