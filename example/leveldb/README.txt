This example is for verifying the crash-consistency of Google's LevelDB[1], "a
fast key-value storage library written at Google", using the ALICE tool. The
reader is assumed to have successfully played around with the "toy" example of
ALICE before going through this README.

To use this example, you must first download and build LevelDB, and then
change the Makefile present in this directory to point to the place where
LevelDB was built.  LevelDB-1.17 can be downloaded from [2]; building requires
untarring, and "./configure" and "make" within the untarred directory. In the
Makefile present in the example directory (i.e., the directory where this
README file is found), the "LEVELDB_SRC" variable should be set appropriately.

The example can be run by issuing the following two commands in the directory
where this README file is found:

./leveldb_workload.sh
alice-check --traces_dir=traces_dir --checker=./checker

The "leveldb_workload.sh" script initializes "workload_dir" and "traces_dir",
similar to the toy example, and creates and initializes a LevelDB database
inside "workload_dir". The initialization of the LevelDB database is done by
init.cc, which inserts four large key-value pairs. Thus, before alice-record
is run, "workload_dir" will contain a database with four key-value pairs. The
"leveldb_workload.sh" script then runs "workload.cc" (the actual LevelDB
workload) under the "alice-record" command. This inserts six large key-value
pairs into the database; the first five inserts are done asynchronously, and
the last is done synchronously.

After "leveldb_workload.sh", the "alice-check" tool is invoked. The
"alice-check" tool runs "checker.cc" for each crash it simulates; the state of
the simulated crash is supplied to "checker.cc" via command-line arguments, as
described in the ALICE documentation. "checker.cc" verifies that the database
(after the simulated crash) can be opened, that it only contains the key-value
pairs in full (i.e., atomicity), that key-value pairs are recorded in the same
order they were inserted, and that the database contains all key value pairs
if the crash happened after the last (synchronous) pair was inserted by the
workload. The alice-check tool should display all vulnerabilities it finds.

[1] https://github.com/google/leveldb
[2] https://github.com/google/leveldb/archive/v1.17.tar.gz
