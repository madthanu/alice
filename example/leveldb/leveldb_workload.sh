#!/bin/bash
set -e
trap 'error ${LINENO}' ERR

# The workload directory is where the files of the application will be stored.
# The application, as it runs, will modify the workload directory and its
# contents. 
rm -rf workload_dir
mkdir workload_dir

# The traces directory is for storing the (multiple) traces that are recorded
# as the application is run.
rm -rf traces_dir
mkdir traces_dir

# Compiling all files, and running init.cc
make
./init

# Perform the actual workload and collect traces. The "workload_dir" argument
# to alice-record specifies the entire directory which will be re-constructed
# by alice and supplied to the checker. Alice also takes an initial snapshot of
# the workload directory before beginning the workload. The "traces_dir"
# argument specifies where all the traces recorded will be stored.
alice-record --workload_dir workload_dir \
	--traces_dir traces_dir \
	./workload

