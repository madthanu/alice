#!/bin/bash

# Initialize the traces directory (where we are going to store traces collected
# during the workload) and the workload directory (where we are going to
# initialize a git repository and actually do the workload).
rm -rf traces_dir
rm -rf workload_dir
mkdir -p traces_dir
mkdir -p workload_dir

# Move into the workload and initialize a git repository.
cd workload_dir
git init .

# Create some file that we will be adding to the repository during the
# workload.
echo "hello" > file1

# Perform the actual workload and collect traces. The "workload_dir" argument
# to alice-record specifies the entire directory which will be re-constructed
# by alice and supplied to the checker. Alice also takes an initial snapshot of
# the workload directory before beginning the workload. The "traces_dir"
# argument specifies where all the traces recorded will be stored.
alice-record --workload_dir . \
	--traces_dir ../traces_dir \
	git add .

