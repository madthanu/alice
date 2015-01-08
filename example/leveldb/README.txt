To check Git using ALICE, run the following commands within the example/git
directory:

./git_workload.sh
alice-check --traces_dir=traces_dir --checker=./git_checker.sh

Please note that the checker and workload included in this directory are
simple, and meant to explain how to use ALICE, rather than for actually testing
Git.

