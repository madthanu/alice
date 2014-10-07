#!/usr/bin/env python
import os
import sys

crashed_state_directory = sys.argv[1]
stdout_file = sys.argv[2]

# Move into the crashed-state directory supplied by ALICE, and read all
# messages printed to the terminal at the time of the crash.
os.chdir(crashed_state_directory)
stdout = open(stdout_file).read()

if 'Updated' in stdout:
	# Check durability
	assert open('file1').read() == 'world'
else:
	# Check atomicity
	assert open('file1').read() in ['hello', 'world']

# Check whether link1 and link2 were created together as a single atomic unit
dirlist = os.listdir('.')
assert ('link1' in dirlist) == ('link2' in dirlist)

