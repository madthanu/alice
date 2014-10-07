#!/usr/bin/env python
import re
import math
import pickle
import os
import subprocess
import inspect
import copy
import string
import traceback
import random
import _aliceautotest as auto_test
import signal
import _aliceparsesyscalls
import pdb
import cProfile
import Queue
import threading
import time
import pprint
import code
import sys
import collections
from alicestruct import Struct
from _aliceutils import *
import gc

print colorize('-------------------------------------------------------------------------------', 1)
print 'ALICE tool version 0.0.1. Please go through the documentation, particularly the'
print 'listed caveats and limitations, before deriving any inferences from this tool. '
print colorize('-------------------------------------------------------------------------------', 1)

cached_rows = None
cached_dirinode_map = {}

# use_cached works only on a single thread
def replay_disk_ops(initial_paths_inode_map, rows, replay_dir, stdout_file, use_cached = False):
	def get_stat(path):
		try:
			return os.stat(path)
		except OSError as err:
			return False

	def get_inode_file(inode, mode = None):
		assert type(inode) == int
		if not get_stat(replay_dir + '/.inodes/' + str(inode)):
			if mode == None:
				mode = 0666
			if type(mode) == str:
				mode = safe_string_to_int(mode)
			fd = os.open(replay_dir + '/.inodes/' + str(inode), os.O_CREAT | os.O_WRONLY, mode)
			assert fd > 0
			os.close(fd)
		return replay_dir + '/.inodes/' + str(inode)

	dirinode_map = {} # From initial_inode to replayed_directory_path
	def is_linked_inode_directory(inode):
		assert type(inode) == int
		if inode not in dirinode_map:
			return False
		if dirinode_map[inode] == replay_dir + '/.inodes/' + str(inode):
			return False
		return True

	def get_inode_directory(inode, mode = None):
		assert type(inode) == int
		if inode not in dirinode_map:
			if mode == None:
				mode = 0777
			if type(mode) == str:
				mode = safe_string_to_int(mode)
			os.mkdir(replay_dir + '/.inodes/' + str(inode), mode)
			dirinode_map[inode] = replay_dir + '/.inodes/' + str(inode)
		return dirinode_map[inode]

	def set_inode_directory(inode, dir_path):
		assert type(inode) == int
		dirinode_map[inode] = dir_path

	def initialize_inode_links(initial_paths_inode_map):
		final_paths_inode_map = get_path_inode_map(replay_dir) # This map is used only for assertions
		assert len(final_paths_inode_map) == len(initial_paths_inode_map)

		# Asserting there are no hardlinks on the initial list - if there were, 'cp -R' wouldn't have worked correctly.
		initial_inodes_list = [inode for (inode, entry_type) in initial_paths_inode_map.values()]
		assert len(initial_inodes_list) == len(set(initial_inodes_list))

		os.system("mkdir " + replay_dir + '/.inodes')

		for path in initial_paths_inode_map.keys():
			final_path = path.replace(aliceconfig().scratchpad_dir, replay_dir, 1)
			assert final_path in final_paths_inode_map
			(initial_inode, entry_type) = initial_paths_inode_map[path]
			(tmp_final_inode, tmp_entry_type) = final_paths_inode_map[final_path]
			assert entry_type == tmp_entry_type
			if entry_type == 'd':
				set_inode_directory(initial_inode, final_path)
			else:
				os.link(final_path, replay_dir + '/.inodes/' + str(initial_inode))


	global cached_rows, cached_dirinode_map
	if use_cached:
		original_replay_dir = replay_dir
		replay_dir = os.path.join(aliceconfig().scratchpad_dir, 'cached_replay_dir')
		dirinode_map = cached_dirinode_map
		if cached_rows and len(cached_rows) <= len(rows) and rows[0:len(cached_rows)] == cached_rows:
			rows = copy.deepcopy(rows[len(cached_rows):])
			cached_rows += rows
		else:
			cached_rows = copy.deepcopy(rows)
			cached_dirinode_map = {}
			dirinode_map = cached_dirinode_map
			os.system("rm -rf " + replay_dir)
			os.system("cp -R " + aliceconfig().initial_snapshot + " " + replay_dir)
			initialize_inode_links(initial_paths_inode_map)
	else:
		os.system("rm -rf " + replay_dir)
		os.system("cp -R " + aliceconfig().initial_snapshot + " " + replay_dir)
		initialize_inode_links(initial_paths_inode_map)

	output_stdout = open(stdout_file, 'w')
	for line in rows:
	#	print line
		if line.op == 'create_dir_entry':
			new_path = get_inode_directory(line.parent) + '/' + os.path.basename(line.entry)
			if line.entry_type == Struct.TYPE_FILE:
				if os.path.exists(new_path):
					os.unlink(new_path)
				assert not os.path.exists(new_path)
				os.link(get_inode_file(line.inode, line.mode), new_path)
			else:
				assert not is_linked_inode_directory(line.inode) # According to the model, there might
					# exist two links to the same directory after FS crash-recovery. However, Linux
					# does not allow this to be simulated. Checking for that condition here - if this
					# assert is ever triggered in a real workload, we'll have to handle this case
					# somehow. Can potentially be handled using symlinks.
				os.rename(get_inode_directory(line.inode, line.mode), new_path)
				set_inode_directory(line.inode, new_path)
		elif line.op == 'delete_dir_entry':
			path = get_inode_directory(line.parent) + '/' + os.path.basename(line.entry)
			if get_stat(path):
				if line.entry_type == Struct.TYPE_FILE:
					os.unlink(path)
				else:
					os.rename(path, replay_dir + '/.inodes/' + str(line.inode)) # Deletion of
						# directory is equivalent to moving it back into the '.inodes' directory.
		elif line.op == 'truncate':
			old_mode = writeable_toggle(get_inode_file(line.inode))
			fd = os.open(get_inode_file(line.inode), os.O_WRONLY)
			assert fd > 0
			os.ftruncate(fd, line.final_size)
			os.close(fd)
			writeable_toggle(get_inode_file(line.inode), old_mode)
		elif line.op == 'write':
			old_mode = writeable_toggle(get_inode_file(line.inode))
			if line.special_write != None:
				if (line.special_write == 'GARBAGE' or line.special_write == 'ZEROS') and line.count > 4096:
					if line.count > 4 * 1024 * 1024:
						BLOCK_SIZE = 1024 * 1024
					else:
						BLOCK_SIZE = 4096
					blocks_byte_offset = int(math.ceil(float(line.offset) / BLOCK_SIZE)) * BLOCK_SIZE
					blocks_byte_count = max(0, (line.offset + line.count) - blocks_byte_offset)
					blocks_count = int(math.floor(float(blocks_byte_count) / BLOCK_SIZE))
					blocks_byte_count = blocks_count * BLOCK_SIZE
					blocks_offset = blocks_byte_offset / BLOCK_SIZE

					pre_blocks_offset = line.offset
					pre_blocks_count = blocks_byte_offset - line.offset
					if pre_blocks_count > line.count:
						assert blocks_byte_count == 0
						pre_blocks_count = line.count
					assert pre_blocks_count >= 0

					post_blocks_count = 0
					if pre_blocks_count < line.count:
						post_blocks_offset = (blocks_byte_offset + blocks_byte_count)
						assert post_blocks_offset % BLOCK_SIZE == 0
						post_blocks_count = line.offset + line.count - post_blocks_offset

					assert pre_blocks_count >= 0
					assert blocks_count >= 0
					assert post_blocks_count >= 0
					assert pre_blocks_count + blocks_count * BLOCK_SIZE + post_blocks_count == line.count
					assert pre_blocks_offset == line.offset
					if pre_blocks_count < line.count:
						assert blocks_offset * BLOCK_SIZE == pre_blocks_offset + pre_blocks_count
					if post_blocks_count > 0:
						assert (blocks_offset + blocks_count) * BLOCK_SIZE == post_blocks_offset

					if line.special_write == 'GARBAGE':
						cmd = "dd if=/dev/urandom of=\"" + get_inode_file(line.inode) + "\" conv=notrunc conv=nocreat status=noxfer "
					else:
						cmd = "dd if=/dev/zero of=\"" + get_inode_file(line.inode) + "\" conv=notrunc conv=nocreat status=noxfer "
					if pre_blocks_count > 0:
						subprocess.check_call(cmd + 'seek=' + str(pre_blocks_offset) + ' count=' + str(pre_blocks_count) + ' bs=1 2>/dev/null', shell=True, )
					if blocks_count > 0:
						subprocess.check_call(cmd + 'seek=' + str(blocks_offset) + ' count=' + str(blocks_count) + ' bs=' + str(BLOCK_SIZE) + '  2>/dev/null', shell=True)
					if post_blocks_count > 0:
						subprocess.check_call(cmd + 'seek=' + str(post_blocks_offset) + ' count=' + str(post_blocks_count) + ' bs=1 2>/dev/null', shell=True)
				elif line.special_write == 'GARBAGE' or line.special_write == 'ZEROS':
					if line.special_write == 'GARBAGE':
						data = string.ascii_uppercase + string.digits
					else:
						data = '\0'
					buf = ''.join(random.choice(data) for x in range(line.count))
					fd = os.open(get_inode_file(line.inode), os.O_WRONLY)
					os.lseek(fd, line.offset, os.SEEK_SET)
					os.write(fd, buf)
					os.close(fd)
					buf = ""
				else:
					assert False
			else:
				if line.dump_file == None:
					buf = line.override_data
				else:
					fd = os.open(line.dump_file, os.O_RDONLY)
					os.lseek(fd, line.dump_offset, os.SEEK_SET)
					buf = os.read(fd, line.count)
					os.close(fd)
				fd = os.open(get_inode_file(line.inode), os.O_WRONLY)
				os.lseek(fd, line.offset, os.SEEK_SET)
				os.write(fd, buf)
				os.close(fd)
				buf = ""
			writeable_toggle(get_inode_file(line.inode), old_mode)
		elif line.op == 'stdout':
			output_stdout.write(line.data)
		else:
			assert line.op == 'sync'

	if use_cached:
		os.system('rm -rf ' + original_replay_dir)
		os.system('cp -a ' + replay_dir + ' ' + original_replay_dir)
		replay_dir = original_replay_dir
		cached_dirinode_map = copy.deepcopy(dirinode_map)

	os.system("rm -rf " + replay_dir + '/.inodes')


class Replayer:
	def is_legal(self):
		assert self.fs_initialized
		diskops_index = 0
		included_diskops = []
		for i in range(0, self.__micro_end + 1):
			micro_op = self.micro_ops[i]
			till = self.__disk_end + 1 if self.__micro_end == i else len(micro_op.hidden_disk_ops)
			for j in range(0, till):
				if not micro_op.hidden_disk_ops[j].hidden_omitted:
					included_diskops.append(diskops_index)
				diskops_index += 1
		return self.test_suite.test_combo_validity(included_diskops)
	def __init__(self, alice_args):
		init_aliceconfig(alice_args)
		(self.path_inode_map, self.micro_ops) = _aliceparsesyscalls.get_micro_ops()
		cnt = 0
		for i in self.micro_ops:
			i.hidden_id = str(cnt)
			cnt = cnt + 1
		self.__micro_end = len(self.micro_ops) - 1
		self.__disk_end = 0 # Will be set during the dops_generate() call

		self.saved = dict()
		self.fs_initialized = False

	def print_ops(self, show_diskops = False, show_tids = False, show_time = False):
		for i in range(0, len(self.micro_ops)):
			micro_id = colorize(str(i), 3 if i > self.__micro_end else 2)
			tid_info = ''
			if show_tids:
				tid_info = str(self.micro_ops[i].hidden_pid) + '\t' + str(self.micro_ops[i].hidden_tid) + '\t'
			if show_time:
				tid_info += self.micro_ops[i].hidden_time + '\t'
			print(micro_id + '\t' + tid_info + str(self.micro_ops[i]))
			for j in range(0, len(self.micro_ops[i].hidden_disk_ops)):
				disk_op_str = str(self.micro_ops[i].hidden_disk_ops[j])
				if self.micro_ops[i].hidden_disk_ops[j].hidden_omitted:
					disk_op_str = colorize(disk_op_str, 3)
				if show_diskops:
					print('\t' + str(j) + '\t' + disk_op_str)
				if i == self.__micro_end and j == self.__disk_end:
					print(colorize('-------------------------------------', 1))
	def save(self, i):
		assert self.fs_initialized
		self.saved[int(i)] = copy.deepcopy(Struct(micro_ops = self.micro_ops,
							micro_end = self.__micro_end,
							disk_end = self.__disk_end,
							test_suite = self.test_suite))
	def load(self, i):
		assert self.fs_initialized
		assert int(i) in self.saved
		retrieved = copy.deepcopy(self.saved[int(i)])
		self.micro_ops = retrieved.micro_ops
		self.__micro_end = retrieved.micro_end
		self.__disk_end = retrieved.disk_end
		self.test_suite = retrieved.test_suite

	def construct_crashed_dir(self, dirname, stdout_file):
		assert self.fs_initialized
		to_replay = []
		for i in range(0, self.__micro_end + 1):
			micro_op = self.micro_ops[i]
			till = self.__disk_end + 1 if self.__micro_end == i else len(micro_op.hidden_disk_ops)
			for j in range(0, till):
				if not micro_op.hidden_disk_ops[j].hidden_omitted:
					to_replay.append(micro_op.hidden_disk_ops[j])
		replay_disk_ops(self.path_inode_map, to_replay, dirname, stdout_file, use_cached = True)
	def get_op(self, i):
		assert i <= len(self.micro_ops)
		return copy.deepcopy(self.micro_ops[i])
	def dops_end_at(self, i, j = None):
		assert self.fs_initialized
		if type(i) == tuple:
			assert j == None
			j = i[1]
			i = i[0]
		assert j != None
		self.__micro_end = i
		self.__disk_end = j
	def set_fs(self, fs):
		all_diskops = []
		for micro_op_id in range(0, len(self.micro_ops)):
			fs.get_disk_ops(self.micro_ops[micro_op_id])

			if micro_op_id == self.__micro_end:
				self.__disk_end = len(self.micro_ops[micro_op_id].hidden_disk_ops) - 1

			cnt = 0
			for disk_op in self.micro_ops[micro_op_id].hidden_disk_ops:
				disk_op.hidden_omitted = False
				disk_op.hidden_id = cnt
				disk_op.hidden_micro_op = self.micro_ops[micro_op_id]
				cnt += 1

			all_diskops += self.micro_ops[micro_op_id].hidden_disk_ops

		for i in range(0, len(all_diskops)):
			if all_diskops[i].op == 'stdout':
				all_diskops[i] = Struct(op = 'write', inode = -1, offset = 0, count = 1, hidden_actual_op = all_diskops[i]) 

		self.test_suite = auto_test.ALCTestSuite(all_diskops)

		for i in range(0, len(all_diskops)):
			if all_diskops[i].op == 'write' and all_diskops[i].inode == -1:
				all_diskops[i] = all_diskops[i].hidden_actual_op

		fs.get_deps(all_diskops)
		dependency_tuples = []
		for i in range(0, len(all_diskops)):
			for j in sorted(list(all_diskops[i].hidden_dependencies)):
				dependency_tuples.append((i, j))
		self.test_suite.add_deps_to_ops(dependency_tuples)


		self.fs_initialized = True
		self.saved = dict()
		self.save(0)
	def __dops_get_i_j(self, i, j):
		if type(i) == tuple:
			assert j == None
			j = i[1]
			i = i[0]
		assert j != None
		assert i < len(self.micro_ops)
		assert 'hidden_disk_ops' in self.micro_ops[i].__dict__
		assert j < len(self.micro_ops[i].hidden_disk_ops)
		return (i, j)
	def dops_omit(self, i, j = None):
		assert self.fs_initialized
		(i, j) = self.__dops_get_i_j(i, j)
		if self.micro_ops[i].op != 'stdout':
			self.micro_ops[i].hidden_disk_ops[j].hidden_omitted = True
	def dops_include(self, i, j = None):
		assert self.fs_initialized
		(i, j) = self.__dops_get_i_j(i, j)
		self.micro_ops[i].hidden_disk_ops[j].hidden_omitted = False
	def dops_get_op(self, i, j = None):
		assert self.fs_initialized
		(i, j) = self.__dops_get_i_j(i, j)
		return copy.deepcopy(self.micro_ops[i].hidden_disk_ops[j])
	def dops_len(self, i = None):
		assert self.fs_initialized
		if i == None:
			total = 0
			for micro_op in self.micro_ops:
				total += len(micro_op.hidden_disk_ops)
			return total
		assert i < len(self.micro_ops)
		return len(self.micro_ops[i].hidden_disk_ops)
	def mops_len(self):
		return len(self.micro_ops)
	def dops_double(self, single):
		assert self.fs_initialized
		i = 0
		seen_disk_ops = 0
		for i in range(0, len(self.micro_ops)):
			micro_op = self.micro_ops[i]
			if single < seen_disk_ops + len(micro_op.hidden_disk_ops):
				return (i, single - seen_disk_ops)
			seen_disk_ops += len(micro_op.hidden_disk_ops)
		assert False
	def dops_single(self, double):
		assert self.fs_initialized
		if double == None:
			return -1
		seen_disk_ops = 0
		for micro_op in self.micro_ops[0: double[0]]:
			seen_disk_ops += len(micro_op.hidden_disk_ops)
		return seen_disk_ops + double[1]
