# Copyright (c) 2014 Thanumalayan Sankaranarayana Pillai. All Rights Reserved.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from alicestruct import Struct
import math

__author__ = "Thanumalayan Sankaranarayana Pillai"
__copyright__ = "Copyright 2014, Thanumalayan Sankaranarayana Pillai"
__credits__ = ["Thanumalayan Sankaranarayana Pillai", "Vijay Chidambaram",
	"Ramnatthan Alagappan", "Samer Al-Kiswany"]
__license__ = "MIT"

class defaultfs:
	def __init__(self, split_mode, splits):
		assert split_mode in ['aligned', 'count']
		self.split_mode = split_mode
		self.splits = splits

	def get_disk_ops(self, line):
		splits = self.splits
		split_mode = self.split_mode
		def trunc_disk_ops(inode, initial_size, final_size, append_micro_op = None, atomicity_prefix = ''):
			toret = []

			if initial_size == final_size:
				print 'Warning: trunc_disk_ops called for the same initial and final size, ' + str(initial_size) 
				return toret

			# If we are making the file smaller, follow the same algorithm
			# as making the file bigger. But, exchange the initial_size and
			# final_size in the beginning, and then reverse the final
			# output list.
			invert = False
			if initial_size > final_size:
				t = initial_size
				initial_size = final_size
				final_size = t
				invert = True

			if append_micro_op:
				assert not invert
				assert append_micro_op.inode == inode
				assert append_micro_op.offset == initial_size
				assert append_micro_op.count == (final_size - initial_size)

			splits = self.splits
			split_mode = self.split_mode

			start = initial_size
			remaining = final_size - initial_size
			if split_mode == 'count':
				per_slice_size = int(math.ceil(float(remaining) / splits))

			end = 0
			while remaining > 0:
				if split_mode == 'aligned':
					count = min(splits - (start % splits), remaining)
				else:
					count = min(per_slice_size, remaining)
				end = count + start

				if invert:
					# Actually truncate. Final operation (if there is no size-splitting) for size-decreasing truncates. 
					atomicity = atomicity_prefix
					if remaining != count:
						atomicity += ' semi-truncated (' + str(splits) + ' ' + split_mode + ' splits)'
					disk_op = Struct(op = 'truncate', inode = inode, initial_size = start, final_size = end, atomicity = atomicity)
					toret.append(disk_op)

				if append_micro_op:
					# Write zeros
					atomicity = atomicity_prefix + 'zero written'
					if remaining != count:
						atomicity += ' semi-expanded (' + str(splits) + ' ' + split_mode + ' splits)'
					disk_op = Struct(op = 'write', inode = inode, offset = start, dump_offset = 0, count = count, \
						dump_file = None, override_data = None, special_write = 'ZEROS', atomicity = atomicity)
					toret.append(disk_op)

				if not invert:
					# Write garbage
					atomicity = atomicity_prefix + 'garbage written'
					if remaining != count:
						atomicity += ' semi-expanded (' + str(splits) + ' ' + split_mode + ' splits)'
					disk_op = Struct(op = 'write', inode = inode, offset = start, dump_offset = 0, count = count, \
						dump_file = None, override_data = None, special_write = 'GARBAGE', atomicity = atomicity)
					toret.append(disk_op)

				if (not invert) and not append_micro_op:
					# Write zeros. Final operation (if there is no size-splitting) for size-increasing truncate.
					atomicity = atomicity_prefix
					if remaining != count:
						atomicity += 'semi-expanded (' + str(splits) + ' ' + split_mode + ' splits)'
					disk_op = Struct(op = 'write', inode = inode, offset = start, dump_offset = 0, count = count, \
						dump_file = None, override_data = None, special_write = 'ZEROS', atomicity = atomicity)
					toret.append(disk_op)

				if append_micro_op:
					# Write data. Final operation (if there is no size-splitting) for appends.
					atomicity = atomicity_prefix
					if remaining != count:
						atomicity += 'semi-expanded (' + str(splits) + ' ' + split_mode + ' splits)'
					dump_offset = append_micro_op.dump_offset + (start - append_micro_op.offset)
					disk_op = Struct(op = 'write', inode = inode, offset = start, dump_offset = dump_offset, count = count, \
						dump_file = append_micro_op.dump_file, special_write = None, atomicity = atomicity)
					toret.append(disk_op)
		
				remaining -= count
				start = end

			assert end == final_size

			if invert == True:
				toret.reverse()
				for disk_op in toret:
					t = disk_op.initial_size
					disk_op.initial_size = disk_op.final_size
					disk_op.final_size = t

			return toret

		def unlink_disk_ops(parent, inode, name, size, hardlinks, entry_type = Struct.TYPE_FILE, atomicity_prefix = ''):
			toret = []
			if hardlinks == 1:
				toret += trunc_disk_ops(inode, size, 0, atomicity_prefix = atomicity_prefix)
				if len(toret) > 0:
					toret[-1].atomicity = atomicity_prefix + 'fully truncated'
			disk_op = Struct(op = 'delete_dir_entry', parent = parent, entry = name, inode = inode, entry_type = entry_type)
			toret.append(disk_op)
			return toret
		def link_disk_ops(parent, inode, name, mode = None, entry_type = Struct.TYPE_FILE):
			return [Struct(op = 'create_dir_entry', parent = parent, entry = name, inode = inode, mode = mode, entry_type = entry_type)]

		if line.op == 'creat':
			line.hidden_disk_ops = link_disk_ops(line.parent, line.inode, line.name, line.mode)
		elif line.op == 'unlink':
			line.hidden_disk_ops = unlink_disk_ops(line.parent, line.inode, line.name, line.size, line.hardlinks)
		elif line.op == 'link':
			line.hidden_disk_ops = link_disk_ops(line.dest_parent, line.source_inode, line.dest)
		elif line.op == 'rename':
			line.hidden_disk_ops = []
			# source: source_inode, dest: dest_inode
			if line.dest_hardlinks >= 1:
				line.hidden_disk_ops += unlink_disk_ops(line.dest_parent, line.dest_inode, line.dest, line.dest_size, line.dest_hardlinks, atomicity_prefix = 'destination unlinking partial ')
				line.hidden_disk_ops[-1].atomicity = 'destination unlinked fully, source untouched'
			# source: source_inode, dest: None
			line.hidden_disk_ops += unlink_disk_ops(line.source_parent, line.source_inode, line.source, line.source_size, 2, atomicity_prefix = 'destination unlinked fully, source unlinking partial ') # Setting hardlinks as 2 so that trunc does not happen
			line.hidden_disk_ops[-1].atomicity = 'destination and source unlinked fully'
			# source: None, dest: None
			line.hidden_disk_ops += link_disk_ops(line.dest_parent, line.source_inode, line.dest)
			# source: None, dest: source_inode
		elif line.op == 'trunc':
			line.hidden_disk_ops = trunc_disk_ops(line.inode, line.initial_size, line.final_size)
		elif line.op == 'append':
			line.hidden_disk_ops = trunc_disk_ops(line.inode, line.offset, line.offset + line.count, line)
		elif line.op == 'write':
			assert line.count > 0
			line.hidden_disk_ops = []

			offset = line.offset
			remaining = line.count
			if split_mode == 'count':
				per_slice_size = int(math.ceil(float(line.count) / splits))

			while remaining > 0:
				if split_mode == 'aligned':
					count = min(splits - (offset % splits), remaining)
				else:
					count = min(per_slice_size, remaining)

				dump_offset = line.dump_offset + (offset - line.offset)
				disk_op = Struct(op = 'write', inode = line.inode, offset = offset, dump_offset = dump_offset, \
					count = count, dump_file = line.dump_file, override_data = None, special_write = None, \
					atomicity = str(splits) + ' ' + split_mode + ' split')
				line.hidden_disk_ops.append(disk_op)
				remaining -= count
				offset += count
		elif line.op == 'mkdir':
			line.hidden_disk_ops = link_disk_ops(line.parent, line.inode, line.name, eval(line.mode), Struct.TYPE_DIR)
		elif line.op == 'rmdir':
			line.hidden_disk_ops = unlink_disk_ops(line.parent, line.inode, line.name, 0, 0, Struct.TYPE_DIR)
		elif line.op in ['fsync', 'fdatasync', 'file_sync_range']:
			line.hidden_disk_ops = []
			if line.op in ['fsync', 'fdatasync']:
				offset = 0
				count = line.size
			else:
				offset = line.offset
				count = line.count
			disk_op = Struct(op = 'sync', inode = line.inode, offset = offset, count = count)
			line.hidden_disk_ops.append(disk_op)
		elif line.op in ['sync']:
			line.hidden_disk_ops = []
			for f in line.hidden_files:
				disk_op = Struct(op = 'sync', inode = f.inode, offset = 0, count = f.size)
				line.hidden_disk_ops.append(disk_op)
		elif line.op == 'stdout':
			line.hidden_disk_ops = [Struct(op = line.op, data = line.data)]
		else:
			assert False

	def get_deps(self, ops):
		last_sync = None
		for i in range(0, len(ops)):
			ops[i].hidden_dependencies = set()
			ops[i].hidden_twojournalfs_stuff = Struct(reverse_fsync_dependencies = set())
			if last_sync != None:
				ops[i].hidden_dependencies.add(last_sync)
			if ops[i].op in ['sync', 'stdout']:
				last_sync = i
			else:
				assert ops[i].op in ['truncate', 'write', 'delete_dir_entry', 'create_dir_entry']
			if ops[i].op == 'sync':
				for j in range(i - 1, -1, -1):
					if ops[j].op in ['sync', 'write']:
						i_final = ops[i].offset + ops[i].count
						i_initial = ops[i].offset
						j_final = ops[j].offset + ops[j].count
						j_initial = ops[j].offset
					if ops[j].op == 'sync':
						if not ops[j].inode == ops[i].inode:
							continue
						# If j-sync overlaps i-sync
						if j_initial <= i_initial and j_final >= i_final:
							break
					elif ops[j].op == 'truncate':
						if not ops[j].inode == ops[i].inode:
							continue
						assert ops[i].hidden_micro_op.hidden_parsed_line.syscall in ['fsync', 'fdatasync', 'sync']
						ops[i].hidden_dependencies.add(j)
						ops[j].hidden_twojournalfs_stuff.reverse_fsync_dependencies.add(i)
					elif ops[j].op == 'write':
						if not ops[j].inode == ops[i].inode:
							continue
						# If j_initial is within i's range
						if j_initial >= i_initial and j_initial <= i_final:
							if not (j_final >= i_initial and j_final <= i_final):
								if not 'warned_xxxx1' in globals():
									print '----------------------------------------------------------'
									print 'WARNING: not (j_final >= i_initial and j_final <= i_final)'
									traceback.print_stack(file = sys.stdout)
									print '----------------------------------------------------------'
								globals()['warned_xxxx1'] = 1
							ops[i].hidden_dependencies.add(j)
							ops[j].hidden_twojournalfs_stuff.reverse_fsync_dependencies.add(i)
						else:
							if (j_final >= i_initial and j_final <= i_final):
								if not 'warned_xxxx2' in globals():
									print '----------------------------------------------------------'
									print 'WARNING: (j_final >= i_initial and j_final <= i_final)'
									traceback.print_stack(file = sys.stdout)
									print '----------------------------------------------------------'
								globals()['warned_xxxx2'] = 1
					elif ops[j].op in ['create_dir_entry', 'delete_dir_entry']:
						if not ops[j].parent == ops[i].inode:
							continue
						assert ops[i].hidden_micro_op.hidden_parsed_line.syscall in ['fsync', 'sync']
						ops[i].hidden_dependencies.add(j)
						ops[j].hidden_twojournalfs_stuff.reverse_fsync_dependencies.add(i)
					else:
						assert ops[j].op == 'stdout'

