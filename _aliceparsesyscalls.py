import pickle
import csv
import sys
import commands
import uuid
import copy
import os
import traceback
import pprint
from _aliceutils import *
from alicestruct import Struct
from collections import namedtuple

innocent_syscalls = ["_exit","pread","_newselect","_sysctl","accept","accept4","access","acct","add_key","adjtimex",
"afs_syscall","alarm","alloc_hugepages","arch_prctl","bind","break","brk","cacheflush",
"capget","capset","clock_getres","clock_gettime","clock_nanosleep","clock_settime",
"connect","create_module","delete_module","epoll_create","epoll_create1","epoll_ctl","epoll_pwait",
"epoll_wait","eventfd","eventfd2","exit","exit_group","faccessat","fadvise64",
"fadvise64_64","fgetxattr","flistxattr","flock","free_hugepages","fstat","fstat64",
"fstatat64","fstatfs","fstatfs64","ftime","futex","get_kernel_syms","get_mempolicy","get_robust_list",
"get_thread_area","getcpu","getcwd","getdents","getdents64","getegid","getegid32","geteuid",
"geteuid32","getgid","getgid32","getgroups","getgroups32","getitimer","getpeername","getpagesize",
"getpgid","getpgrp","getpid","getpmsg","getppid","getpriority","getresgid","getresgid32",
"getresuid","getresuid32","getrlimit","getrusage","getsid","getsockname","getsockopt","gettid",
"gettimeofday","getuid","getuid32","getxattr","gtty","idle","init_module","inotify_add_watch",
"inotify_init","inotify_init1","inotify_rm_watch","ioperm","iopl","ioprio_get","ioprio_set",
"ipc","kexec_load","keyctl","kill","lgetxattr","listen","listxattr","llistxattr",
"lock","lookup_dcookie","lstat","lstat64","madvise","madvise1","mbind","migrate_pages",
"mincore","mlock","mlockall","move_pages","mprotect","mpx",
"mq_getsetattr","mq_notify","mq_open","mq_timedreceive","mq_timedsend","mq_unlink","msgctl","msgget",
"msgrcv","msgsnd","munlock","munlockall","nanosleep","nfsservctl","nice","oldfstat",
"oldlstat","oldolduname","oldstat","olduname","pause","pciconfig_iobase","pciconfig_read","pciconfig_write",
"perf_event_open","in","personality","phys","pipe","pipe2","pivot_root","poll",
"ppoll","prctl","pread64","renamed","preadv","prlimit","prof","profil",
"pselect6","ptrace","putpmsg","query_module","quotactl","read","readahead","readdir",
"readlink","readlinkat","readv","reboot","recv","recvfrom","recvmsg","recvmmsg",
"request_key","restart_syscall","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn",
"rt_sigsuspend","rt_sigtimedwait","rt_tgsigqueueinfo","sched_get_priority_max","sched_get_priority_min","sched_getaffinity","sched_getparam","sched_getscheduler",
"sched_rr_get_interval","sched_setaffinity","sched_setparam","sched_setscheduler","sched_yield","security","select","semctl",
"semget","semop","semtimedop","send","sendmsg","sendto",
"set_mempolicy","set_robust_list","set_thread_area","set_tid_address","set_zone_reclaim","available","setdomainname","setfsgid",
"setfsgid32","setfsuid","setfsuid32","setgid","setgid32","setgroups","setgroups32","sethostname",
"setitimer","setpgid","setpriority","setregid","setregid32","setresgid","setresgid32","setresuid",
"setresuid32","setreuid","setreuid32","setrlimit","setsid","setsockopt","settimeofday","setuid",
"setuid32","setup","sgetmask","shutdown","sigaction","sigaltstack","signal",
"signalfd","signalfd4","sigpending","sigprocmask","sigreturn","sigsuspend","socket","socketcall",
"socketpair","spu_create","spu_run","ssetmask","stat","stat64","statfs","statfs64",
"stime","stty","subpage_prot","swapoff","swapon","sysfs","sysinfo","syslog",
"tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_settime","timerfd_create",
"timerfd_gettime","timerfd_settime","times","tkill","tuxcall","ugetrlimit","ulimit",
"uname","unshare","uselib","ustat","utime","utimensat","utimes",
"vhangup","vm86old","vserver","wait4","waitid","waitpid", "mount"]

innocent_syscalls += ['mtrace_mmap', 'mtrace_munmap', 'mtrace_thread_start']

sync_ops = set(['fsync', 'fdatasync', 'file_sync_range'])
expansive_ops = set(['append', 'trunc', 'write', 'unlink', 'rename'])
pseudo_ops = sync_ops | set(['stdout'])
real_ops = expansive_ops | set(['creat', 'link', 'mkdir', 'rmdir'])

def parse_line(line):
	try:
		toret = Struct()
		# Split the line, the format being 'HH:MM:SS.nnnnn syscall(args...) = RETVALUE ERRORCODE (Error String)'
		m = re.search(r'^([0-9:\.]+) ([^(]+)(\(.*\)) += ([xa-f\-0-9]+|\?) ?(E[^ ]* \([^\(\)]*\)|\([^\(\)]*\))?$', line)

		# Convert time into a numerical value
		time = line[m.start(1) : m.end(1)]
		toret.str_time = time
		time = time.split(':')
		toret.time = int(time[0]) * 60.0 * 60.0 + int(time[1]) * 60.0 + float(time[2])

		toret.syscall = line[m.start(2) : m.end(2)]
		toret.ret = line[m.start(4) : m.end(4)]

		return_explanation = line[m.start(5) : m.end(5)]
		if return_explanation.startswith("E"):
			toret.err = return_explanation
		else:
			toret.return_explanation = return_explanation

		# The arguments part looks something like '(20, "hello", "world", 3)'
		args = csv.reader([line[m.start(3):m.end(3)]], delimiter=',', quotechar='"').next()
		# Now args is ['(20', ' "hello"', ' "world"', ' 3)']
		args = [x[1:] for x in args]
		args[len(args) - 1] = args[len(args) - 1][:-1]
		toret.args = args

		return toret
	except AttributeError as err:
		for innocent_line in ['+++ exited with', ' --- SIG', '<unfinished ...>', ' = ? <unavailable>', 'ptrace(SYSCALL):No such process']:
			if line.find(innocent_line) != -1:
				return False
		print line
		raise err

class MemregionTracker:
	def __init__(self):
		# memregion_map[addr_start] = Struct(addr_end, name, inode, offset)
		self.memregion_map = {}

	def __find_overlap(self, addr_start, addr_end, return_immediately = True):
		toret = []
		for cur_start in self.memregion_map.keys():
			memregion = self.memregion_map[cur_start]
			cur_end = memregion.addr_end
			if (addr_start >= cur_start and addr_start <= cur_end) or \
				(addr_end >= cur_start and addr_end <= cur_end) or \
				(cur_start >= addr_start and cur_start <= addr_end) or \
				(cur_end >= addr_start and cur_end <= addr_end):
				if return_immediately:
					return memregion
				else:
					toret.append(memregion)
		if return_immediately:
			return False
		return toret

	
	def insert(self, addr_start, addr_end, name, inode, offset):
		assert self.__find_overlap(addr_start, addr_end) == False
		self.memregion_map[addr_start] = Struct(addr_start = addr_start, addr_end = addr_end, name = name, inode = inode, offset = offset)

	def remove_overlaps(self, addr_start, addr_end, whole_regions = False):
		while True:
			found_region = self.__find_overlap(addr_start, addr_end)
			if found_region == False:
				return

			found_region = copy.deepcopy(found_region)
			del self.memregion_map[found_region.addr_start]

			if not whole_regions:
				if(found_region.addr_start < addr_start):
					new_region = copy.deepcopy(found_region)
					new_region.addr_end = addr_start - 1
					self.memregion_map[new_region.addr_start] = new_region
				if(found_region.addr_start > addr_end):
					new_region = copy.deepcopy(found_region)
					new_region.addr_start = addr_end + 1
					new_region.offset = (new_region.addr_start - found_region.addr_start) + found_region.offset
					self.memregion_map[new_region.addr_start] = new_region

	def file_mapped(self, inode):
		for region in self.memregion_map.values():
			if region.inode == inode:
				return True
		return False

	def resolve_range(self, addr_start, addr_end):
		toret = []
		overlap_regions = copy.deepcopy(self.__find_overlap(addr_start, addr_end, return_immediately = False))
		overlap_regions = sorted(overlap_regions, key = lambda region: region.addr_start)
		for region in overlap_regions:
			if region.addr_start < addr_start:
				assert addr_start <= region.addr_end
				region.offset = (addr_start - region.addr_start) + region.offset
				region.addr_start = addr_start
			if region.addr_end > addr_end:
				assert addr_end >= region.addr_start
				region.addr_end = addr_end
			assert region.addr_start >= addr_start
			assert region.addr_end <= addr_end
			toret.append(region)
		return toret

class FileDescriptorTracker:
	def __init__(self):
		self.fd_details = {}

	def new_fd_mapping(self, fd, name, pos, attribs, inode):
		if fd in self.fd_details:
			print self.fd_details[fd]
		assert fd not in self.fd_details
		attribs = set(attribs)
		self.fd_details[fd] = Struct(name = name, pos = pos, attribs = attribs, inode = inode)

	def set_equivalent(self, oldfd, newfd):
		assert oldfd in self.fd_details
		assert newfd not in self.fd_details
		self.fd_details[newfd] = self.fd_details[oldfd]

	def remove_fd_mapping(self, fd):
		assert fd in self.fd_details
		del self.fd_details[fd]

	def is_watched(self, fd):
		return (fd in self.fd_details)

	def get_pos(self, fd):
		assert fd in self.fd_details
		return self.fd_details[fd].pos

	def get_inode(self, fd):
		assert fd in self.fd_details
		return self.fd_details[fd].inode

	def get_attribs(self, fd):
		assert fd in self.fd_details
		return self.fd_details[fd].attribs

	def set_pos(self, fd, pos):
		assert fd in self.fd_details
		self.fd_details[fd].pos = pos

	def get_name(self, fd):
		assert fd in self.fd_details
		return self.fd_details[fd].name

	def get_fds_fname(self, name):
		result = [fd for fd in self.fd_details if self.fd_details[fd].name == name]
		return result

	def get_fds(self, inode):
		result = [fd for fd in self.fd_details if self.fd_details[fd].inode == inode]
		return result

	def get_fds_attribs(self, attrib):
		toret = []
		for fd in self.fd_details:
			if attrib in self.fd_details[fd].attribs:
				toret.append(fd)
		return toret

def __replayed_stat(path):
	try:
		return os.stat(replayed_path(path))
	except OSError as err:
		return False

def __parent_inode(path):
	return __replayed_stat(os.path.dirname(path)).st_ino

def __replayed_truncate(path, new_size):
	old_mode = writeable_toggle(replayed_path(path))
	tmp_fd = os.open(replayed_path(path), os.O_WRONLY)
	os.ftruncate(tmp_fd, new_size)
	os.close(tmp_fd)
	writeable_toggle(replayed_path(path), old_mode)

def __get_files_from_inode(inode):
	results = subprocess.check_output(['find', aliceconfig().scratchpad_dir, '-inum', str(inode)])
	toret = []
	for path in results.split('\n'):
		if path != '':
			# Converting the (replayed) path into original path
			assert path.startswith(aliceconfig().scratchpad_dir)
			path = path.replace(aliceconfig().scratchpad_dir, aliceconfig().base_path + '/', 1)
			path = re.sub(r'//', r'/', path)

			assert __replayed_stat(path)
			assert __replayed_stat(path).st_ino == inode
			toret.append(path)
	return toret

class ProcessTracker:
	def __init__(self, pid):
		self.pid = pid
		self.memtracker = MemregionTracker()
		self.fdtracker = FileDescriptorTracker()
		self.fdtracker_unwatched = FileDescriptorTracker()
		self.cwd = aliceconfig().starting_cwd 
		self.child_tids = []

	def record_fork(self, forked_tid):
		assert forked_tid not in ProcessTracker.trackers_map
		toret = copy.deepcopy(self)
		toret.pid = forked_tid
		toret.child_tids = []
		ProcessTracker.trackers_map[forked_tid] = toret
	
	def record_clone(self, cloned_tid):
		assert cloned_tid not in ProcessTracker.trackers_map
		self.child_tids.append(cloned_tid)
		ProcessTracker.trackers_map[cloned_tid] = self

	def record_execve(self):
		fds_to_remove = self.fdtracker.get_fds_attribs('O_CLOEXEC')
		for fd in fds_to_remove:
			self.fdtracker.remove_fd_mapping(fd)

		fds_to_remove = self.fdtracker_unwatched.get_fds_attribs('O_CLOEXEC')
		for fd in fds_to_remove:
			self.fdtracker_unwatched.remove_fd_mapping(fd)

		self.memtracker = MemregionTracker()

		for child_tid in self.child_tids:
			ProcessTracker.trackers_map[child_tid] = None
		self.child_tids = []


	def set_cwd(self, path):
		self.cwd = path

	def original_path(self, path):
		if not path.startswith('/'):
			path = self.cwd + '/' + path
		while True:
			old_path = path
			path = re.sub(r'//', r'/', path)
			path = re.sub(r'/\./', r'/', path)
			path = re.sub(r'/[^/]*/\.\./', r'/', path)
			if path == old_path:
				break
		return path

	trackers_map = {} ## trackers_map[pid] = (memtracker, fdtracker, proctracker)
	@staticmethod
	def get_proctracker(tid):
		if tid not in ProcessTracker.trackers_map:
			# Pid corresponds to a process that was created directly from the workload.
			# i.e., not forked from anywhere
			ProcessTracker.trackers_map[tid] = ProcessTracker(tid)
		toret = ProcessTracker.trackers_map[tid]
		assert toret.pid == tid or tid in toret.child_tids
		return toret

symtab = None
SymbolTableEntry = namedtuple('SymbolTableEntry',
	['func_name', 'instr_offset', 'src_filename', 'src_line_num'])
StackEntry = namedtuple('StackEntry',
	['func_name', 'instr_offset', 'src_filename', 'src_line_num',
	'binary_filename', 'addr_offset', 'raw_addr'])
def __get_backtrace(stackinfo):
	global symtab
	backtrace = []

	if aliceconfig().ignore_stacktrace: return backtrace

	assert stackinfo[0] == '['
	assert stackinfo[-2] == ']'
	stackinfo = stackinfo[1:-2].strip()

	if stackinfo == '':
		return []

	stack_addrs_lst = stackinfo.split()
	for addr in stack_addrs_lst:
		binary_filename, addr_offset, raw_addr = addr.split(':')
		symtab_for_file = symtab[binary_filename]

		# try both addr_offset and raw_addr to see if either one matches:
		if addr_offset in symtab_for_file:
			syms = SymbolTableEntry._make(symtab_for_file[addr_offset])
		elif raw_addr in symtab_for_file:
			syms = SymbolTableEntry._make(symtab_for_file[raw_addr])
		else:
			syms = SymbolTableEntry(None, None, None, None)

		assert len(syms) == 4
		t = StackEntry(syms.func_name, syms.instr_offset, syms.src_filename, syms.src_line_num, binary_filename, addr_offset, raw_addr)
		backtrace.append(t)

	return backtrace

__directory_symlinks = []
def __get_micro_op(syscall_tid, line, stackinfo, mtrace_recorded):
	micro_operations = []

	assert type(syscall_tid) == int
	proctracker = ProcessTracker.get_proctracker(syscall_tid)
	memtracker = proctracker.memtracker
	fdtracker = proctracker.fdtracker
	fdtracker_unwatched = proctracker.fdtracker_unwatched

	global __directory_symlinks
	parsed_line = parse_line(line)

	if parsed_line == False:
		return []

	### Known Issues:
	###	1. Access time with read() kind of calls, modification times in general, other attributes
	###	2. Symlinks

	if parsed_line.syscall == 'open' or \
		(parsed_line.syscall == 'openat' and parsed_line.args[0] == 'AT_FDCWD'):
		if parsed_line.syscall == 'openat':
			parsed_line.args.pop(0)
		flags = parsed_line.args[1].split('|')
		name = proctracker.original_path(eval(parsed_line.args[0]))
		mode = parsed_line.args[2] if len(parsed_line.args) == 3 else False
		fd = safe_string_to_int(parsed_line.ret);
		if is_interesting(name):
			if 'O_WRONLY' in flags or 'O_RDWR' in flags:
				assert 'O_ASYNC' not in flags
				assert 'O_DIRECTORY' not in flags
			if fd >= 0 and 'O_DIRECTORY' not in flags:
				# Finished with most of the asserts and initialization. Actually handling the open() here.

				newly_created = False
				if not __replayed_stat(name):
					assert 'O_CREAT' in flags
					assert 'O_WRONLY' in flags or 'O_RDWR' in flags
					assert len(fdtracker.get_fds_fname(name)) == 0
					assert mode
					tmp_fd = os.open(replayed_path(name), os.O_CREAT | os.O_WRONLY, eval(mode))
					assert tmp_fd > 0
					os.close(tmp_fd)
					inode = __replayed_stat(name).st_ino
					new_op = Struct(op = 'creat', name = name, mode = mode, inode = inode, parent = __parent_inode(name))
					micro_operations.append(new_op)
					newly_created = True
				else:
					inode = __replayed_stat(name).st_ino

				if 'O_TRUNC' in flags:
					assert 'O_WRONLY' in flags or 'O_RDWR' in flags
					if not newly_created:
						new_op = Struct(op = 'trunc', name = name, initial_size = __replayed_stat(name).st_size, final_size = 0, inode = inode)
						micro_operations.append(new_op)
						__replayed_truncate(name, 0)

				fd_flags = []
				if 'O_SYNC' in flags or 'O_DSYNC' in flags or 'O_RSYNC' in flags:
					fd_flags.append('O_SYNC')
				if 'O_CLOEXEC' in flags:
					fd_flags.append('O_CLOEXEC')

				if 'O_APPEND' in flags:
					fdtracker.new_fd_mapping(fd, name, __replayed_stat(name).st_size, fd_flags, inode)
				else:
					fdtracker.new_fd_mapping(fd, name, 0, fd_flags, inode)
		elif fd >= 0:
			fd_flags = []
			if 'O_CLOEXEC' in flags:
				fd_flags.append('O_CLOEXEC')
			fdtracker_unwatched.new_fd_mapping(fd, name, 0, fd_flags, 0)
	elif parsed_line.syscall in ['write', 'writev', 'pwrite', 'pwritev']:	
		fd = safe_string_to_int(parsed_line.args[0])
		name = None
		if fdtracker_unwatched.is_watched(fd):
			name = fdtracker_unwatched.get_name(fd)
		elif fdtracker.is_watched(fd):
			name = fdtracker.get_name(fd)
		if fdtracker.is_watched(fd) or fd == 1:
			dump_file = eval(parsed_line.args[-2])
			dump_offset = safe_string_to_int(parsed_line.args[-1])
			if fd == 1:
				count = safe_string_to_int(parsed_line.args[2])
				fd_data = os.open(dump_file, os.O_RDONLY)
				os.lseek(fd_data, dump_offset, os.SEEK_SET)
				buf = os.read(fd_data, count)
				os.close(fd_data)
				new_op = Struct(op = 'stdout', data = buf)
				micro_operations.append(new_op)
			else:
				if parsed_line.syscall == 'write':
					count = safe_string_to_int(parsed_line.args[2])
					pos = fdtracker.get_pos(fd)
				elif parsed_line.syscall == 'writev':
					count = safe_string_to_int(parsed_line.args[3])
					pos = fdtracker.get_pos(fd)
				elif parsed_line.syscall == 'pwrite':
					count = safe_string_to_int(parsed_line.args[2])
					pos = safe_string_to_int(parsed_line.args[3])
				elif parsed_line.syscall == 'pwritev':
					count = safe_string_to_int(parsed_line.args[4])
					pos = safe_string_to_int(parsed_line.args[3])
				assert safe_string_to_int(parsed_line.ret) == count
				name = fdtracker.get_name(fd)
				inode = fdtracker.get_inode(fd)
				size = __replayed_stat(name).st_size
				overwrite_size = 0
				if pos < size:
					if pos + count < size:
						overwrite_size = count
					else:
						overwrite_size = size - pos
					new_op = Struct(op = 'write', name = name, offset = pos, count = overwrite_size, dump_file = dump_file, dump_offset = dump_offset, inode = inode)
					assert new_op.count > 0
					micro_operations.append(new_op)
					if 'O_SYNC' in fdtracker.get_attribs(fd):
						new_op = Struct(op = 'file_sync_range', name = name, offset = pos, count = overwrite_size, inode = inode)
						micro_operations.append(new_op)
				pos += overwrite_size
				count -= overwrite_size
				dump_offset += overwrite_size

				if(pos > size):
					new_op = Struct(op = 'trunc', name = name, final_size = pos, inode = inode, initial_size = size)
					micro_operations.append(new_op)
					__replayed_truncate(name, size)
					size = pos

				if(pos + count > size):
					new_op = Struct(op = 'append', name = name, offset = pos, count = count, dump_file = dump_file, dump_offset = dump_offset, inode = inode)
					micro_operations.append(new_op)
					__replayed_truncate(name, pos + count)

					if 'O_SYNC' in fdtracker.get_attribs(fd):
						new_op = Struct(op = 'file_sync_range', name = name, offset = pos, count = count, inode = inode)
						micro_operations.append(new_op)
				if parsed_line.syscall not in ['pwrite', 'pwritev']:
					fdtracker.set_pos(fd, pos + count)
	elif parsed_line.syscall == 'close':
		if int(parsed_line.ret) == -1:
			if aliceconfig().debug_level >= 2:
				print 'WARNING: close() returned -1. ' + line
		else:
			fd = safe_string_to_int(parsed_line.args[0])
			if fdtracker.is_watched(fd):
				fdtracker.remove_fd_mapping(fd)
			else:
				if fdtracker_unwatched.is_watched(fd):
					fdtracker_unwatched.remove_fd_mapping(fd)
	elif parsed_line.syscall == 'link':
		if int(parsed_line.ret) != -1:
			source = proctracker.original_path(eval(parsed_line.args[0]))
			dest = proctracker.original_path(eval(parsed_line.args[1]))
			if is_interesting(source):
				assert is_interesting(dest)
				assert not __replayed_stat(dest)
				assert __replayed_stat(source)
				source_inode = __replayed_stat(source).st_ino
				micro_operations.append(Struct(op = 'link', source = source, dest = dest, source_inode = source_inode, source_parent = __parent_inode(source), dest_parent = __parent_inode(dest)))
				os.link(replayed_path(source), replayed_path(dest))
			else:
				assert not is_interesting(dest)
	elif parsed_line.syscall == 'rename':
		if int(parsed_line.ret) != -1:
			source = proctracker.original_path(eval(parsed_line.args[0]))
			dest = proctracker.original_path(eval(parsed_line.args[1]))
			if is_interesting(source):
				assert is_interesting(dest)
				assert __replayed_stat(source)
				source_inode = __replayed_stat(source).st_ino
				source_hardlinks = __replayed_stat(source).st_nlink
				source_size = __replayed_stat(source).st_size
				dest_inode = False
				dest_hardlinks = 0
				dest_size = 0
				if __replayed_stat(dest):
					dest_inode = __replayed_stat(dest).st_ino
					dest_hardlinks = __replayed_stat(dest).st_nlink
					dest_size = __replayed_stat(dest).st_size
				micro_operations.append(Struct(op = 'rename', source = source, dest = dest, source_inode = source_inode, dest_inode = dest_inode, source_parent = __parent_inode(source), dest_parent = __parent_inode(dest), source_hardlinks = source_hardlinks, dest_hardlinks = dest_hardlinks, dest_size = dest_size, source_size = source_size))
				if dest_hardlinks == 1:
					assert len(fdtracker.get_fds(dest_inode)) == 0
					assert memtracker.file_mapped(dest_inode) == False
					os.rename(replayed_path(dest), replayed_path(dest) + '.deleted_' + str(uuid.uuid1()))
				os.rename(replayed_path(source), replayed_path(dest))
	elif parsed_line.syscall == 'unlink':
		if int(parsed_line.ret) != -1:
			name = proctracker.original_path(eval(parsed_line.args[0]))
			if is_interesting(name):
				assert __replayed_stat(name)
				inode = __replayed_stat(name).st_ino
				if os.path.isdir(replayed_path(name)):
					assert inode in __directory_symlinks
					micro_operations.append(Struct(op = 'rmdir', name = name, inode = inode, parent = __parent_inode(name)))
					os.rename(replayed_path(name), replayed_path(name) + '.deleted_' + str(uuid.uuid1()))
				else:
					hardlinks = __replayed_stat(name).st_nlink
					size = __replayed_stat(name).st_size
					micro_operations.append(Struct(op = 'unlink', name = name, inode = inode, hardlinks = hardlinks, parent = __parent_inode(name), size = size))
					# A simple os.unlink might be sufficient, but making sure that the inode is not re-used.
					if hardlinks > 1:
						os.unlink(replayed_path(name))
						if len(fdtracker.get_fds(inode)) > 1:
							print "Warning: File unlinked while being open: " + name
						if memtracker.file_mapped(inode):
							print "Warning: File unlinked while being mapped: " + name
					else:
						os.rename(replayed_path(name), replayed_path(name) + '.deleted_' + str(uuid.uuid1()))
	elif parsed_line.syscall == 'lseek':
		if int(parsed_line.ret) != -1:
			fd = safe_string_to_int(parsed_line.args[0])
			if fdtracker.is_watched(fd):
				fdtracker.set_pos(fd, int(parsed_line.ret))
	elif parsed_line.syscall in ['truncate', 'ftruncate']:
		assert int(parsed_line.ret) != -1
		if parsed_line.syscall == 'truncate':
			name = proctracker.original_path(eval(parsed_line.args[0]))
			interesting = is_interesting(name)
			if interesting:
				assert __replayed_stat(name)
				inode = __replayed_stat(name).st_ino
				init_size = __replayed_stat(name).st_size
		else:
			fd = safe_string_to_int(parsed_line.args[0])
			interesting = fdtracker.is_watched(fd)
			if interesting:
				name = fdtracker.get_name(fd)
				inode = fdtracker.get_inode(fd)
				files = __get_files_from_inode(inode)
				assert len(files) > 0
				init_size = __replayed_stat(files[0]).st_size
		if interesting:
			size = safe_string_to_int(parsed_line.args[1])
			new_op = Struct(op = 'trunc', name = name, final_size = size, inode = inode, initial_size = init_size)
			micro_operations.append(new_op)
			__replayed_truncate(name, size)
	elif parsed_line.syscall == 'fallocate':
		if int(parsed_line.ret) != -1:
			fd = safe_string_to_int(parsed_line.args[0])
			if fdtracker.is_watched(fd):
				mode = parsed_line.args[1]
				assert mode == '0'
				offset = safe_string_to_int(parsed_line.args[2])
				count = safe_string_to_int(parsed_line.args[3])
				inode = fdtracker.get_inode(fd)
				init_size = __replayed_stat(name).st_size
				if offset + size > init_size:
					new_op = Struct(op = 'trunc', name = name, final_size = offset + count, inode = inode, initial_size = init_size)
					micro_operations.append(new_op)
					__replayed_truncate(name, offset + count)
				data = ''.join('0' for x in range(count))
				new_op = Struct(op = 'write', name = name, inode = inode, offset = offset, count = count, dump_file = '', dump_offset = 0, override_data = data)
				assert new_op.count > 0
				micro_operations.append(new_op)
	elif parsed_line.syscall in ['fsync', 'fdatasync']:
		assert int(parsed_line.ret) == 0
		fd = safe_string_to_int(parsed_line.args[0])
		if fdtracker.is_watched(fd):
			name = fdtracker.get_name(fd)
			inode = fdtracker.get_inode(fd)
			files = __get_files_from_inode(inode)
			assert len(files) > 0
			size = __replayed_stat(files[0]).st_size
			micro_operations.append(Struct(op = parsed_line.syscall, name = name, inode = inode, size = size))
	elif parsed_line.syscall == 'mkdir':
		if int(parsed_line.ret) != -1:
			name = proctracker.original_path(eval(parsed_line.args[0]))
			mode = parsed_line.args[1]
			if is_interesting(name):
				os.mkdir(replayed_path(name), eval(mode))
				inode = __replayed_stat(name).st_ino
				micro_operations.append(Struct(op = 'mkdir', name = name, mode = mode, inode = inode, parent = __parent_inode(name)))
	elif parsed_line.syscall == 'rmdir':
		if int(parsed_line.ret) != -1:
			name = proctracker.original_path(eval(parsed_line.args[0]))
			if is_interesting(name):
				inode = __replayed_stat(name).st_ino
				micro_operations.append(Struct(op = 'rmdir', name = name, inode = inode, parent = __parent_inode(name)))
				os.rename(replayed_path(name), replayed_path(name) + '.deleted_' + str(uuid.uuid1()))
	elif parsed_line.syscall == 'chdir':
		if int(parsed_line.ret) == 0:
			proctracker.set_cwd(proctracker.original_path(eval(parsed_line.args[0])))
	elif parsed_line.syscall == 'fchdir':
		if int(parsed_line.ret) == 0:
			fd = eval(parsed_line.args[0])
			if fdtracker.is_watched(fd):
				name = fdtracker.get_name(fd)
			else:
				assert fdtracker_unwatched.is_watched(fd)
				name = fdtracker_unwatched.get_name(fd)
			proctracker.set_cwd(name)
	elif parsed_line.syscall == 'clone':
		new_tid = int(parsed_line.ret)
		if new_tid != -1:
			flags_string = parsed_line.args[1]
			assert(flags_string.startswith("flags="))
			flags = flags_string[6:].split('|')
			if 'CLONE_VM' in flags:
				assert 'CLONE_FILES' in flags
				assert 'CLONE_FS' in flags
				proctracker.record_clone(new_tid)
			else:
				assert 'CLONE_FILES' not in flags
				assert 'CLONE_FS' not in flags
				proctracker.record_fork(new_tid)
	elif parsed_line.syscall == 'vfork':
		new_pid = int(parsed_line.ret)
		if new_pid != -1:
			proctracker.record_fork(new_pid)
	elif parsed_line.syscall in ['fcntl', 'fcntl64']:
		fd = safe_string_to_int(parsed_line.args[0])
		cmd = parsed_line.args[1]
		assert cmd in ['F_GETFD', 'F_SETFD', 'F_GETFL', 'F_SETFL', 'F_SETLK', 'F_SETLKW', 'F_GETLK', 'F_SETLK64', 'F_SETLKW64', 'F_GETLK64', 'F_DUPFD']

		tracker = None
		if fdtracker.is_watched(fd):
			tracker = fdtracker
		elif fdtracker_unwatched.is_watched(fd):
			tracker = fdtracker_unwatched

		if tracker:
			if cmd == 'F_SETFD':
				assert parsed_line.args[2] in ['FD_CLOEXEC', '0']
				if parsed_line.args[2] == 'FD_CLOEXEC':
					tracker.get_attribs(fd).add('O_CLOEXEC')
				else:
					tracker.get_attribs(fd).discard('O_CLOEXEC')
			elif cmd == 'F_DUPFD' and eval(parsed_line.ret) != -1:
				new_fd = eval(parsed_line.ret)
				old_fd = eval(parsed_line.args[0])
				tracker.set_equivalent(old_fd, new_fd)
			elif cmd == 'F_SETFL':
				assert tracker == fdtracker_unwatched
	elif parsed_line.syscall in ['mmap', 'mmap2']:
		addr_start = safe_string_to_int(parsed_line.ret)
		length = safe_string_to_int(parsed_line.args[1])
		prot = parsed_line.args[2].split('|')
		flags = parsed_line.args[3].split('|')
		fd = safe_string_to_int(parsed_line.args[4])
		offset = safe_string_to_int(parsed_line.args[5])
		if parsed_line.syscall == 'mmap2':
			offset = offset * 4096

		if addr_start == -1:
			return

		addr_end = addr_start + length - 1
		if 'MAP_FIXED' in flags:
			given_addr = safe_string_to_int(parsed_line.args[0])
			assert given_addr == addr_start
			assert 'MAP_GROWSDOWN' not in flags
			memtracker.remove_overlaps(addr_start, addr_end)

		if 'MAP_ANON' not in flags and 'MAP_ANONYMOUS' not in flags and \
			fdtracker.is_watched(fd) and 'MAP_SHARED' in flags and \
			'PROT_WRITE' in prot:

			name = fdtracker.get_name(fd)
			file_size = __replayed_stat(name).st_size
			assert file_size <= offset + length
			if not aliceconfig().ignore_mmap: assert syscall_tid in mtrace_recorded
			assert 'MAP_GROWSDOWN' not in flags
			memtracker.insert(addr_start, addr_end, fdtracker.get_name(fd), fdtracker.get_inode(fd), offset)
	elif parsed_line.syscall == 'munmap':
		addr_start = safe_string_to_int(parsed_line.args[0])
		length = safe_string_to_int(parsed_line.args[1])
		addr_end = addr_start + length - 1
		ret = safe_string_to_int(parsed_line.ret)
		if ret != -1:
			memtracker.remove_overlaps(addr_start, addr_end, whole_regions = True)
	elif parsed_line.syscall == 'msync':
		addr_start = safe_string_to_int(parsed_line.args[0])
		length = safe_string_to_int(parsed_line.args[1])
		flags = parsed_line.args[2].split('|')
		ret = safe_string_to_int(parsed_line.ret)

		addr_end = addr_start + length - 1
		if ret != -1:
			regions = memtracker.resolve_range(addr_start, addr_end)
			for region in regions:
				count = region.addr_end - region.addr_start + 1
				new_op = Struct(op = 'file_sync_range', name = region.name, inode = region.inode, offset = region.offset, count = count)
				micro_operations.append(new_op)
	elif parsed_line.syscall == 'mwrite':
		addr_start = safe_string_to_int(parsed_line.args[0])
		length = safe_string_to_int(parsed_line.args[2])
		dump_file = eval(parsed_line.args[3])
		dump_offset = safe_string_to_int(parsed_line.args[4])

		addr_end = addr_start + length - 1
		regions = memtracker.resolve_range(addr_start, addr_end)
		for region in regions:
			count = region.addr_end - region.addr_start + 1
			cur_dump_offset = dump_offset + (region.addr_start - addr_start)
			offset = region.offset
			name = region.name
			inode = region.inode
			new_op = Struct(op = 'write', name = name, inode = inode, offset = offset, count = count, dump_file = dump_file, dump_offset = cur_dump_offset)
			assert new_op.count > 0
			micro_operations.append(new_op)
	elif parsed_line.syscall in ['dup', 'dup2', 'dup3']:
		newfd = safe_string_to_int(parsed_line.ret)
		oldfd = safe_string_to_int(parsed_line.args[0])
		if newfd != -1:
			if parsed_line.syscall in ['dup2', 'dup3']:
				if fdtracker.is_watched(newfd):
					fdtracker.remove_fd_mapping(newfd)
				elif fdtracker_unwatched.is_watched(newfd):
					fdtracker_unwatched.remove_fd_mapping(newfd)
			if fdtracker.is_watched(oldfd):
				fdtracker.set_equivalent(oldfd, newfd)
			elif fdtracker_unwatched.is_watched(oldfd):
				fdtracker_unwatched.set_equivalent(oldfd, newfd)
	elif parsed_line.syscall in ['chmod', 'fchmod', 'chown', 'fchown', 'umask']:
		if parsed_line.syscall.startswith('f'):
			fd = eval(parsed_line.args[0])
			if fdtracker.is_watched(fd):
				print 'WARNING: ' + line + ' :: file = ' + fdtracker.get_name(fd)
		elif parsed_line.syscall == 'umask':
			if not 'umask_warned' in globals():
				globals()['umask_warned'] = True
				print 'WARNING: UMASK'
		else:
			name = proctracker.original_path(eval(parsed_line.args[0]))
			if is_interesting(name):
				print 'WARNING: ' + line
	elif parsed_line.syscall == 'ioctl':
		fd = int(parsed_line.args[0])
		assert not fdtracker.is_watched(fd)
		if fd not in [0, 1, 2]:
			name = None
			if fdtracker_unwatched.is_watched(fd):
				name = fdtracker_unwatched.get_name(fd)
			debug_level = 0
			for start in ['/usr/bin', '/dev/snd', '/dev/tty', '/dev/vmnet', '/dev/urandom'] + aliceconfig().ignore_ioctl:
				if str(name).startswith(start):
					debug_level = 2
			if name == None:
				debug_level = 2
			if aliceconfig().debug_level >= debug_level:
				print 'WARNING: ' + line + ' name = ' + str(name)
	elif parsed_line.syscall in ['shmget', 'shmat', 'shmdt', 'shmctl']:
		if parsed_line.syscall == 'shmget':
			assert parsed_line.args[0] == 'IPC_PRIVATE'
	elif parsed_line.syscall == 'execve':
		proctracker.record_execve()
	elif parsed_line.syscall in ['io_setup', 'aio_read', 'io_getevents', 'io_destroy']:
		if aliceconfig().debug_level >= 2:
			print 'Warning: AIO ' + line
	elif parsed_line.syscall == 'symlink':
		if eval(parsed_line.ret) != -1:
			source = proctracker.original_path(eval(parsed_line.args[0]))
			dest = proctracker.original_path(eval(parsed_line.args[1]))
			if is_interesting(dest) or is_interesting(source):
				print 'WARNING: ' + line
			if is_interesting(dest):
				source_is_dir = False
				if source.startswith(aliceconfig().base_path):
					if os.path.isdir(replayed_path(source)):
						source_is_dir = True
				else:
					print 'WARNING: symlink source outside base path. Assuming file link.'
				if source_is_dir == True:
					os.mkdir(replayed_path(dest), 0777)
					inode = __replayed_stat(dest).st_ino
					__directory_symlinks.append(inode)
					micro_operations.append(Struct(op = 'mkdir', name = dest, mode = '0777', inode = inode, parent = __parent_inode(dest)))
				else:
					tmp_fd = os.open(replayed_path(dest), os.O_CREAT | os.O_WRONLY, 0666)
					assert tmp_fd > 0
					os.close(tmp_fd)
					inode = __replayed_stat(dest).st_ino
					new_op = Struct(op = 'creat', name = dest, mode = 0666, inode = inode, parent = __parent_inode(dest))
					micro_operations.append(new_op)
	elif parsed_line.syscall == 'mremap':
		ret_address = safe_string_to_int(parsed_line.ret)
		if ret_address != -1:
			start_addr = safe_string_to_int(parsed_line.args[0])
			end_addr = start_addr + safe_string_to_int(parsed_line.args[1]) - 1
			assert(len(memtracker.resolve_range(start_addr, end_addr)) == 0)
	else:
		if parsed_line.syscall not in innocent_syscalls and not parsed_line.syscall.startswith("ignore_"):
			raise Exception("Unhandled system call: " + parsed_line.syscall)
	for op in micro_operations:
		op.hidden_tid = syscall_tid
		op.hidden_time = parsed_line.str_time
		op.hidden_pid = proctracker.pid
		op.hidden_full_line = copy.deepcopy(line)
		op.hidden_parsed_line = copy.deepcopy(parsed_line)
		op.hidden_stackinfo = copy.deepcopy(stackinfo)
		op.hidden_backtrace = __get_backtrace(stackinfo)
	return micro_operations


def get_micro_ops():
	global innocent_syscalls, symtab, SymbolTableEntry

	files = commands.getoutput("ls " + aliceconfig().strace_file_prefix + ".* | grep -v byte_dump | grep -v stackinfo | grep -v symtab").split()
	rows = []
	mtrace_recorded = []
	assert len(files) > 0
	for trace_file in files:
		f = open(trace_file, 'r')
		array = trace_file.split('.')
		pid = int(array[len(array) - 1])
		if array[-2] == 'mtrace':
			mtrace_recorded.append(pid)
		dump_offset = 0
		m = re.search(r'\.[^.]*$', trace_file)
		dump_file = trace_file[0 : m.start(0)] + '.byte_dump' + trace_file[m.start(0) : ]
		if not aliceconfig().ignore_stacktrace:
			stackinfo_file = open(trace_file[0 : m.start(0)] + '.stackinfo' + trace_file[m.start(0) : ], 'r')
		for line in f:
			parsed_line = parse_line(line)
			if parsed_line:
				if parsed_line.syscall in ['write', 'writev', 'pwrite', 'pwritev', 'mwrite']:
					if parsed_line.syscall == 'pwrite':
						write_size = safe_string_to_int(parsed_line.args[-2])
					else:
						write_size = safe_string_to_int(parsed_line.args[-1])
					m = re.search(r'\) += [^,]*$', line)
					line = line[ 0 : m.start(0) ] + ', "' + dump_file + '", ' + str(dump_offset) + line[m.start(0) : ]
					dump_offset += write_size
				stacktrace = '[]\n' if aliceconfig().ignore_stacktrace else stackinfo_file.readline()
				if parsed_line.syscall in innocent_syscalls or parsed_line.syscall.startswith("ignore_"):
					pass
				else:
					rows.append((pid, parsed_line.time, line, stacktrace))

	rows = sorted(rows, key = lambda row: row[1])
	
	os.system("rm -rf " + aliceconfig().scratchpad_dir)
	os.system("cp -R " + aliceconfig().initial_snapshot + " " + aliceconfig().scratchpad_dir)

	path_inode_map = get_path_inode_map(aliceconfig().scratchpad_dir)

	if not aliceconfig().ignore_stacktrace:
		symtab = pickle.load(open(aliceconfig().strace_file_prefix + '.symtab'))
	micro_operations = []
	for row in rows:
		syscall_tid = row[0]
		line = row[2]
		stackinfo = row[3]
		line = line.strip()
		try:
			micro_operations += __get_micro_op(syscall_tid, line, stackinfo, mtrace_recorded)
		except:
			traceback.print_exc()
			print row
			print '----------------------------------------------------'
			for op in micro_operations:
				print op
			exit()

	return (path_inode_map, micro_operations)
