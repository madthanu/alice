#!/usr/bin/env python

# Pretty-print the output of strace++, using gdb to print out the
# function/file/line info for stack traces
#
#	 argv[1] - output from strace++ (use -o <outfile> option to create the trace file)
#
# (also requires the 'file' program to be installed in addition to 'gdb')
#
# by Philip Guo

import os, sys, re, subprocess, cPickle
from collections import defaultdict, namedtuple
import commands

# Return a symbol table, which is a dict where:
#
#	 Key: Filename
#	 Value: Dict where ...
#						Key: hex address (string)
#						Value: (function name, instruction offset, filename, line number)
#									 Any of those fields might be null when there isn't adequate debug info
#
# containing all the debug info needed to pretty-print the entries
#
# Input: fn is the filename of the strace++ output trace file
def create_symtab(fn_list):
	# each element is a string representing a return address, e.g.,:
	#	 '/lib32/libc-2.11.1.so:0x6990d:0xf769390d'
	# it's a colon-separated triple containing:
	#	 1.) absolute path to the binary
	#	 2.) our best guess at the offset within that binary
	#	 3.) the original return address (in case the calculated offset is bogus)
	return_addrs_set = set()

	for fn in fn_list:
		# do a first pass to find ALL return addresses, so that we can call gdb to do a lookup
		for line in open(fn):
			# look for a raw stack trace of addrs like:
			#	 [ /lib32/libc-2.11.1.so:0x67aef:0xf75ccaef /lib32/libc-2.11.1.so:0x67e06:0xf75cce06 ]
			if line.strip() == '[]':
				continue
			if line[0] == '[':
				first_rb = line.find(']')
				stack_addrs = line[1:first_rb].strip()
				if stack_addrs:
					stack_addrs = stack_addrs.split()
					for addr in stack_addrs:
						return_addrs_set.add(addr)


	# Key: filename
	# Value: set of (addr_offset, original_addr)
	d = defaultdict(set)

	for e in return_addrs_set:
		try:
			filename, addr_offset, original_addr = e.split(':')
		except:
			print e
			assert False
		d[filename].add((addr_offset, original_addr))


	# Key: filename
	# Value: list of addresses to query (strings representing hex numbers)
	filenames_to_addrs = defaultdict(list)


	for filename, addrs_set in d.iteritems():
		# use the following heuristic to determine which address to use:
		#	 - if the file is an 'executable', then use original_addr
		#	 - otherwise if the file is a 'shared object', then use addr_offset
		#
		# shared objects are usually mmapped into "high" addresses and thus need an
		# addr_offset, while exectuables usually do NOT need an offset and can instead
		# use their original_addr to do symbol lookups
		(file_out, _) = subprocess.Popen(['file', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
		if 'shared object' in file_out:
			for (addr_offset, _) in addrs_set:
				filenames_to_addrs[filename].append(addr_offset)
		elif 'executable' in file_out:
			for (_, original_addr) in addrs_set:
				filenames_to_addrs[filename].append(original_addr)
		else:
			print >> sys.stderr, "Warning:", filename, "doesn't appear to be an executable or shared library"


	return get_symbol_table_using_gdb(filenames_to_addrs)


# some fields might be null if there isn't adequate debug info
SymbolTableEntry = namedtuple('SymbolTableEntry',
	['func_name', 'instr_offset', 'src_filename', 'src_line_num'])

# Use gdb to probe the debug info of binaries in order to return a symbol
# table, which is structured as a dict where:
#
#	 Key: Filename
#	 Value: Dict where ...
#						Key: hex address (string)
#						Value: a SymbolTableEntry object
#
# The advantage of using gdb is that you can usually get file/line info, and gdb
# supports "splitdebug" binaries where the debug info is stored in a separate
# binary linked with .gnu_debuglink
# (See: http://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html)
#
# The disadvantage is that gdb is quite heavyweight.	Also, when you can't get
# .gnu_debuglink to work with custom paths (e.g., on Chrome OS), then gdb
# won't print out the proper debug info.	TODO: try to look into improving this!
#
# Input: filenames_to_addrs is a dict mapping each binary filename to a list of
# addresses (strings representing hex numbers) on which to query for debug info
def get_symbol_table_using_gdb(filenames_to_addrs):
	ret = defaultdict(dict)

	lineRE = re.compile('Line (\d+) of "(.*)" starts at address 0x\S+ <(.*?)> and ends at 0x\S+')
	# even if there's no line number info, it might give you the function name
	# e.g., in "No line number information available for address 0x857 <_dl_start_user>"
	# at least you can find out that the function name is _dl_start_user
	noLineInfoRE = re.compile('No line number information available for address 0x\S+ <(.*?)>')

	# for each file, create a gdb script to introspect all elements of addr_list
	for filename, addrs_lst in filenames_to_addrs.iteritems():
		# now create a gdb script with some filler and the critical line that makes
		# the query for debug info: 'info line *<addr>'
		tmp_gdb_script = open('temp.gdb', 'w')
		for addr in sorted(addrs_lst):
			print >> tmp_gdb_script, 'echo ===\\n'
			print >> tmp_gdb_script, 'echo ' + addr + '\\n'
			print >> tmp_gdb_script, 'info line *' + addr
		tmp_gdb_script.close() # force write to disk, or else temp.gdb will be empty!

		# now run:
		#	 gdb <filename> -batch -x temp.gdb
		# and harvest its stdout
		# ( -batch mode allows gdb to produce 'clean' output and be run as a subprocess
		#	 see: http://ftp.gnu.org/old-gnu/Manuals/gdb-5.1.1/html_node/gdb_8.html )
		(gdb_stdout, gdb_stderr) = subprocess.Popen(['gdb', filename, '-batch', '-x', 'temp.gdb'],
																								stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
		if gdb_stderr:
			print >> sys.stderr, "GDB warnings while processing %s:" % (filename,), gdb_stderr,

		# parse the output of gdb, where each record is:
		# ===
		# <hex address>
		# one or more lines containing the output of gdb (which should be appended together later)
		tokens = gdb_stdout.split('===')
		for t in tokens:
			if not t:
				continue
			# collapse all space-like characters into a single space to simplify parsing later
			t = re.sub('\s+', ' ', t).strip()
			hex_addr = t.split()[0].strip()
			# gdb output is the REST of the line
			gdb_out = t[len(hex_addr):].strip()
			#print hex_addr, gdb_out

			assert hex_addr.startswith('0x')

			m = lineRE.match(gdb_out)
			if m:
				(linenum, src_filename, funcname) = m.groups()
				# split up "funcname+offset", e.g., 'main+21'
				s = funcname.split('+')
				# don't just assume that funcname splits into either 1 or 2 components.	Sometimes
				# there are weird function names like "STRING::operator+=(char const*)+91"
				# containing a '+' in the function name!!!
				if len(s) > 1:
					offset = int(s[-1]) # the FINAL component should be the offset number
					funcname = '+'.join(s[:-1]) # join the REST of the components into funcname
				else:
					offset = 0
					funcname = s[0]

				ret[filename][hex_addr] = tuple(SymbolTableEntry(funcname, offset, src_filename, int(linenum)))
			else:
				m = noLineInfoRE.match(gdb_out)
				if m:
					funcname = m.group(1)

					s = funcname.split('+')
					assert len(s) <= 2
					offset = 0
					if len(s) == 2:
						offset = int(s[1])
					funcname = s[0]
					ret[filename][hex_addr] = tuple(SymbolTableEntry(funcname, offset, None, None))

	return ret


strace_file_prefix = sys.argv[1]
output_file = strace_file_prefix + '.symtab'
stack_files = commands.getoutput("ls " + strace_file_prefix + "*stackinfo*").split()

symtab = create_symtab(stack_files)

cPickle.dump(symtab, open(output_file, "wb"))
