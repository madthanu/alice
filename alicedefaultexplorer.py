#!/usr/bin/env python
import os
import subprocess
import cProfile
import Queue
import threading
import time
import pprint
import code
import sys
import collections
import gc
from alice import aliceconfig
from alice import Replayer
from alicedefaultfs import defaultfs

class MultiThreadedChecker(threading.Thread):
	queue = Queue.Queue()
	outputs = {}
	
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.queue = MultiThreadedChecker.queue

	def __threaded_check(self, dirname, crashid):
		assert type(aliceconfig().checker_tool) in [list, str, tuple]
		args = [aliceconfig().checker_tool, dirname, dirname + '.input_stdout']
		output_stdout = dirname + '.output_stdout'
		output_stderr = dirname + '.output_stderr'
		retcode = subprocess.call(args, stdout = open(output_stdout, 'w'), stderr = open(output_stderr, 'w'))
		MultiThreadedChecker.outputs[crashid] = retcode
		os.system('rm -rf ' + dirname)

	def run(self):
		while True:
			task = self.queue.get()
			self.__threaded_check(*task)
			self.queue.task_done()

	@staticmethod
	def check_later(dirname, retcodeid):
		MultiThreadedChecker.queue.put((dirname, retcodeid))

	@staticmethod
	def reset():
		assert MultiThreadedChecker.queue.empty()
		MultiThreadedChecker.outputs = {}

	@staticmethod
	def wait_and_get_outputs():
		MultiThreadedChecker.queue.join()
		return MultiThreadedChecker.outputs

def stack_repr(op):
	try:
		backtrace = 0
		try:
			backtrace = op.hidden_backtrace
		except:
			pass
		found = False
		#code.interact(local=dict(globals().items() + locals().items()))
		for i in range(0, len(backtrace)):
			stack_frame = backtrace[i]
			if stack_frame.src_filename != None and 'syscall-template' in stack_frame.src_filename:
				continue
			if '/libc' in stack_frame.binary_filename:
				continue
			if stack_frame.func_name != None and 'output_stacktrace' in stack_frame.func_name:
				continue
			found = True
			break
		if not found:
			raise Exception('Standard stack traverse did not work')
		if stack_frame.src_filename == None:
			return 'B-' + str(stack_frame.binary_filename) + ':' + str(stack_frame.raw_addr) + '[' + str(stack_frame.func_name).replace('(anonymous namespace)', '()') + ']'
		return str(stack_frame.src_filename) + ':' + str(stack_frame.src_line_num) + '[' + str(stack_frame.func_name).replace('(anonymous namespace)', '()') + ']'
	except Exception as e:
		return 'Unknown (stacktraces not traversable for finding static vulnerabilities):' + op.hidden_id


def default_checks(alice_args, threads = 1):
	print 'Parsing traces to determine logical operations ...'
	replayer = Replayer(alice_args)
	replayer.set_fs(defaultfs('count', 1))

	print 'Logical operations:'
	replayer.print_ops()

	assert threads > 0
	for i in range(0, threads):
		t = MultiThreadedChecker(MultiThreadedChecker.queue)
		t.setDaemon(True)
		t.start()

	atomic_patch_middle = set()

	print 'Finding vulnerabilities...'
	# Finding across-syscall atomicity
	for i in range(0, replayer.mops_len()):
		dirname = os.path.join(aliceconfig().scratchpad_dir, 'reconstructeddir-' + str(i))
		replayer.dops_end_at((i, replayer.dops_len(i) - 1))
		replayer.construct_crashed_dir(dirname, dirname + '.input_stdout')
		MultiThreadedChecker.check_later(dirname, i)

	checker_outputs = MultiThreadedChecker.wait_and_get_outputs()
	staticvuls = set()
	i = 0
	while(i < replayer.mops_len()):
		if checker_outputs[i] != 0:
			patch_start = i
			atomic_patch_middle.add(i)
			# Go until the last but one mop
			while(i < replayer.mops_len() - 1 and checker_outputs[i + 1] != 0):
				atomic_patch_middle.add(i)
				i += 1
			patch_end = i + 1
			if patch_end >= replayer.mops_len():
				patch_end = replayer.mops_len() - 1
				print 'WARNING: Application found to be inconsistent after the entire workload completes. Recheck workload and checker. Possible bug in ALICE framework if this is not expected.'
			print '(Dynamic vulnerability) Across-syscall atomicity, sometimes concerning durability: ' + \
				'Operations ' + str(patch_start) + ' until ' + str(patch_end) + ' need to be atomically persisted'
			staticvuls.add((stack_repr(replayer.get_op(patch_start)),
				stack_repr(replayer.get_op(patch_end))))
		i += 1

	for vul in staticvuls:
		print '(Static vulnerability) Across-syscall atomicity: ' + \
			'Operation ' + vul[0] + ' until ' + vul[1]

	# Finding ordering vulnerabilities
	replayer.load(0)
	MultiThreadedChecker.reset()

	for i in range(0, replayer.mops_len()):
		if replayer.dops_len(i) == 0 or i in atomic_patch_middle or (i - 1) in atomic_patch_middle:
			continue

		for j in range(0, replayer.dops_len(i)):
			replayer.dops_omit((i, j))

		for j in range(i + 1, replayer.mops_len()):
			if replayer.dops_len(j)  == 0 or j in atomic_patch_middle:
				continue
			replayer.dops_end_at((j, replayer.dops_len(j) - 1))
			if replayer.is_legal():
				dirname = os.path.join(aliceconfig().scratchpad_dir, 'reconstructeddir-' + str(i) + '-' + str(j))
				replayer.construct_crashed_dir(dirname, dirname + '.input_stdout')
				MultiThreadedChecker.check_later(dirname, (i, j))

		for j in range(0, replayer.dops_len(i)):
			replayer.dops_include((i, j))

	checker_outputs = MultiThreadedChecker.wait_and_get_outputs()
	staticvuls = set()
	for i in range(0, replayer.mops_len()):
		for j in range(i + 1, replayer.mops_len()):
			if (i, j) in checker_outputs and checker_outputs[(i, j)] != 0:
				print '(Dynamic vulnerability) Ordering: ' + \
					'Operation ' + str(i) + ' needs to be persisted before ' + str(j)
				staticvuls.add((stack_repr(replayer.get_op(i)),
					stack_repr(replayer.get_op(j))))
				break

	for vul in staticvuls:
		print '(Static vulnerability) Ordering: ' + \
			'Operation ' + vul[0] + ' needed before ' + vul[1]

	# Finding atomicity vulnerabilities
	replayer.load(0)
	MultiThreadedChecker.reset()
	atomicity_explanations = dict()

	for mode in (('count', 1), ('count', 3), ('aligned', 4096)):
		replayer.set_fs(defaultfs(*mode))
		for i in range(0, replayer.mops_len()):
			if i in atomic_patch_middle or (i - 1) in atomic_patch_middle:
				continue

			for j in range(0, replayer.dops_len(i) - 1):
				replayer.dops_end_at((i, j))
				if replayer.is_legal():
					dirname = os.path.join(aliceconfig().scratchpad_dir, 'reconstructeddir-' + mode[0] + '-' + str(mode[1]) + '-' + str(i) + '-' + str(j))
					replayer.construct_crashed_dir(dirname, dirname + '.input_stdout')
					MultiThreadedChecker.check_later(dirname, (mode, i, j))
					atomicity_explanations[(mode, i, j)] = replayer.get_op(i).hidden_disk_ops[j].atomicity

				if mode != ('aligned', '4096'): # Do not do this for the 4096 aligned case, since a large write might contain a huge number of diskops
					for k in range(0, j):
						replayer.dops_omit((i, k))
						if replayer.is_legal():
							dirname = os.path.join(aliceconfig().scratchpad_dir, 'reconstructeddir-' + mode[0] + '-' + str(mode[1]) + '-' + str(i) + '-' + str(j) + '-' + str(k))
							replayer.construct_crashed_dir(dirname, dirname + '.input_stdout')
							MultiThreadedChecker.check_later(dirname, (mode, i, j, k))
						replayer.dops_include((i, k))


	checker_outputs = MultiThreadedChecker.wait_and_get_outputs()
	staticvuls = collections.defaultdict(lambda:set())
	for i in range(0, replayer.mops_len()):
		dynamicvuls = set()
		for j in range(0, replayer.dops_len(i) - 1):
			for mode in (('count', 1), ('count', 3), ('aligned', 4096)):
				if (mode, i, j) in checker_outputs and checker_outputs[(mode, i, j)] != 0:
					dynamicvuls.add(atomicity_explanations[(mode, i, j)])

		if len(dynamicvuls) == 0:
			for j in range(0, replayer.dops_len(i) - 1):
				for mode in (('count', 1), ('count', 3), ('aligned', 4096)):
					for k in range(0, j):
						if (mode, i, j, k) in checker_outputs and checker_outputs[(mode, i, j, k)] != 0:
							dynamicvuls.add('???')
					

		if len(dynamicvuls) > 0:
			print '(Dynamic vulnerability) Atomicity: ' + \
				'Operation ' + str(i) + '(' + (', '.join(dynamicvuls)) + ')'
			staticvuls[stack_repr(replayer.get_op(i))].update(dynamicvuls)

	for vul in staticvuls:
		print '(Static vulnerability) Atomicity: ' + \
			'Operation ' + vul + ' (' + (','.join(staticvuls[vul])) + ')'

	print 'Done finding vulnerabilities.'
