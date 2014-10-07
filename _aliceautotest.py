#!/usr/bin/python2.7

import argparse
import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + '/upstream_dependencies/'))
import BitVector
from collections import defaultdict
import itertools
import pickle
import pprint
from sets import Set

# I use system call and operation interchangeably in the script. Both are used
# to denote something like fsync(3) or write(4,"hello", 5) in the input trace
# file.

# TODO: Change script to work correctly with multiple threads. Right now script
# parses thread value, but doesn't really use that value anywhere.

# Parse input arguments. 
parser = argparse.ArgumentParser()
parser.add_argument('--op_file', dest = 'op_file', type = str, default = False)
parser.add_argument("-b","--brute_force_verify", help="Verify combinations via\
                    brute force", 
                    action="store_true")
parser.add_argument("-p","--print_dependencies", help="Print dependencies", 
                    action="store_true")
parser.add_argument("-v","--verbose", help="Print dependency calculations.", 
                    action="store_true")
parser.add_argument("-vv","--very_verbose", help="Print internal re-ordering calculations.", 
                    action="store_true")
#args = parser.parse_args()

# This causes problems on my mac. Keeping for Thanu's repo.
if __name__ == '__main__':
	args = parser.parse_args()
else:
	args = parser.parse_args([])

if args.very_verbose:
    args.verbose = True

# The list of syscalls we are interested in.
# Interesting parameters.
# write:    offset, count
# sync:     offset, count
# truncate: initial_size, final_size  
calls_of_interest = ["write", "sync", "delete_dir_entry", "create_dir_entry", "truncate"]
# The list of syscalls treated as ordering points.
# Sync parameters.
# Offset, count (bytes)
# fsync: offset = 0, count = full size of file.
ordering_calls = ["sync"]
# Metadata calls.
metadata_calls = ["create_dir_entry", "delete_dir_entry"]

# Set of all current dirty writes for a file.
dirty_write_ops = defaultdict(set) 
dirty_write_ops_inode = defaultdict(set)

# Latest global fsync (on any file).
latest_fsync_on_any_file = None 

# Map inodes to filenames (one inode can map to many names) and filenames to
# inode,
inode_to_filenames = defaultdict(set)
filename_to_inode = {} 

# Test whether the first path is a parent of the second.
def is_parent(path_a, path_b):
    return path_b.startswith(path_a)

# Class to encapsulate operation details.
class Operation:

    # All the setup
    def __init__(self, micro_op, micro_op_id):
        global inode_to_filenames
        global filename_to_inode

        #print(micro_op)
        self.syscall = micro_op.op 
        self.micro_op = micro_op
        # Set of ops that depend on this op: dropping this op means dropping those ops
        # also.
        self.inode = micro_op.inode
        self.total_num_combos = 0
        # Get the filename for metadata calls. 
        if micro_op.op in metadata_calls:  
            if micro_op.op in ["create_dir_entry", "delete_dir_entry"]:
                self.parent = micro_op.parent
            self.filename = micro_op.entry
            # Set up the maps
            filename_to_inode[self.filename] = self.inode
            inode_to_filenames[self.inode].add(self.filename)
        else:
            # Need to consult the map to get the filename.
            # Note that an inode can be mapped to many names. We just get the
            # first name in the list. It shouldn't matter for most operations.
            for x in inode_to_filenames[self.inode]:
                #print("setting filename to " + x) 
                self.filename = x
                break
        # Set offset and count for certain system calls.
        if micro_op.op in ["write", "sync"]:
            self.offset = micro_op.offset
            self.count  = micro_op.count
        if micro_op.op in ["truncate"]:
            self.final_size = micro_op.final_size

        # The file specific ID for each inode 
        op_index = (self.inode, self.syscall)
        self.micro_op_id = micro_op_id
        # The set of ops that this is dependent on.
        self.deps = Set()
        # Update dirty write collection if required.
        self.update_dirty_write_collection()
        # Finally, calculate dependencies
        self.calculate_dependencies()
        # Clear write dependencies if required.
        self.clear_dirty_write_collection()

    # Check if this operation falls into a sync range.
    def is_included_in_sync_range(self, offset, count):
        start = offset
        end = start + count

        if self.syscall == "write":
            write_start = self.offset
            write_end = self.offset + self.count
            if write_start >= start and write_end <= end:
                return True

        if self.syscall == "truncate":
            if self.final_size >= start and self.final_size <= end:
                return True

	if self.syscall in ["create_dir_entry", "delete_dir_entry"]:
		return True

        return False 

    # This updates the dirty write collection.
    def update_dirty_write_collection(self):
        global dirty_write_ops
        global dirty_write_ops_inode
        if self.syscall in ["write", "truncate"]:
            dirty_write_ops_inode[self.inode].add(self)
        # If this is a create/dir operation, the operation is actually on the
        # parent inode.
        if self.syscall in ["create_dir_entry", "delete_dir_entry"]:
            dirty_write_ops_inode[self.parent].add(self)
        
    # Clears dirty write collection on fsync.
    # TODO: handle file_sync_range correctly. Currently treating as 
    # the same as fdatasync. 
    def clear_dirty_write_collection(self):
        global dirty_write_ops
        global dirty_write_ops_inode
        global latest_fsync_on_any_file
        if self.syscall in ["sync"]: 
            # Remove the dirty writes which will be flushed by this sync.
            set_of_dops_to_remove = set() 
            for dop in dirty_write_ops_inode[self.inode]:
                if dop.is_included_in_sync_range(self.offset, self.count):
                    set_of_dops_to_remove.add(dop)

            for dop in set_of_dops_to_remove:
                dirty_write_ops_inode[self.inode].remove(dop) 

            latest_fsync_on_any_file = self

    # This method returns a nice short representation of the operation. This
    # needs to be updated as we support new operations. See design doc for what
    # the representation is.
    def get_short_string(self):
        rstr = ""
        if self.syscall == "write":
            rstr += "W"
        elif self.syscall == "create_dir_entry":
            rstr += "L"
        elif self.syscall == "delete_dir_entry":
            rstr += "U"
        elif self.syscall in ["sync"]: 
            rstr += "F"
        elif self.syscall == "truncate":
            rstr += "T"

        rstr += str(self.micro_op_id)
        if self.syscall in ["create_dir_entry"]:
            rstr += "(p= " + str(self.parent) + ", " + self.filename + ", c=" + str(self.inode)
        elif self.syscall in ["delete_dir_entry"]:
            rstr += "(p= " + str(self.parent) + ", " + self.filename + ", c=" + str(self.inode)
        else:        
            rstr += "(" + str(self.inode)

        rstr += ")"
        return rstr

    # This method calculates the existential dependencies of an operation:
    # basically, we can only include this operation in an combination if one of
    # the conditions for this operation evaluates to true. 
    def calculate_dependencies(self):
    
        # If this is an fsync, then it depends on all the dirty writes to this
        # file previously, which fall within the sync range.
        if self.syscall in ["sync"]:
            for wop in dirty_write_ops_inode[self.inode]:
                if wop.is_included_in_sync_range(self.offset, self.count):
                    self.deps = self.deps | wop.deps
                    self.deps.add(wop)

        # The fsync dependency.
        # Each operation on a file depends on the last fsync to the file. The
        # reasoning is that this operation could not have happened without that
        # fsync happening.
        # CLARIFY: does the op depend on the last fsync *on the same file* or
        # just the last fsync (on any file) in the thread?
       # fsync: offset = 0, count = full size of file.
        if latest_fsync_on_any_file:
            self.deps = self.deps | latest_fsync_on_any_file.deps
            self.deps.add(latest_fsync_on_any_file)

    # Store the notation of dependencies as a bit vector.
    def store_deps_as_bit_vector(self, total_len):            
        self.deps_vector = BitVector.BitVector(size = total_len)
        # Set the relevant bits
        for x in self.deps:
            self.deps_vector[x.micro_op_id] = 1

    # Add a dependecy to the operation.
    def add_dep(self, op):
        self.deps = self.deps | op.deps
        self.deps.add(op)

def test_validity(op_list):
    valid = True
    # Dependence check
    op_set = Set(op_list)
    for op in op_list:
        if not op.deps <= op_set:
            return False
    return True

# Print the whole thing on one line instead of as a list.
def print_op_string(op_combo):
    str = ""
    for x in op_combo:
        str += x.get_short_string() + " "
    print(str)

# The brute force method.
def try_all_combos(op_list, limit = None, limit_tested = 10000000):
    ans_list = []
    clist = op_list[:]
    total_size = len(op_list) 
    set_count = 0
    o_count = 0
    for i in range(1, total_size + 1):
        for op_combo in itertools.combinations(op_list, i):
            o_count += 1
            assert(o_count <= limit_tested)
            if limit != None and set_count >= limit:
                return ans_list
            if test_validity(op_combo):
                mop_list = []
                for xx in op_combo:
                    mop_list.append(xx.micro_op)
                #ans_list.append(mop_list)
                ans_list.append(op_combo)
                set_count += 1
    return get_micro_ops_set(ans_list)

# Globals for combo generation.
generated_combos = set()
max_combo_limit = None
max_combos_tested = 10000000
num_recursive_calls = 0

def get_micro_ops_set(vijayops_set):
    return [[x.micro_op for x in combo] for combo in vijayops_set]

# Class to contain all the test class suites.
class ALCTestSuite:
    # Load it up with a list of micro ops 
    def __init__(self, micro_op_list):
        global dirty_write_ops, dirty_write_ops_inode
        global latest_fsync_on_any_file, inode_to_filenames, filename_to_inode

        # Reset all the global things
        dirty_write_ops = defaultdict(set) 
        dirty_write_ops_inode = defaultdict(set)
        latest_fsync_on_any_file = None 
        inode_to_filenames = defaultdict(set)
        filename_to_inode = {} 

        self.op_list = [] 
        self.generated_combos = set()
        self.max_combo_limit = None
        self.max_combos_tested = 10000000
        self.num_recursive_calls = 0
        self.total_len = 0
        self.id_to_micro_op_map = {}

        for micro_op in micro_op_list:
            #print(micro_op)
            assert(micro_op.op in calls_of_interest)
            x = Operation(micro_op, len(self.op_list))
            self.id_to_micro_op_map[len(self.op_list)] = x
            self.op_list.append(x)

        self.total_len = len(self.op_list)

        # Store the dependencies as bit vectors.
        for op in self.op_list:
            op.store_deps_as_bit_vector(self.total_len)

    # == External ==
    # Test if this combo is valid. Combo is specified using the id numbers of
    # the operations in the combo.
    # 
    # Input: combo ids (set or list of operation ids)
    # Output: Boolean as to whether this is a valid combo. 
    def test_combo_validity(self, combo):
        combo_to_test = []
        for op_id in combo:
            combo_to_test.append(self.id_to_micro_op_map[op_id])
        validity = test_validity(combo_to_test)
        return validity

    # The recursive function that calculates all the combos.
    # The op_list is treated as a global constant.
    # Each invocation of the function has the prefix (0 to n-1) that has been
    # processed plus the ops that have been dropped in that prefix.
    def generate_combos(self, start, end, drop_set):
        # Check limits
        self.num_recursive_calls += 1
        assert(self.num_recursive_calls <= self.max_combos_tested)
        # Return if we have enough combos.
        if self.max_combo_limit and len(self.generated_combos) >= self.max_combo_limit:
            return

        # Create the combo set.
        op_set_so_far = Set(self.op_list[start:(end+1)]) - drop_set
        op_set_so_far = sorted(op_set_so_far, key=lambda Operation:
                               Operation.micro_op_id)
        if len(op_set_so_far):
            self.generated_combos.add(tuple(op_set_so_far))

        # Return if we are at the end of the op_list.
        if end == (self.total_len - 1):
            return

        # Build up a local drop_set
        local_drop_set = drop_set.copy()

        # Look for candidates beyond the end position.
        for i in range(end + 1, self.total_len):
            if len(self.op_list[i].deps & local_drop_set) == 0:
                # Can be included
                self.generate_combos(start, i, local_drop_set)
                # Add this op to the local drop set for the next iteration.
                local_drop_set.add(self.op_list[i])

    # The recursive function that calculates the total number of combos.
    # The op_list is treated as a global constant.
    # Each invocation of the function has the prefix (0 to n-1) that has been
    # processed plus the ops that have been dropped in that prefix.
    def count_combos(self, start, end, drop_vector):
        if end >= start:
            self.total_num_combos += 1

        # Return if we are at the end of the op_list.
        if end == (self.total_len - 1):
            return

        # Build up a local drop_set
        local_drop_vector = drop_vector.deep_copy()

        # Look for candidates beyond the end position.
        for i in range(end + 1, self.total_len):
            if (self.op_list[i].deps_vector & local_drop_vector).count_bits_sparse() == 0:
                # Can be included
                self.count_combos(start, i, local_drop_vector)
                # Add this op to the local drop vector for the next iteration.
                local_drop_vector[i] = 1

    # == External ==
    # Get all the combos.  
    # 
    # Input: maximum number of combos to be returned (limit) and tested (limit_tested) 
    # Output: list of items - each item is a combo (array of micro ops)
    def get_combos(self, limit = None, limit_tested = 10000000):
        # Set limits
        self.max_combo_limit = limit
        self.max_combos_tested = limit_tested
        self.num_recursive_calls = 0

        # Generate all the combos
        self.total_len = len(self.op_list)
        self.generate_combos(0, -1, Set())

        # If we want to debug, return the op list (not micro ops)
        if args.very_verbose:
            return self.generated_combos
        else:
            return get_micro_ops_set(self.generated_combos)

    # == External ==
    # Return the number of combos.  
    # 
    # Input: maximum number of combos to be returned (limit) and tested (limit_tested) 
    # Output: Number of combos possible for given disk op set with given
    # constraints.
    def count_all_combos(self):
        self.total_len = len(self.op_list)
        self.total_num_combos = 0
        bv = BitVector.BitVector(size = self.total_len)
        self.count_combos(0, -1, bv)
        return self.total_num_combos 

    # == External ==
    # Drop a list of operations from the combination. This can result in
    # needing to drop more operations (which depended on the operations we just
    # dropped). 
    # 
    # Input: list of operation ids to drop 
    # Output: list of micro-ops that result after dropping the input list.
    def drop_list_of_ops(self, op_id_list):
        op_set = Set(self.op_list) 
        drop_set = Set()
        for op_id in op_id_list:
            # Drop op and its dep
            drop_op = self.id_to_micro_op_map[op_id]
            drop_set.add(drop_op)
        # Recurse until no new ops are added to drop_set.
        prevlen = len(drop_set)
        droplen = 0
        while droplen != prevlen:
            prevlen = len(drop_set)
            for op in op_set:
                if op.deps & drop_set:
                    drop_set.add(op)
            droplen = len(drop_set)
        new_op_set = op_set - drop_set
        # assert(test_validity(new_op_set))
        # Return as micro op list
        return [x.micro_op_id for x in new_op_set] 

    # == External ==
    # Keep a list of operations in the combination. This can result in needing
    # to keep all their dependencies.
    # 
    # Input: list of operation ids to keep
    # Output: list of micro-ops that are needed to keep the input list.
    def keep_list_of_ops(self, op_id_list):
        op_set = Set(self.op_list) 
        keep_set = Set()
        for op_id in op_id_list:
            # Drop op and its dep
            keep_op = self.id_to_micro_op_map[op_id]
            keep_set.add(keep_op)
        # Get all the deps of all the ops in the keep set. 
        dep_set = Set()
        for op in keep_set:
            dep_set = dep_set | op.deps
        keep_set = keep_set | dep_set
        assert(test_validity(keep_set))
        # Return as micro op list
        return [x.micro_op_id for x in keep_set] 

    # Pretty print an op list with the representation for each operation.
    def print_op_list(self):
        for op in self.op_list:
            print(op.get_short_string())

    # Print deps.
    def print_deps(self):
        for op in self.op_list:
            print(op.get_short_string() + "depends on:")
            print_op_string(op.deps)

    # == External ==
    #
    # Add a list of dependencies to the list already computed.
    # 
    # Input: list of tuples. Each tuple (X, Y) indicates that X should now
    # depend on Y. To include X in a combo, you also need Y. 
    # X and Y are op ids. 
    # Output: None. 
    def add_deps_to_ops(self, dep_list):
        dep_list = sorted(dep_list)
        for dep_tuple in dep_list:
            x_id = dep_tuple[0]
            y_id = dep_tuple[1]
            x_op = self.id_to_micro_op_map[x_id]
            y_op = self.id_to_micro_op_map[y_id]
            x_op.add_dep(y_op)

        # Recompute all the dependencies and bit vectors.
        for op in self.op_list:
            for dep_op in op.deps:
                op.deps = op.deps | dep_op.deps
            op.store_deps_as_bit_vector(self.total_len)

# Driver main showing how the code is meant to be used.
if __name__ == '__main__':
    micro_op_list = pickle.load(open(args.op_file, 'r'))

    testSuite = ALCTestSuite(micro_op_list) 
    combos = testSuite.get_combos(5000)
    print("Number of combos: " + str(len(combos)))

    # Alternatively, you can just get the number of combos directly. 
    # This doesn't generate all the sets, and is much faster.
    # print("Number of combos: " + str(testSuite.count_all_combos()))

    if args.very_verbose:
        for x in combos:
            print_op_string(x)

    # Test case of how to use test_combo_validity
    combo_list = [1, 2, 51]
    print(testSuite.test_combo_validity(combo_list))
    combo_list = [1, 2, 3]
    print(testSuite.test_combo_validity(combo_list))

    # Testing out the drop list functionality for single item list.
    for i in range(0, len(testSuite.op_list)):
        op_id_list = []
        op_id_list.append(i)
        result_set = testSuite.drop_list_of_ops(op_id_list)
        print(str(i) + ": " + str(len(result_set)))

    # Test for random combos. 
    op_id_list = []
    op_id_list.append(2)
    op_id_list.append(5)
    op_id_list.append(40)
    result_set = testSuite.drop_list_of_ops(op_id_list)
    print("Drop list answer: " + str(len(result_set)))

    # Testing out the keep list functionality for single item list.
    for i in range(0, len(testSuite.op_list)):
        op_id_list = []
        op_id_list.append(i)
        result_set = testSuite.keep_list_of_ops(op_id_list)
        print(str(i) + ": " + str(len(result_set)))

    # Testing keep list functionality.
    op_id_list = []
    op_id_list.append(2)
    op_id_list.append(5)
    op_id_list.append(40)
    result_set = testSuite.keep_list_of_ops(op_id_list)
    print("Keep list answer: " + str(len(result_set)))

    # Testing adding lots of dependencies and seeing if it reduces the number
    # of combos.
    testSuite2 = ALCTestSuite(micro_op_list[:10]) 
    before_combo = testSuite2.count_all_combos()
    list_of_deps = []
    for i in range(0, 8):
        list_of_deps.append((9, i))
        list_of_deps.append((8, i))
    testSuite2.add_deps_to_ops(list_of_deps)
    after_combo = testSuite2.count_all_combos()
    print(before_combo, after_combo)

    # Print out the list of operations
    if args.very_verbose:
        print("List of operations:")
        testSuite.print_op_list()

    if args.print_dependencies or args.very_verbose:
        testSuite.print_deps()

    if args.brute_force_verify:
        all_combos = try_all_combos(op_list) 
        mismatch_flag = False
        print("Mis-matches:")
        for x in combos:
            if x not in all_combos:
                print_op_string(x)
                mismatch_flag = True
          
            if not mismatch_flag:
                print("Perfect Match!")
