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

import re
from _aliceutils import *

__author__ = "Thanumalayan Sankaranarayana Pillai"
__copyright__ = "Copyright 2014, Thanumalayan Sankaranarayana Pillai"
__credits__ = ["Thanumalayan Sankaranarayana Pillai", "Vijay Chidambaram",
	"Ramnatthan Alagappan", "Samer Al-Kiswany"]
__license__ = "MIT"

class Struct:
	TYPE_DIR = 0
	TYPE_FILE = 1
	def __init__(self, **entries): self.__dict__.update(entries)
	def update(self, mydict): self.__dict__.update(mydict)
	def __repr__(self):
		if 'op' in vars(self):
			if self.op == 'stdout':
				args = ['"' + repr(self.data) + '"']
			elif self.op in ['write', 'append']:
				args = ['%s=%s' % (k, repr(vars(self)[k])) for k in ['offset', 'count', 'inode']]
			else:
				argsbegin = []
				argsend = []
				for (k,v) in vars(self).items():
					if k != 'op' and k != 'name' and k[0:7] != 'hidden_':
						if k == 'source' or k == 'dest':
							argsbegin.append('%s="%s"' % (k, coded_colorize(short_path(v))))
						else:
							argsend.append('%s=%s' % (k, repr(v)))
				args = argsbegin + argsend
			if 'name' in vars(self):
				args.insert(0, '"' + coded_colorize(short_path(self.name)) + '"')
			colored_op = self.op
			if self.op.find('sync') != -1:
				colored_op = colorize(self.op, 1)
			elif self.op == 'stdout':
				colored_op = colorize(self.op, 2)
			return '%s(%s)' % (colored_op, ', '.join(args))
	        args = ['%s=%s' % (k, repr(v)) for (k,v) in vars(self).items() if k[0:7] != 'hidden_']
	        return 'Struct(%s)' % ', '.join(args)
	def superficial_eq(self, other):
		if type(self) != type(other):
			return False
		# return str(self.__dict__) == str(other.__dict__)
		for k in self.__dict__:
			if not type(self.__dict__[k]) == type(self) and type(self.__dict__[k]) != list and type(self.__dict__[k]) != set:
				if k not in other.__dict__:
					return False
				if self.__dict__[k] != other.__dict__[k]:
					return False
		return True
	def __eq__(self, other):
		if type(self) != type(other):
			return False
		# return str(self.__dict__) == str(other.__dict__)
		for k in self.__dict__:
			if k not in other.__dict__:
				return False
			if not type(self.__dict__[k]) == type(self):
				if self.__dict__[k] != other.__dict__[k]:
					return False
			else:
				if not self.__dict__[k].superficial_eq(other.__dict__[k]):
					return False
		return True
		# return self.__dict__ == other.__dict__
	def __ne__(self, other):
		return not self.__eq__(other)
	def __hash__(self):
		return hash(str(self.__dict__))

