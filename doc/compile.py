#!/usr/bin/env python
import os
import re
import sys

if len(sys.argv) > 1 and sys.argv[1] == 'clean':
	os.system('rm doc.4ct doc.4tc doc.aux doc.css doc.dvi doc.html doc.idv doc.lg doc.log doc.out doc.pdf doc.tmp doc.xref')
	exit(0)
	
os.system('mk4ht htlatex doc.tex doc.cfg')
os.system('pdflatex doc')
html = open('doc.html').read()
m = re.search(r'<[ \t\r\n]*body[ \t\r\n]*>', html)
html = html[0:m.end(0)] + '<table border="0" cellspacing="0" cellpadding="0" style="text-align: justify; margin-left: auto; margin-right: auto;" width="70%"><tbody><tr><td>' + html[m.end(0):]
m = re.search(r'</[ \t\r\n]*body[ \t\r\n]*>', html)
html = html[0:m.start(0)] + '</td></tr></tbody></table>' + html[m.start(0):]
open('doc.html', 'w').write(html)

os.system('pandoc doc.html -o doc.md')
md = open('doc.md').read()
m = re.search(r'\.\n  ~', md)
while m != None:
	md = md[0:m.start(0)] + '.' + md[m.end(0):]
	m = re.search(r'\.\n  ~', md)
m = re.search(r'## Chapter.*\\\n', md)
while m != None:
	md = md[0:m.end(0) - 2] + ': ' + md[m.end(0):]
	m = re.search(r'## Chapter.*\\\n', md)
for i in range(0, len(md) - 1):
	if i >= len(md) - 1:
		break
	if md[i] == '\\' and md[i + 1] != '\\':
		md = md[0:i] + md[i+1:]
open('doc.md', 'w').write(md)

os.system('mv doc.md ../README.md')
