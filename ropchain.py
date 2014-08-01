#!/usr/bin/env python 

from capstone import *
import sys

print "Enter binary file name: ",
data = sys.stdin.readline().rstrip('\n')

md = Cs(CS_ARCH_X86, CS_MODE_32)
with open(data, 'rb') as content_file:
    content = content_file.read()
    for i in md.disasm(content, 0x08048000):
	print "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)


