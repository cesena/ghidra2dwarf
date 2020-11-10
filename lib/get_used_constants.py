# find all the constants used inside ghidra2dwarf.py and output the matching java constants from LibdwarfLibrary.java.old

import re

script = open('../src/ghidra2dwarf.py', 'r').read()
javalib = open('LibdwarfLibrary_jnarated.java', 'r').read()

BLACKLIST = {'DW_OP_breg'}
FORCE_ADD = {r'DW_OP_breg\d+'}
constants = set(re.findall(r'DW_\w+', script)) - BLACKLIST | FORCE_ADD
if 'DW_FRAME_LAST_REG_NUM' in constants:
	constants.add('DW_FRAME_HIGHEST_NORMAL_REGISTER')

l = []
for c in sorted(constants):
	lines = re.findall(r'public static final \w+ %s = .+;' % c, javalib)
	if not lines:
		assert False, '%s not found' % c
	l.extend(lines)

print('\n'.join(l))