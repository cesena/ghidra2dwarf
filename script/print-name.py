# Add symbols to ELF file
# @author meowmeowxw
# @category _NEW_
# @keybinding
# @menupath
# @toolbar

try:
    from ghidra_builtins import *
except:
    pass

from ghidra.program.disassemble import *

curr = currentProgram

print curr.name

