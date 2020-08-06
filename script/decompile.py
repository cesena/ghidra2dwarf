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


from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

## let addr be a valid Address
curr = getCurrentProgram()

ifc = DecompInterface()
ifc.openProgram(curr)
fm = curr.getFunctionManager()
funcs = fm.getFunctions(True)  # True means 'forward'

# decompile the function and print the pseudo C
for f in funcs:
    results = ifc.decompileFunction(f, 0, ConsoleTaskMonitor())
    print(results.getDecompiledFunction().getC())
