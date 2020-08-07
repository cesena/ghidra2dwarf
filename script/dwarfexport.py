# Ghidra2Dwarf
# @author sen, meowmeowxw
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
from ghidra.app.util.bin.format.elf import ElfSymbolTable

from libdwarf import LibdwarfLibrary
from com.sun.jna.ptr import PointerByReference

l = LibdwarfLibrary.INSTANCE

g = globals()
for i in LibdwarfLibrary.__dict__.keys():
    g[i] = getattr(l, i)

print DW_DLE_DWARF_INIT_DBG_NULL
print DW_DLE_HEX_STRING_ERROR

d = Dwarf_P_Debug()
r1 = PointerByReference(d.pointer)
r2 = PointerByReference()

DW_TAG_compile_unit = 0x11

dwarf_producer_init(DW_DLC_WRITE | DW_DLC_SYMBOLIC_RELOCATIONS | DW_DLC_POINTER64 | DW_DLC_OFFSET32 | DW_DLC_TARGET_LITTLEENDIAN, lambda x: 0, None, None, None, "x86_64", "V2", None, r1, r2)

cu = dwarf_new_die(
    d, DW_TAG_compile_unit, None, None, None, None, r2
)
print cu

# dwarf_add_AT_name(cu, , r2)

# if (dwarf_add_AT_name(die, &name[0], &err) == NULL) {

