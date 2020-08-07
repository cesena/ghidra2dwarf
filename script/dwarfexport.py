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
from com.sun.jna import Pointer
from com.sun.jna import Memory
from java.nio import ByteBuffer

l = LibdwarfLibrary.INSTANCE

g = globals()
for i in LibdwarfLibrary.__dict__.keys():
    g[i] = getattr(l, i)

print DW_DLE_DWARF_INIT_DBG_NULL
print DW_DLE_HEX_STRING_ERROR

dbg_ref = PointerByReference()
err_ref = PointerByReference()

dwarf_producer_init(DW_DLC_WRITE | DW_DLC_SYMBOLIC_RELOCATIONS | DW_DLC_POINTER64 | DW_DLC_OFFSET32 | DW_DLC_TARGET_LITTLEENDIAN, lambda x: 0, None, None, None, "x86_64", "V2", None, dbg_ref, err_ref)

dbg = Dwarf_P_Debug(dbg_ref.value)

dwarf_pro_set_default_string_form(dbg, DW_FORM_string, err_ref);

cu = dwarf_new_die(
    dbg, DW_TAG_compile_unit, None, None, None, None, err_ref
)
print cu

dwarf_add_AT_name(cu, "kek", err_ref)
