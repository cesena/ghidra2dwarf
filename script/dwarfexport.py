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
curr = getCurrentProgram()

ext_c = lambda s: s + ".c"
ext_dbg = lambda s: s + ".dbg"


class Info:
    def __init__(self):
        self.elf = 0
        self.mode = 8
        self.dbg = PointerByReference()
        self.err = PointerByReference()
        dwarf_producer_init(
            DW_DLC_WRITE
            | DW_DLC_SYMBOLIC_RELOCATIONS
            | DW_DLC_POINTER64
            | DW_DLC_OFFSET32
            | DW_DLC_TARGET_LITTLEENDIAN,
            lambda x: 0,
            None,
            None,
            None,
            "x86_64",
            "V2",
            None,
            self.dbg,
            self.err,
        )
        self.dbg = Dwarf_P_Debug(self.dbg.value)


class Options:
    def __init__(
        self, use_dec=False, only_dec_nam_fun=False, att_deb_inf=False, verbose=False
    ):
        self.use_decompiler = use_dec
        self.only_decompile_named_funcs = only_dec_nam_fun
        self.attach_debug_info = att_deb_inf
        self.verbose = verbose
        self.filepath = ""
        self.filename = ""
        self.dwarf_source_path = ""
        self.export_options = 0


def add_debug_info(info):
    dbg = info.dbg
    err = info.err
    dwarf_pro_set_default_string_form(dbg, DW_FORM_string, err)
    cu = dwarf_new_die(dbg, DW_TAG_compile_unit, None, None, None, None, err)
    print cu
    dwarf_add_AT_name(cu, ext_c(curr.name), info.err)
    dir_index = dwarf_add_directory_decl(dbg, ext_dbg(curr.name), err)
    file_index = dwarf_add_file_decl(dbg, ext_c(curr.name), dir_index, 0, 0, err)
    print dir_index
    print file_index
    dwarf_add_AT_comp_dir(cu, ext_dbg(curr.name), err)
    # memory = curr.getMemory()
    # Get sections
    # memory.getBlocks()

    # Get segments
    # memory.getLoadedAndInitializedAddressSet()

    # Get executable segments
    # list(memory.getExecuteSet().getAddressRanges())

    # However we can omit this step and directly decompile all functions

    ifc = DecompInterface()
    ifc.openProgram(curr)
    fm = curr.getFunctionManager()
    funcs = fm.getFunctions(True)
    for f in funcs:
        add_function(info, cu, f, 1, file_index)
        pass
        # add_function()
        # results = ifc.decompileFunction(f, 0, ConsoleTaskMonitor())
        # print (results.getDecompiledFunction().getC())


def add_function(info, cu, func, linecount, file_index):
    dbg = info.dbg
    err = info.err
    die = dwarf_new_die(dbg, DW_TAG_subprogram, cu, None, None, None, err)
    loc_expr = dwarf_new_expr(dbg, err)
    # I don't know if it is linecount - 1 or what
    if dwarf_add_expr_gen(loc_expr, DW_OP_call_frame_cfa, 0, 0, err) == linecount - 1:
        print "error"


g = globals()
for i in LibdwarfLibrary.__dict__.keys():
    g[i] = getattr(l, i)

print DW_DLE_DWARF_INIT_DBG_NULL
print DW_DLE_HEX_STRING_ERROR

info = Info()
option = Options(use_dec=True)
add_debug_info(info)

"""
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
"""
