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

from sys import stderr


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


def add_debug_info():
    dwarf_pro_set_default_string_form(dbg, DW_FORM_string, err)
    cu = dwarf_new_die(dbg, DW_TAG_compile_unit, None, None, None, None, err)
    print cu
    if options.use_decompiler:
        if dwarf_add_AT_name(cu, ext_c(curr.name), err) == None:
            stderr.write("dwarf_add_AT_name error")
        dir_index = dwarf_add_directory_decl(dbg, ext_dbg(curr.name), err)
        file_index = dwarf_add_file_decl(dbg, ext_c(curr.name), dir_index, 0, 0, err)
        dwarf_add_AT_comp_dir(cu, ext_dbg(curr.name), err)
    # memory = curr.getMemory()
    # Get sections
    # memory.getBlocks()

    # Get segments
    # memory.getLoadedAndInitializedAddressSet()

    # Get executable segments
    # list(memory.getExecuteSet().getAddressRanges())

    # However we can omit this step and directly decompile all functions

    linecount = 1
    ifc = DecompInterface()
    ifc.openProgram(curr)
    fm = curr.getFunctionManager()
    funcs = fm.getFunctions(True)
    for f in funcs:
        add_function(cu, f, linecount, file_index)
        pass
        # add_function()
        # results = ifc.decompileFunction(f, 0, ConsoleTaskMonitor())
        # print (results.getDecompiledFunction().getC())


def add_function(cu, func, linecount, file_index):
    die = dwarf_new_die(dbg, DW_TAG_subprogram, cu, None, None, None, err)
    if die == None:
        stderr.write("dwarf_new_die error")
    loc_expr = dwarf_new_expr(dbg, err)
    # I don't know if it is linecount - 1 or what
    if dwarf_add_expr_gen(loc_expr, DW_OP_call_frame_cfa, 0, 0, err) == linecount - 1:
        stderr.write("dwarf_add_expr_gen error")
    if dwarf_add_AT_location_expr(dbg, die, DW_AT_frame_base, loc_expr, err) == None:
        stderr.write("dwarf_add_AT_location_expr error")
    # TODO: Understand difference between c_name and mangled_name
    f_name = func.name
    print f_name
    if dwarf_add_AT_name(die, f_name, err) == None:
        stderr.write("dwarf_add_AT_name error")
    # if dwarf_add_AT_string(dbg, die, DW_AT_linkage_name, f_name, err) == None:
    #     stderr.write("dwarf_add_AT_string error")


ext_c = lambda s: s + ".c"
ext_dbg = lambda s: s + ".dbg"

l = LibdwarfLibrary.INSTANCE
curr = getCurrentProgram()
g = globals()
for i in LibdwarfLibrary.__dict__.keys():
    g[i] = getattr(l, i)

print DW_DLE_DWARF_INIT_DBG_NULL
print DW_DLE_HEX_STRING_ERROR

dbg = PointerByReference()
err = PointerByReference()
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
    dbg,
    err,
)
dbg = Dwarf_P_Debug(dbg.value)
options = Options(use_dec=True)
add_debug_info()

