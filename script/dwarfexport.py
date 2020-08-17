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


from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.app.util.bin.format.elf import ElfSymbolTable
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.database.data import PointerDB
from ghidra.program.model.data import Pointer, Structure, DefaultDataType, BuiltInDataType
from ghidra.app.util.bin.format.dwarf4.next import DWARFRegisterMappingsManager


from libdwarf import LibdwarfLibrary
from com.sun.jna.ptr import PointerByReference, LongByReference
from com.sun.jna import Memory
from java.nio import ByteBuffer

from sys import stderr
import os.path
import tempfile


class Options:
    def __init__(self, use_dec=False, only_dec_nam_fun=False, att_deb_inf=False, verbose=False):
        self.use_decompiler = use_dec
        self.only_decompile_named_funcs = only_dec_nam_fun
        self.attach_debug_info = att_deb_inf
        self.verbose = verbose
        self.filepath = ""
        self.filename = ""
        self.dwarf_source_path = ""
        self.export_options = 0


def get_libdwarf_err():
    derr = Dwarf_Error(err.value)
    return dwarf_errmsg(derr)

def DERROR(func):
    assert False, "%s failed: %s" % (func, get_libdwarf_err())


def add_debug_info():
    dwarf_pro_set_default_string_form(dbg, DW_FORM_string, err)
    cu = dwarf_new_die(dbg, DW_TAG_compile_unit, None, None, None, None, err)
    path, _ = os.path.split(curr.executablePath)
    if options.use_decompiler:
        if dwarf_add_AT_name(cu, ext_c(curr.name), err) is None:
            DERROR("dwarf_add_AT_name")
        dir_index = dwarf_add_directory_decl(dbg, path, err)
        file_index = dwarf_add_file_decl(dbg, ext_c(curr.name), dir_index, 0, 0, err)
        dwarf_add_AT_comp_dir(cu, path, err)
    # memory = curr.getMemory()
    # Get sections
    # memory.getBlocks()

    # Get segments
    # memory.getLoadedAndInitializedAddressSet()

    # Get executable segments
    # list(memory.getExecuteSet().getAddressRanges())

    # However we can omit this step and directly decompile all functions

    linecount = 1
    for f in get_functions():
        if is_function_executable(f):
            add_function(cu, f, linecount, file_index)
        pass
        # results = ifc.decompileFunction(f, 0, ConsoleTaskMonitor())
        # print (results.getDecompiledFunction().getC())
    dwarf_add_die_to_debug(dbg, cu, err)
    add_global_variables(cu)
    add_structures(cu)

def generate_register_mappings():
    d2g_mapping = DWARFRegisterMappingsManager.getMappingForLang(curr.language)
    g2d_mapping = {}
    for i in range(DW_FRAME_LAST_REG_NUM):
        reg = d2g_mapping.getGhidraReg(i)
        if reg:
            g2d_mapping[reg.offset] = i
    stack_reg_num = d2g_mapping.DWARFStackPointerRegNum
    stack_reg_dwarf = globals()['DW_OP_breg%d' % stack_reg_num]
    return g2d_mapping, stack_reg_dwarf

def generate_decomp_interface():
    decompiler = DecompInterface()
    opts = DecompileOptions()
    opts.grabFromProgram(curr)
    decompiler.setOptions(opts)
    decompiler.toggleCCode(True)
    decompiler.toggleSyntaxTree(True)

    # - decompile -- The main decompiler action
    # - normalize -- Decompilation tuned for normalization
    # - jumptable -- Simplify just enough to recover a jump-table
    # - paramid   -- Simplify enough to recover function parameters
    # - register  -- Perform one analysis pass on registers, without stack variables
    # - firstpass -- Construct the initial raw syntax tree, with no simplification
    decompiler.setSimplificationStyle("decompile")
    decompiler.openProgram(curr)
    return decompiler


def get_decompiled_function(func):
    return decompiler.decompileFunction(func, 0, monitor)


def get_decompiled_variables(decomp):
    hf = decomp.highFunction
    for s in hf.localSymbolMap.symbols:
        hv = s.highVariable
        yield s.name, hv.dataType, s.PCAddress, hv.storage


def add_decompiler_func_info(cu, func_die, func, file_index):
    # https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html
    # print func.allVariables
    decomp = get_decompiled_function(func)
    for name, datatype, addr, storage in get_decompiled_variables(decomp):
        add_variable(cu, func_die, name, datatype, addr, storage)

    cmarkup = decomp.CCodeMarkup
    # TODO: implement our own pretty printer?
    # https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/PrettyPrinter.java
    lines = DecompilerUtils.toLines(cmarkup)
    for l in lines:
        # TODO: multiple lines might have the same lowest address
        addresses = [t.minAddress for t in l.allTokens if t.minAddress]
        lowest_addr = min(addresses) if addresses else None
        # print lowest_addr, l
        # TODO: is this call to dwarf_lne_set_address needed?
        # dwarf_lne_set_address(dbg, lowest_line_addr, 0, &err)
        # https://nxmnpg.lemoda.net/3/dwarf_add_line_entry
        if lowest_addr: # TODO: is this ok?
            dwarf_add_line_entry(dbg, file_index, lowest_addr.offset, l.lineNumber, 0, True, False, err)


def get_functions():
    fm = curr.functionManager
    funcs = fm.getFunctions(True)
    return funcs


def get_function_range(func):
    return (func.entryPoint, func.body.maxAddress)


def is_function_executable(func):
    f_start, f_end = get_function_range(func)
    # Check for functions inside executable segments
    for s in curr.memory.executeSet.addressRanges:
        if f_start.offset >= s.minAddress.offset and f_end.offset <= s.maxAddress.offset:
            return True
    return False


def add_global_variables(cu):
    # TODO
    pass

def add_structures(cu):
    # TODO
    pass

def add_variable(cu, func_die, name, datatype, addr, storage):
    var_die = dwarf_new_die(dbg, DW_TAG_variable, func_die, None, None, None, err);
    type_die = add_type(cu, datatype)

    if dwarf_add_AT_reference(dbg, var_die, DW_AT_type, type_die, err) is None:
        DERROR("dwarf_add_AT_reference")

    if dwarf_add_AT_name(var_die, name, err) is None:
        DERROR("dwarf_add_AT_name")

    # TODO: there could be more than one varnode, what does it even mean?
    varnode = storage.firstVarnode
    varnode_addr = varnode.getAddress()

    expr = dwarf_new_expr(dbg, err)

    if varnode_addr.isRegisterAddress():
        reg = curr.getRegister(varnode_addr, varnode.size)
        reg_dwarf = register_mappings[reg.offset]
        if dwarf_add_expr_gen(expr, DW_OP_regx, reg_dwarf, 0, err) == DW_DLV_NOCOUNT:
            DERROR("dwarf_add_expr_gen")
    elif varnode_addr.isStackAddress():
        if dwarf_add_expr_gen(expr, stack_register_dwarf, varnode_addr.offset, 0, err) == DW_DLV_NOCOUNT:
            DERROR("dwarf_add_expr_gen")
    elif varnode_addr.isMemoryAddress():
        # TODO: globals?
        assert False, 'Memory address'
    elif varnode_addr.isHashAddress():
        # TODO: ghidra synthetic vars.
        # It however often can be linked to a register(/stack off?) if looking at the disass,
        # find, if possible, how to get it programmatically.
        # This info is likely lost when generating the decompiled code. :(
        # print 'hash', varnode, curr.getRegister(varnode_addr, varnode.size)
        pass
    else:
        assert False, ('ERR var:', varnode)
    
    if dwarf_add_AT_location_expr(dbg, var_die, DW_AT_location, expr, err) is None:
        DERROR("dwarf_add_AT_location_expr")
    return var_die

def add_function(cu, func, linecount, file_index):
    die = dwarf_new_die(dbg, DW_TAG_subprogram, cu, None, None, None, err)
    if die is None:
        DERROR("dwarf_new_die")
    loc_expr = dwarf_new_expr(dbg, err)
    if dwarf_add_expr_gen(loc_expr, DW_OP_call_frame_cfa, 0, 0, err) == DW_DLV_NOCOUNT:
        DERROR("dwarf_add_expr_gen")
    if dwarf_add_AT_location_expr(dbg, die, DW_AT_frame_base, loc_expr, err) is None:
        DERROR("dwarf_add_AT_location_expr")
    # TODO: Understand difference between c_name and mangled_name
    f_name = func.name
    if dwarf_add_AT_name(die, f_name, err) is None:
        DERROR("dwarf_add_AT_name")
    if dwarf_add_AT_string(dbg, die, DW_AT_linkage_name, f_name, err) is None:
        DERROR("dwarf_add_AT_string")

    # TODO: Check for multiple ranges
    f_start, f_end = get_function_range(func)

    t = func.returnType
    # print f_start, f_end, type(t), t.description, func.name
    # TODO: Fix add_type function
    # ret_type_die = add_type(cu, func.returnType)
    # dwarf_add_AT_reference(dbg, die, DW_AT_type, ret_type_die, err)

    dwarf_add_AT_targ_address(dbg, die, DW_AT_low_pc, f_start.offset, 0, err)
    dwarf_add_AT_targ_address(dbg, die, DW_AT_high_pc, f_end.offset - 1, 0, err)

    if options.use_decompiler:
        # In test.exe.dbg generated by dwarfexport there isn't file_index and linecount
        # Don't decompile for now
        # dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_file, file_index, err)
        # dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_line, linecount, err)
        # dwarf_add_line_entry(dbg, file_index, f_start.offset, linecount, 0, True, False, err)
        # add_decompiler_func_info(cu, die, func, file_index)
        pass
    else:
        # TODO: NEVER?
        # add_disassembler_func_info(cu, die, func)
        pass
    # add_type(cu, func.returnType.description)
    return die


def add_type(cu, t):
    if isinstance(t, Pointer):
        return add_ptr_type(cu, t)
    elif isinstance(t, DefaultDataType):
        # TODO: an example of DefaultDataType is `undefined`, The following line is not definitive
        return add_default_type(cu, t)
    elif isinstance(t, BuiltInDataType):
        return add_default_type(cu, t)
    elif isinstance(t, Structure):
        return add_struct_type(cu, t)
    else:
        try:
            return add_default_type(cu, t)
        except:
            assert False, ("ERR type:", type(t), t)
        return None


def add_default_type(cu, t):
    die = dwarf_new_die(dbg, DW_TAG_base_type, cu, None, None, None, err)
    dwarf_add_AT_name(die, t.name, err)
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, t.length, err)
    return die

def add_ptr_type(cu, t):
    assert "pointer" in t.description
    die = dwarf_new_die(dbg, DW_TAG_compile_unit, cu, None, None, None, err)

    child_die = add_type(cu, t.dataType)
    if dwarf_add_AT_reference(dbg, die, DW_AT_type, child_die, err) is None:
        DERROR("dwarf_add_AT_reference child")
    if dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, 8, err) is None:
        DERROR("dwarf_add_AT_unsigned_const")
    return die


def add_struct_type(cu, struct):
    die = dwarf_new_die(dbg, DW_TAG_structure_type, cu, None, None, None, err)
    if dwarf_add_AT_name(die, struct.name, err) is None:
        DERROR("dwarf_add_AT_name")
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, struct.length, err)
    for c in struct.components:
        member_die = dwarf_new_die(dbg, DW_TAG_member, die, None, None, None, err)
        member_type_die = add_type(cu, c.dataType)
        dwarf_add_AT_reference(dbg, member_die, DW_AT_type, member_type_die, err)
        dwarf_add_AT_name(member_die, c.dataType.name, err)

        loc_expr = dwarf_new_expr(dbg, err)
        if dwarf_add_expr_gen(loc_expr, DW_OP_plus_uconst, c.offset, 0, err) == DW_DLV_NOCOUNT:
            DERROR("dward_add_expr_gen")

        if dwarf_add_AT_location_expr(dbg, member_die, DW_AT_data_member_location, loc_expr, err) is None:
            DERROR("dwarf_add_AT_location_expr")
    return die


def write_detached_dwarf_file(path):
    section_count = dwarf_transform_to_disk_form(dbg, err)
    if section_count == DW_DLV_NOCOUNT:
        ERROR("dwarf_transform_to_disk_form")

    print 'section_count', section_count
    for i in xrange(section_count):
        section_index = LongByReference()
        length = LongByReference()
        content = dwarf_get_section_bytes(dbg, i, section_index, length, err)
        if content is None:
            ERROR("dwarf_get_section_bytes")

        section_index = section_index.value
        length = length.value
        content = content.getByteArray(0, length)
        section_name = debug_sections[section_index]
        print section_index, section_name, length
        file_path = os.path.join(path, section_name.lstrip('.'))

        # TODO: according to the .cpp we might get the same section_index multiple times?
        with open(file_path, 'wb') as f:
            f.write(content)
            print 'written', file_path

    
debug_sections = []
# (const char *name, int size, Dwarf_Unsigned type, Dwarf_Unsigned flags, Dwarf_Unsigned link, Dwarf_Unsigned info, Dwarf_Unsigned *sect_name_symbol_index, void *userdata, int *)
def info_callback(name, *args):
    name = name.getString(0)
    print 'info_callback', name
    debug_sections.append(name)
    return len(debug_sections) - 1
    
ext_c = lambda s: s + ".c"
ext_dbg = lambda s: s + ".dbg"

l = LibdwarfLibrary.INSTANCE
g = globals()
for i in LibdwarfLibrary.__dict__.keys():
    g[i] = getattr(l, i)

curr = getCurrentProgram()
decompiler = generate_decomp_interface()
register_mappings, stack_register_dwarf = generate_register_mappings()

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
    info_callback,
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

write_detached_dwarf_file(tempfile.gettempdir())
dwarf_producer_finish(dbg, None)
