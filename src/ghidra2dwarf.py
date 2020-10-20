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
from ghidra.program.model.data import Pointer, Structure, DefaultDataType, BuiltInDataType, BooleanDataType, CharDataType, AbstractIntegerDataType, AbstractFloatDataType, AbstractComplexDataType
from ghidra.app.util.bin.format.dwarf4.next import DWARFRegisterMappingsManager
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.util.opinion import ElfLoader

from elf import add_sections_to_elf
from libdwarf import LibdwarfLibrary, Dwarf_Relocation_Data_s
from com.sun.jna.ptr import PointerByReference, LongByReference
from com.sun.jna import Memory
from java.nio import ByteBuffer

import subprocess
import os
import tempfile


curr = getCurrentProgram()
is_pie = curr.relocationTable.relocatable
if is_pie:
    orig_base = ElfLoader.getElfOriginalImageBase(curr)
    curr.setImageBase(toAddr(orig_base), False)

MAGIC_OFFSET = 7
record = {}
exe_path = os.path.join(*os.path.split(curr.executablePath))
out_path = exe_path + '_dbg'
decompiled_c_path = exe_path + '.ghidra.c'

l = LibdwarfLibrary.INSTANCE
g = globals()
for i in LibdwarfLibrary.__dict__.keys():
    g[i] = getattr(l, i)


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
    if options.use_decompiler:
        c_file_name = os.path.split(decompiled_c_path)[1]
        if dwarf_add_AT_name(cu, c_file_name, err) is None:
            DERROR("dwarf_add_AT_name")
        dir_index = dwarf_add_directory_decl(dbg, '.', err)
        file_index = dwarf_add_file_decl(dbg, c_file_name, dir_index, 0, 0, err)
        dwarf_add_AT_comp_dir(cu, '.', err)

    for f in get_functions():
        if is_function_executable(f):
            add_function(cu, f, file_index)
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
    stack_reg_dwarf = globals()["DW_OP_breg%d" % stack_reg_num]
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
        # TODO: Sometimes error with custom types?
        try:
            yield s.name, hv.dataType, s.PCAddress, hv.storage
        except:
            pass


def add_decompiler_func_info(cu, func_die, func, file_index, linecount):
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
        if lowest_addr:
            dwarf_add_line_entry(
                dbg, file_index, lowest_addr.offset, l.lineNumber + linecount - MAGIC_OFFSET, 0, True, False, err,
            )


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
    """
    TODO: Why is not working correctly ?
    It corrupts the .debug_info section
    for s in curr.dataTypeManager.allStructures:
        add_type(cu, s)
    """
    pass


def add_variable(cu, func_die, name, datatype, addr, storage):
    # TODO: there could be more than one varnode, what does it even mean?
    varnode = storage.firstVarnode
    # It looks like sometimes ghidra creates a fake/temp variable without any varnodes, it should be ok to ignore it
    if varnode is None:
        return None
    varnode_addr = varnode.getAddress()

    # TODO: add varaible starting from addr
    var_die = dwarf_new_die(dbg, DW_TAG_variable, func_die, None, None, None, err)
    type_die = add_type(cu, datatype)

    if dwarf_add_AT_reference(dbg, var_die, DW_AT_type, type_die, err) is None:
        DERROR("dwarf_add_AT_reference")

    if dwarf_add_AT_name(var_die, name, err) is None:
        DERROR("dwarf_add_AT_name")

    expr = dwarf_new_expr(dbg, err)

    try:
        if varnode_addr.isRegisterAddress():
            reg = curr.getRegister(varnode_addr, varnode.size)
            reg_dwarf = register_mappings[reg.offset]
            if dwarf_add_expr_gen(expr, DW_OP_regx, reg_dwarf, 0, err) == DW_DLV_NOCOUNT:
                DERROR("dwarf_add_expr_gen")
        elif varnode_addr.isStackAddress():
            # TODO: properly get register size and figure out if this is always correct
            if dwarf_add_expr_gen(expr, DW_OP_fbreg, varnode_addr.offset - varnode_addr.pointerSize, 0, err) == DW_DLV_NOCOUNT:
                DERROR("dwarf_add_expr_gen")
        elif varnode_addr.isMemoryAddress():
            # TODO: globals?
            assert False, "Memory address"
        elif varnode_addr.isHashAddress():
            # TODO: ghidra synthetic vars.
            # It however often can be linked to a register(/stack off?) if looking at the disass,
            # find, if possible, how to get it programmatically.
            # This info is likely lost when generating the decompiled code. :(
            # print 'hash', varnode, curr.getRegister(varnode_addr, varnode.size)
            pass
        else:
            assert False, ("ERR var:", varnode)

        if dwarf_add_AT_location_expr(dbg, var_die, DW_AT_location, expr, err) is None:
            DERROR("dwarf_add_AT_location_expr")
    except:
        return var_die
    return var_die


def add_function(cu, func, file_index):
    die = dwarf_new_die(dbg, DW_TAG_subprogram, cu, None, None, None, err)
    if die is None:
        DERROR("dwarf_new_die")
    loc_expr = dwarf_new_expr(dbg, err)
    if dwarf_add_expr_gen(loc_expr, DW_OP_call_frame_cfa, 0, 0, err) == DW_DLV_NOCOUNT:
        DERROR("dwarf_add_expr_gen")
    if dwarf_add_AT_location_expr(dbg, die, DW_AT_frame_base, loc_expr, err) is None:
        DERROR("dwarf_add_AT_location_expr")
    f_name = func.name
    if dwarf_add_AT_name(die, f_name, err) is None:
        DERROR("dwarf_add_AT_name")
    if dwarf_add_AT_string(dbg, die, DW_AT_linkage_name, f_name, err) is None:
        DERROR("dwarf_add_AT_string")

    # TODO: Check for multiple ranges
    f_start, f_end = get_function_range(func)

    t = func.returnType
    ret_type_die = add_type(cu, func.returnType)
    dwarf_add_AT_reference(dbg, die, DW_AT_type, ret_type_die, err)

    dwarf_add_AT_targ_address(dbg, die, DW_AT_low_pc, f_start.offset, 0, err)
    dwarf_add_AT_targ_address(dbg, die, DW_AT_high_pc, f_end.offset - 1, 0, err)

    if options.use_decompiler:
        # TODO: thafuck, I tried with a global variable but it didn't work well...
        linecount = sum(1 for line in open(decompiled_c_path, "rb")) + MAGIC_OFFSET
        with open(decompiled_c_path, "ab") as src:
            res = get_decompiled_function(func)
            src.write(res.decompiledFunction.c)

        dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_file, file_index, err)
        dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_line, linecount, err)
        dwarf_add_line_entry(dbg, file_index, f_start.offset, linecount, 0, True, False, err)
        add_decompiler_func_info(cu, die, func, file_index, linecount)
        pass
    else:
        # TODO: NEVER?
        # add_disassembler_func_info(cu, die, func)
        pass
    return die


def add_type(cu, t):
    if record.get(t.name, 0) != 0:
        return record[t.name]

    if isinstance(t, Pointer):
        return add_ptr_type(cu, t)
    elif isinstance(t, Structure):
        return add_struct_type(cu, t)
    elif isinstance(t, (BuiltInDataType, DefaultDataType)):
        return add_default_type(cu, t)
    else:
        try:
            return add_default_type(cu, t)
        except:
            assert False, ("ERR type:", type(t), t)
        return None


def add_default_type(cu, t):
    die = dwarf_new_die(dbg, DW_TAG_base_type, cu, None, None, None, err)
    record[t.name] = die
    dwarf_add_AT_name(die, t.name, err)
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, t.length, err)

    # type encoding dwarfstd.org/doc/DWARF4.pdf#page=91
    if isinstance(t, BooleanDataType):
        encoding = DW_ATE_boolean
    elif isinstance(t, CharDataType):
        is_char_signed = t.dataTypeManager.dataOrganization.signedChar
        encoding = DW_ATE_signed_char if is_char_signed else DW_ATE_unsigned_char
    elif isinstance(t, AbstractIntegerDataType):
        encoding = DW_ATE_signed if t.signed else DW_ATE_unsigned
    elif isinstance(t, AbstractFloatDataType):
        encoding = DW_ATE_float
    elif isinstance(t, AbstractComplexDataType):
        encoding = DW_ATE_complex_float
    else:
        # if I forgot a type it's probably ok for it to be encoded as an unsigned integer
        encoding = DW_ATE_unsigned
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_encoding, encoding, err)
    return die


def add_ptr_type(cu, t):
    assert "pointer" in t.description
    die = dwarf_new_die(dbg, DW_TAG_pointer_type, cu, None, None, None, err)
    record[t.name] = die

    child_die = add_type(cu, t.dataType)
    if dwarf_add_AT_reference(dbg, die, DW_AT_type, child_die, err) is None:
        DERROR("dwarf_add_AT_reference child")
    if dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, 8, err) is None:
        DERROR("dwarf_add_AT_unsigned_const")
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_encoding, DW_ATE_address, err)
    return die


def add_struct_type(cu, struct):
    die = dwarf_new_die(dbg, DW_TAG_structure_type, cu, None, None, None, err)
    record[struct.name] = die
    if dwarf_add_AT_name(die, struct.name.replace("struct", ""), err) is None:
        DERROR("dwarf_add_AT_name")
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, struct.length, err)
    for c in struct.components:
        member_die = dwarf_new_die(dbg, DW_TAG_member, die, None, None, None, err)
        member_type_die = add_type(cu, c.dataType)
        dwarf_add_AT_reference(dbg, member_die, DW_AT_type, member_type_die, err)
        dwarf_add_AT_name(member_die, c.fieldName, err)

        loc_expr = dwarf_new_expr(dbg, err)
        if dwarf_add_expr_gen(loc_expr, DW_OP_plus_uconst, c.offset, 0, err) == DW_DLV_NOCOUNT:
            DERROR("dward_add_expr_gen")

        if dwarf_add_AT_location_expr(dbg, member_die, DW_AT_data_member_location, loc_expr, err) is None:
            DERROR("dwarf_add_AT_location_expr")
    return die


class SectionsCallback(Dwarf_Callback_Func):
    def __init__(self):
        self.sections = []

    def apply(self, name, *args):
        name = str(name.getString(0))
        print "info_callback", name
        self.sections.append(name)
        return len(self.sections) - 1

def generate_dwarf_sections():
    section_count = dwarf_transform_to_disk_form(dbg, err)
    if section_count == DW_DLV_NOCOUNT:
        DERROR("dwarf_transform_to_disk_form")
    print "section_count", section_count

    sections = {}
    for i in xrange(section_count):
        section_index = LongByReference()
        length = LongByReference()
        content = dwarf_get_section_bytes(dbg, i, section_index, length, err)
        if content is None:
            DERROR("dwarf_get_section_bytes")

        section_index = section_index.value
        length = length.value
        content = bytearray(content.getByteArray(0, length))
        section_name = sections_callback.sections[section_index]
        if section_name not in sections:
            sections[section_name] = ''
        sections[section_name] += content    
        print section_index, section_name, length
    return sections.items()

if __name__ == "__main__":
    decompiler = generate_decomp_interface()
    register_mappings, stack_register_dwarf = generate_register_mappings()
    dbg = PointerByReference()
    err = PointerByReference()
    sections_callback = SectionsCallback()
    dwarf_producer_init(
        DW_DLC_WRITE | DW_DLC_SYMBOLIC_RELOCATIONS | DW_DLC_POINTER64 | DW_DLC_OFFSET32 | DW_DLC_TARGET_LITTLEENDIAN,
        sections_callback,
        None,
        None,
        None,
        "x86_64",
        "V2",
        None,
        dbg,
        err,
    )
    # TODO: generate the C file in a better way
    with open(decompiled_c_path, "w") as f:
        f.write("\n")
    dbg = Dwarf_P_Debug(dbg.value)
    options = Options(use_dec=True)
    add_debug_info()
    sections = generate_dwarf_sections()
    dwarf_producer_finish(dbg, None)

    add_sections_to_elf(exe_path, out_path, sections)
