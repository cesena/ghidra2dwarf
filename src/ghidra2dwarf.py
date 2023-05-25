# Ghidra2Dwarf
# @author sen, meowmeowxw
# @category PWN
# @keybinding
# @menupath
# @toolbar

try:
    from ghidra_builtins import *
except:
    pass

import os
import sys

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.app.util.bin.format.elf import ElfSymbolTable
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.database.data import PointerDB
from ghidra.program.model.symbol import SymbolTable, SymbolType
from ghidra.program.model.data import Pointer, Structure, DefaultDataType, BuiltInDataType, BooleanDataType, CharDataType, AbstractIntegerDataType, AbstractFloatDataType, AbstractComplexDataType, ArrayDataType, Array, Enum
from ghidra.app.util.bin.format.dwarf4.next import DWARFRegisterMappingsManager
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.util.opinion import ElfLoader
from ghidra.framework import OperatingSystem

from elf import add_sections_to_elf

# we have to load libdwarf.jar dynamically by adding it to the path for some reason
script_path = sourceFile.absolutePath
libdwarf_jar_path = os.path.join(os.path.dirname(script_path), "libdwarf.jar")
sys.path.append(libdwarf_jar_path)

from libdwarf import LibdwarfLibrary
from com.sun.jna.ptr import PointerByReference, LongByReference
from com.sun.jna import Memory
from java.nio import ByteBuffer


curr = getCurrentProgram()
if curr.executableFormat != ElfLoader.ELF_NAME:
    print "Only ELF binaries are supported"
    exit(1)
image_base = curr.imageBase.offset
is_pie = curr.relocationTable.relocatable
orig_base = ElfLoader.getElfOriginalImageBase(curr)
# this breaks stuff, we changed approach and started using get_real_address
# curr.setImageBase(toAddr(orig_base), False)


def get_real_address(addr):
    return addr.offset - image_base + orig_base


def get_libdwarf_err():
    derr = Dwarf_Error(err.value)
    print derr
    return dwarf_errmsg(derr)


record = {}
exe_path = curr.executablePath
# workaround ghidra being dumb and putting a slash in front of Windows paths
# this should be fixed in the next release as discussed here:
# https://github.com/NationalSecurityAgency/ghidra/pull/2220
if OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS and exe_path[0] == "/":
    exe_path = exe_path[1:]

while not os.path.isfile(exe_path):
    print "I couldn't find the original file at path %s. Please specify its path:" % exe_path
    exe_path = askFile("Original binary path", "Open").path
    curr.executablePath = exe_path
    print "Changed binary path to %s." % exe_path

out_path = exe_path + "_dbg"
decompiled_c_path = exe_path + "_dbg.c"
decomp_lines = []

ERR_IS_NOT_OK = lambda e: e != DW_DLV_OK
ERR_IS_NOCOUNT = lambda e: e == DW_DLV_NOCOUNT
ERR_IS_BADADDR = lambda e: e is None or e == DW_DLV_BADADDR or (hasattr(e, "pointer") and e.pointer == DW_DLV_BADADDR)
DWARF_FUNCTIONS = {
    'dwarf_producer_init': ERR_IS_NOT_OK,
    'dwarf_pro_set_default_string_form': ERR_IS_NOT_OK,
    'dwarf_transform_to_disk_form': ERR_IS_NOCOUNT,
    'dwarf_get_section_bytes': ERR_IS_BADADDR,
    'dwarf_producer_finish_a': ERR_IS_NOT_OK,
    'dwarf_add_AT_targ_address': ERR_IS_BADADDR,
    'dwarf_add_AT_unsigned_const': ERR_IS_BADADDR,
    'dwarf_add_AT_reference': ERR_IS_BADADDR,
    'dwarf_add_AT_location_expr': ERR_IS_BADADDR,
    'dwarf_add_AT_string': ERR_IS_BADADDR,
    'dwarf_add_AT_comp_dir': ERR_IS_BADADDR,
    'dwarf_add_AT_name': ERR_IS_BADADDR,
    'dwarf_add_directory_decl': ERR_IS_NOCOUNT,
    'dwarf_add_file_decl': ERR_IS_NOCOUNT,
    'dwarf_add_line_entry': ERR_IS_NOCOUNT,
    'dwarf_lne_end_sequence_a': ERR_IS_NOCOUNT,
    'dwarf_new_die': ERR_IS_BADADDR,
    'dwarf_add_die_to_debug_a': ERR_IS_NOT_OK,
    'dwarf_new_expr': ERR_IS_BADADDR,
    'dwarf_add_expr_gen': ERR_IS_NOCOUNT,
    'dwarf_add_expr_addr_b': ERR_IS_NOCOUNT
}


def generate_fun_wrapper(name, fun):
    def wrapper(*args):
        r = fun(*(args + (err,)))
        error_check = DWARF_FUNCTIONS[name]
        if error_check(r):
            # TODO: dwarf_errmsg (hence get_libdwarf_err) is broken for some reason
            # assert False, "%s failed: %s" % (name, get_libdwarf_err())
            assert False, "%s failed. Returned %r" % (name, r)
        return r

    return wrapper


l = LibdwarfLibrary.INSTANCE
g = globals()
for name in LibdwarfLibrary.__dict__.keys():
    if name in DWARF_FUNCTIONS:
        fun = getattr(l, name)
        g[name] = generate_fun_wrapper(name, fun)
    else:
        g[name] = getattr(l, name)


def add_debug_info():
    dwarf_pro_set_default_string_form(dbg, DW_FORM_string)
    cu = dwarf_new_die(dbg, DW_TAG_compile_unit, None, None, None, None)

    c_file_name = os.path.split(decompiled_c_path)[1]
    dwarf_add_AT_name(cu, c_file_name)
    dir_index = dwarf_add_directory_decl(dbg, ".")
    file_index = dwarf_add_file_decl(dbg, c_file_name, dir_index, 0, 0)
    dwarf_add_AT_comp_dir(cu, ".")

    funcs = get_functions()
    addr_to_line = {}
    max_addr = 0
    for i, f in enumerate(funcs):
        print "Decompiling function %d: %s" % (i, f)
        die, func_addrs = add_function(cu, f, file_index)
        addr_to_line.update(func_addrs)
        max_addr = max(max_addr, get_function_range(f)[1] + 1)

    for addr in sorted(addr_to_line):
        dwarf_add_line_entry(dbg, file_index, addr, addr_to_line[addr], 0, True, False)
        max_addr = max(max_addr, addr + 1)

    dwarf_lne_end_sequence_a(dbg, max_addr)

    dwarf_add_die_to_debug_a(dbg, cu)
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
    symbolMap = hf.localSymbolMap
    params = [symbolMap.getParam(i).symbol for i in range(symbolMap.numParams) if symbolMap.getParam(i)]
    for s in symbolMap.symbols:
        yield s.name, s.dataType, s.PCAddress, s.storage, s in params


def add_decompiler_func_info(cu, func_die, func, decomp, file_index, func_line):
    # https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html
    # print func.allVariables
    for name, datatype, addr, storage, is_param in get_decompiled_variables(decomp):
        add_variable(cu, func_die, name, datatype, addr, storage, is_parameter=is_param)

    cmarkup = decomp.CCodeMarkup
    # TODO: implement our own pretty printer?
    # https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/PrettyPrinter.java
    lines = DecompilerUtils.toLines(cmarkup)
    addr_to_line = {}
    for l in lines:
        for token in l.allTokens:
            if token.minAddress:
                addr_to_line[get_real_address(token.minAddress)] = l.lineNumber + func_line - 1

    return addr_to_line


def get_functions():
    fm = curr.functionManager
    funcs = fm.getFunctions(True)
    return funcs


def get_function_range(func):
    return get_real_address(func.entryPoint), get_real_address(func.body.maxAddress)


def is_function_executable(func):
    f_start, f_end = get_function_range(func)
    # Check for functions inside executable segments
    for s in curr.memory.executeSet.addressRanges:
        if f_start >= get_real_address(s.minAddress) and f_end <= get_real_address(s.maxAddress):
            return True
    return False


def add_global_variables(cu):
    for s in curr.symbolTable.getAllSymbols(True):
        # TODO: What is the difference between GLOBAL and GLOBAL_VAR ?
        if s.symbolType in [SymbolType.LABEL, SymbolType.GLOBAL, SymbolType.GLOBAL_VAR]:
            t = curr.listing.getDataAt(s.address)
            if t:
                die = dwarf_new_die(dbg, DW_TAG_variable, cu, None, None, None)
                var_type_die = add_type(cu, t.dataType)

                dwarf_add_AT_name(die, s.name)
                dwarf_add_AT_reference(dbg, die, DW_AT_type, var_type_die)

                loc_expr = dwarf_new_expr(dbg)
                dwarf_add_expr_addr_b(loc_expr, get_real_address(t.address), 0)
                dwarf_add_AT_location_expr(dbg, die, DW_AT_location, loc_expr)


def add_structures(cu):
    for s in curr.dataTypeManager.allStructures:
        add_type(cu, s)


def add_variable(cu, func_die, name, datatype, addr, storage, is_parameter=False):
    # TODO: there could be more than one varnode, what does it even mean?
    varnode = storage.firstVarnode
    # It looks like sometimes ghidra creates a fake/temp variable without any varnodes, it should be ok to ignore it
    if varnode is None:
        return None
    varnode_addr = varnode.getAddress()

    # TODO: add varaible starting from addr
    tag = DW_TAG_variable
    if is_parameter:
        tag = DW_TAG_formal_parameter
    var_die = dwarf_new_die(dbg, tag, func_die, None, None, None)
    type_die = add_type(cu, datatype)

    dwarf_add_AT_reference(dbg, var_die, DW_AT_type, type_die)
    dwarf_add_AT_name(var_die, name)

    expr = dwarf_new_expr(dbg)

    try:
        if varnode_addr.isRegisterAddress():
            reg = curr.getRegister(varnode_addr, varnode.size)
            reg_dwarf = register_mappings[reg.offset]
            dwarf_add_expr_gen(expr, DW_OP_regx, reg_dwarf, 0)
        elif varnode_addr.isStackAddress():
            # TODO: properly get register size and figure out if this is always correct
            dwarf_add_expr_gen(expr, DW_OP_fbreg, varnode_addr.offset - varnode_addr.pointerSize, 0)
        elif varnode_addr.isMemoryAddress():
            print name, varnode
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

        dwarf_add_AT_location_expr(dbg, var_die, DW_AT_location, expr)
    except:
        return var_die
    return var_die


def add_function(cu, func, file_index):
    die = dwarf_new_die(dbg, DW_TAG_subprogram, cu, None, None, None)
    loc_expr = dwarf_new_expr(dbg)
    dwarf_add_expr_gen(loc_expr, DW_OP_call_frame_cfa, 0, 0)
    dwarf_add_AT_location_expr(dbg, die, DW_AT_frame_base, loc_expr)
    f_name = func.name
    dwarf_add_AT_name(die, f_name)
    dwarf_add_AT_string(dbg, die, DW_AT_linkage_name, f_name)

    # TODO: Check for multiple ranges
    f_start, f_end = get_function_range(func)

    ret_type_die = add_type(cu, func.returnType)
    dwarf_add_AT_reference(dbg, die, DW_AT_type, ret_type_die)

    dwarf_add_AT_targ_address(dbg, die, DW_AT_low_pc, f_start, 0)
    dwarf_add_AT_targ_address(dbg, die, DW_AT_high_pc, f_end + 1, 0)

    func_line = len(decomp_lines) + 1

    res = get_decompiled_function(func)
    if res.decompiledFunction is None:
        d = "/* Error decompiling %s: %s */" % (func.getName(True), res.errorMessage)
    else:
        d = res.decompiledFunction.c
    decomp_lines.extend(d.split("\n"))

    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_file, file_index)
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_line, func_line + 1)
    addr_to_line = {f_start: func_line + 1}
    if res.decompiledFunction is not None:
        addr_to_line.update(add_decompiler_func_info(cu, die, func, res, file_index, func_line))

    return die, addr_to_line


def write_source():
    with open(decompiled_c_path, "wb") as src:
        src.write("\n".join(decomp_lines).encode("utf8"))


def add_type(cu, t):
    if t.name in record:
        return record[t.name]

    if isinstance(t, Pointer):
        return add_ptr_type(cu, t)
    elif isinstance(t, Enum):
        return add_enum_type(cu, t)
    elif isinstance(t, Array):
        return add_array_type(cu, t)
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
    die = dwarf_new_die(dbg, DW_TAG_base_type, cu, None, None, None)
    record[t.name] = die
    dwarf_add_AT_name(die, t.name)
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, t.length)

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
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_encoding, encoding)
    return die


def add_ptr_type(cu, t):
    die = dwarf_new_die(dbg, DW_TAG_pointer_type, cu, None, None, None)
    record[t.name] = die

    # Some pointer don't have childs
    if t.dataType:
        child_die = add_type(cu, t.dataType)
        dwarf_add_AT_reference(dbg, die, DW_AT_type, child_die)

    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, t.length)
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_encoding, DW_ATE_address)
    return die


def add_enum_type(cu, t):
    die = dwarf_new_die(dbg, DW_TAG_enumeration_type, cu, None, None, None)
    record[t.name] = die

    dwarf_add_AT_name(die, t.name)
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, t.length)

    int_type = AbstractIntegerDataType.getUnsignedDataType(t.length, curr.dataTypeManager)
    child_type_die = add_type(cu, int_type)
    dwarf_add_AT_reference(dbg, die, DW_AT_type, child_type_die)

    # In this way we iterate the values in order
    for value in t.values:
        name = t.getName(value)
        child_die = dwarf_new_die(dbg, DW_TAG_enumerator, die, None, None, None)
        dwarf_add_AT_name(child_die, name)
        dwarf_add_AT_unsigned_const(dbg, child_die, DW_AT_const_value, value)

    return die


def add_struct_type(cu, struct):
    die = dwarf_new_die(dbg, DW_TAG_structure_type, cu, None, None, None)
    record[struct.name] = die
    dwarf_add_AT_name(die, struct.name.replace("struct", ""))
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, struct.length)
    for c in struct.components:
        member_die = dwarf_new_die(dbg, DW_TAG_member, die, None, None, None)
        member_type_die = add_type(cu, c.dataType)
        dwarf_add_AT_reference(dbg, member_die, DW_AT_type, member_type_die)
        dwarf_add_AT_name(member_die, c.fieldName or c.defaultFieldName)

        loc_expr = dwarf_new_expr(dbg)
        dwarf_add_expr_gen(loc_expr, DW_OP_plus_uconst, c.offset, 0)

        dwarf_add_AT_location_expr(dbg, member_die, DW_AT_data_member_location, loc_expr)
    return die


def add_array_type(cu, array):
    die = dwarf_new_die(dbg, DW_TAG_array_type, cu, None, None, None)
    record[array.name] = die

    element_die = add_type(cu, array.dataType)
    dwarf_add_AT_reference(dbg, die, DW_AT_type, element_die)

    subrange = dwarf_new_die(dbg, DW_TAG_subrange_type, die, None, None, None)
    # array.length is the total size of the array, so we need to divide it with
    # the dataType's length to find the number of elements
    dwarf_add_AT_unsigned_const(dbg, subrange, DW_AT_count, array.length / array.dataType.length)

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
    section_count = dwarf_transform_to_disk_form(dbg)
    print "section_count", section_count

    sections = {}
    for i in xrange(section_count):
        section_index = LongByReference()
        length = LongByReference()
        content = dwarf_get_section_bytes(dbg, i, section_index, length)

        section_index = section_index.value
        length = length.value
        content = bytearray(content.getByteArray(0, length))
        section_name = sections_callback.sections[section_index]
        if section_name not in sections:
            sections[section_name] = ""
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
    )
    dbg = Dwarf_P_Debug(dbg.value)
    add_debug_info()
    write_source()
    sections = generate_dwarf_sections()
    dwarf_producer_finish_a(dbg)
    add_sections_to_elf(exe_path, out_path, sections)
    print "Done."
    print "ELF saved to", out_path
    print "C source saved to", decompiled_c_path
