#!/usr/bin/env python3
import struct

# ================= ELF CONSTANTS =================

SHT_NULL   = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3

STB_LOCAL  = 0
STB_GLOBAL = 1

STT_NOTYPE = 0
STT_FUNC   = 2

ELFCLASS32 = 1
ELFCLASS64 = 2

# ================= ELF HELPER =================

def unpack(fmt, data, off=0):
    return struct.unpack_from(fmt, data, off)

def pack(fmt, *vals):
    return struct.pack(fmt, *vals)

class ELF:
    def __init__(self, path):
        self.data = bytearray(open(path,"rb").read())
        if self.data[:4] != b"\x7fELF":
            raise RuntimeError("Not an ELF file")
        self.elfclass = self.data[4]
        if self.elfclass == ELFCLASS32:
            self.is_64 = False
            self.EHDR_FMT = "<16sHHIIIIIHHHHHH"
            self.SHDR_FMT = "<IIIIIIIIII"
            self.SYM_FMT  = "<IIIBBH"
            hdr = unpack(self.EHDR_FMT, self.data)
            (
                self.e_ident, self.e_type, self.e_machine, self.e_version,
                self.e_entry, self.e_phoff, self.e_shoff, self.e_flags,
                self.e_ehsize, self.e_phentsize, self.e_phnum,
                self.e_shentsize, self.e_shnum, self.e_shstrndx
            ) = hdr
        elif self.elfclass == ELFCLASS64:
            self.is_64 = True
            self.EHDR_FMT = "<16sHHIQQQIHHHHHH"
            self.SHDR_FMT = "<IIQQQQIIQQ"
            self.SYM_FMT  = "<IBBHQQ"
            hdr = unpack(self.EHDR_FMT, self.data)
            (
                self.e_ident, self.e_type, self.e_machine, self.e_version,
                self.e_entry, self.e_phoff, self.e_shoff, self.e_flags,
                self.e_ehsize, self.e_phentsize, self.e_phnum,
                self.e_shentsize, self.e_shnum, self.e_shstrndx
            ) = hdr
        else:
            raise RuntimeError("Unknown ELF class")
        self._load_sections()

    def elf32_sym(self,name,value,size,info,other,shndx):
        return pack(self.SYM_FMT, name,value,size,info,other,shndx)

    def elf64_sym(self,name,info,other,shndx,value,size):
        return pack(self.SYM_FMT,name,info,other,shndx,value,size)

    def _load_sections(self):
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i*self.e_shentsize
            self.sections.append(list(unpack(self.SHDR_FMT,self.data,off)))
        shstr = self.sections[self.e_shstrndx]
        self.shstrtab_offset = shstr[4]
        self.shstrtab_size   = shstr[5]
        self.shstrtab = bytearray(self.data[self.shstrtab_offset:self.shstrtab_offset+self.shstrtab_size])
        self.section_names = {}
        for i, sh in enumerate(self.sections):
            off = sh[0]
            end = self.shstrtab.find(b"\x00", off)
            self.section_names[i] = self.shstrtab[off:end].decode() if end!=-1 else ""

    def find_section(self,name):
        for i,n in self.section_names.items():
            if n==name:
                return i,self.sections[i]
        return None,None

    def add_section(self,name,shtype,entsize=0,link=0,info=0):
        name_off = len(self.shstrtab)
        self.shstrtab += name.encode() + b"\x00"
        sh = [name_off,shtype,0,0,0,0,link,info,0,entsize]
        self.sections.append(sh)
        idx = len(self.sections)-1
        self.section_names[idx] = name
        self.e_shnum += 1
        return idx

# ================= SYMTAB =================

def read_or_create_symtab(elf):
    sym_idx,symsec = elf.find_section(".symtab")
    str_idx,strsec = elf.find_section(".strtab")
    if sym_idx is not None:
        sym_data = elf.data[symsec[4]:symsec[4]+symsec[5]]
        syms=[]
        for i in range(0,len(sym_data),symsec[9]):
            syms.append(unpack(elf.SYM_FMT,sym_data,i))
        strtab = elf.data[strsec[4]:strsec[4]+strsec[5]]
        return syms,strtab,sym_idx,str_idx
    # create empty
    strtab = b"\x00"
    str_idx = elf.add_section(".strtab",SHT_STRTAB)
    sym_idx = elf.add_section(".symtab",SHT_SYMTAB,entsize=struct.calcsize(elf.SYM_FMT),link=str_idx,info=1)
    return [],strtab,sym_idx,str_idx

def append_symbols(elf, syms, strtab, labels, func_addrs, text_shndx):
    strtab = bytearray(strtab)
    symtab = bytearray()
    if not syms:
        if elf.is_64:
            symtab += elf.elf64_sym(0,0,0,0,0,0)
        else:
            symtab += elf.elf32_sym(0,0,0,0,0,0)
    for s in syms:
        symtab += pack(elf.SYM_FMT,*s)
    for name, addr in labels:
        off = len(strtab)
        strtab += name.encode() + b"\x00"
        typ = STT_FUNC if addr in func_addrs else STT_NOTYPE
        info = (STB_GLOBAL <<4) | typ
        if elf.is_64:
            symtab += elf.elf64_sym(off,info,0,text_shndx,addr,0)
        else:
            symtab += elf.elf32_sym(off,addr,0,info,0,text_shndx)
    return symtab,strtab

# ================= MAIN =================

def add_ghidra_symbols(in_path, out_path, ghidra_labels, ghidra_funcs):
    """
    in_path: path to existing ELF
    out_path: output ELF path
    ghidra_labels: list of tuples (name, addr_in_ELF)
    ghidra_funcs: list of tuples (name, addr_in_ELF)
    """
    elf = ELF(in_path)
    text_idx,_ = elf.find_section(".text")
    if text_idx is None:
        raise RuntimeError("No .text section")
    func_addrs = [addr for name, addr in ghidra_funcs]

    syms,strtab,sym_idx,str_idx = read_or_create_symtab(elf)
    symtab,strtab = append_symbols(
        elf, syms, strtab,
        labels=ghidra_labels + ghidra_funcs,
        func_addrs=func_addrs,
        text_shndx=text_idx
    )

    # append symtab/strtab
    sym_offset = len(elf.data)
    elf.data += symtab
    str_offset = len(elf.data)
    elf.data += strtab
    elf.sections[sym_idx][4] = sym_offset
    elf.sections[sym_idx][5] = len(symtab)
    elf.sections[str_idx][4] = str_offset
    elf.sections[str_idx][5] = len(strtab)

    # update shstrtab
    shstr_offset = len(elf.data)
    elf.data += elf.shstrtab
    elf.sections[elf.e_shstrndx][4] = shstr_offset
    elf.sections[elf.e_shstrndx][5] = len(elf.shstrtab)

    # append section headers
    elf.e_shoff = len(elf.data)
    for sh in elf.sections:
        elf.data += pack(elf.SHDR_FMT,*sh)

    # rewrite ELF header
    elf.data[:struct.calcsize(elf.EHDR_FMT)] = pack(
        elf.EHDR_FMT,
        elf.e_ident, elf.e_type, elf.e_machine, elf.e_version,
        elf.e_entry, elf.e_phoff, elf.e_shoff, elf.e_flags,
        elf.e_ehsize, elf.e_phentsize, elf.e_phnum,
        elf.e_shentsize, elf.e_shnum, elf.e_shstrndx
    )

    open(out_path,"wb").write(elf.data)

# ---------------- USAGE IN GHIDRA ----------------
# labels = [
#     (s.name, get_real_address(s.address))
#     for s in curr.symbolTable.getAllSymbols(True)
#     if s.source == SourceType.USER_DEFINED and s.symbolType == SymbolType.LABEL
# ]
# funcs  = [(f.name,get_real_address(f.entryPoint)) for f in get_functions()]
# add_ghidra_symbols(exe_path, out_path, labels, funcs)
