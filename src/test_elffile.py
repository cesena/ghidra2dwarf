import elffile
import array
import tempfile
import os

reload(elffile)

mem = currentProgram.memory
ghidra_file = mem.allFileBytes[0]
a = array.zeros('b', ghidra_file.size)
ghidra_file.getOriginalBytes(0, a)

bb = a.tostring()


efi = elffile.ElfFileIdent()
efi.unpack_from(bb)
ef = elffile.ElfFile.encodedClass(efi)('test', efi)
ef.unpack_from(bb)
print ef

newbb = ef.pack()

fname = os.path.join(tempfile.gettempdir(), 'lall.bin')
with open(fname, 'wb') as f:
    f.write(newbb)
