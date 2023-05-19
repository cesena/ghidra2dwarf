import struct

class ElfBase(object):
	def __init__(self, file_offset, map, values, **kwargs):
		self.__dict__['map'] = map
		self.file_offset = file_offset
		for n, v in zip(map, values):
			if isinstance(n, tuple):
				n, f = n
				v = f(v)
			setattr(self, n, v)

	@property
	def values(self):
		vv = (getattr(self, n[0] if isinstance(n, tuple) else n) for n in self.map)
		return [v.code if isinstance(v, DumbEnumValue) else v for v in vv]

	def __setattr__(self, name, value):
		if not hasattr(self, 'repr_pos'):
			object.__setattr__(self, 'repr_pos', {})
		if name not in self.repr_pos:
			self.repr_pos[name] = len(self.repr_pos)
		return object.__setattr__(self, name, value)

	def __repr__(self):
		args = ', '.join('%s=%r' % (n, getattr(self, n)) for n, _ in sorted(self.repr_pos.items(), key=lambda x: x[1]))
		return '%s(%s)' % (self.__class__.__name__, args)

class ElfIdent(ElfBase):
	def __init__(self, values, file_offset):
		return ElfBase.__init__(self, file_offset, [
			'magic',
			('elf_class', ElfClass.__getitem__),
			('elf_data', ElfData.__getitem__),
			'file_version',
			'osabi',
			'abi_version',
		], values)

class ElfHeader(ElfBase):
	def __init__(self, values, file_offset):
		return ElfBase.__init__(self, file_offset, [
			('type', ET.__getitem__),
			('machine', EM.__getitem__),
			'version',
			'entry',
			'phoff',
			'shoff',
			'flags',
			'ehsize',
			'phentsize',
			'phnum',
			'shentsize',
			'shnum',
			'shstrndx',
		], values)

class ElfSectionHeader(ElfBase):
	def __init__(self, values, file_offset):
		self.name = ''
		return ElfBase.__init__(self, file_offset, [
			'name_offset',
			('type', SHT.__getitem__),
			'flags',
			'addr',
			'offset',
			'section_size',
			'link',
			'info',
			'addralign',
			'entsize',
		], values)


struct_coders = {
	'ElfIdent': struct.Struct('=4sBBBBBxxxxxxx'),
	'ElfHeader': {
		'32le': struct.Struct('<HHIIIIIHHHHHH'),
		'32be': struct.Struct('>HHIIIIIHHHHHH'),
		'64le': struct.Struct('<HHIQQQIHHHHHH'),
		'64be': struct.Struct('>HHIQQQIHHHHHH'),
	},
	'ElfSectionHeader': {
		'32le': struct.Struct('<IIIIIIIIII'),
		'32be': struct.Struct('>IIIIIIIIII'),
		'64le': struct.Struct('<IIQQQQIIQQ'),
		'64be': struct.Struct('>IIQQQQIIQQ'),
	}
}

class Elf:
	def __init__(self, bytes):
		self.bytes = bytearray(bytes)
		self.extract_ident()
		bits = '64' if self.ident.elf_class == ElfClass.ELFCLASS64 else '32'
		#bits = '64' if ElfClass[self.ident.elf_class] == ElfClass.ELFCLASS64 else '32'
		endianness = 'le' if self.ident.elf_data == ElfData.ELFDATA2LSB else 'be'
		#endianness = 'le' if ElfData[self.ident.elf_data] == ElfData.ELFDATA2LSB else 'be'
		self.type = bits + endianness
		self.new_sections = []

	def _get_struct(self, cls):
		s = struct_coders[cls.__name__]
		return s[self.type] if isinstance(s, dict) else s

	def _dump_struct(self, cls, off):
		s = self._get_struct(cls)
		# unpack_from doesn't work with jython
		# return cls(s.unpack_from(self.bytes, off), file_offset=off)
		bb = self.bytes[off:off+s.size]
		return cls(s.unpack(str(bb)), file_offset=off)

	def _export_struct(self, val, off):
		s = self._get_struct(val.__class__)
		# unpack_into doesn't work with jython
		# s.pack_into(self.bytes, off, *val.values)
		self.bytes[off:off+s.size] = s.pack(*val.values)

	def extract_ident(self):
		if hasattr(self, 'ident'):
			return self.ident
		self.ident = self._dump_struct(ElfIdent, 0)
		self.header_off = self._get_struct(ElfIdent).size
		return self.ident

	def extract_header(self):
		if hasattr(self, 'header'):
			return self.header
		self.header = self._dump_struct(ElfHeader, self.header_off)
		return self.header

	def extract_section_headers(self):
		if hasattr(self, 'section_headers'):
			return self.section_headers

		self.section_headers = []
		h = self.extract_header()
		for i in range(h.shnum):
			self.section_headers.append(self._dump_struct(ElfSectionHeader, h.shoff + i * h.shentsize))
		self.section_names = self.extract_section(self.section_headers[h.shstrndx])
		for s in self.section_headers:
			s.name = self.section_names[s.name_offset:self.section_names.find('\x00', s.name_offset)]
		return self.section_headers

	def extract_section(self, section_header):
		return self.bytes[section_header.offset:section_header.offset+section_header.section_size]

	def encode_section_header(self, section_header):
		return self._get_struct(ElfSectionHeader).pack(*section_header.values)

	def add_section(self, name, body):
		self.new_sections.append((name, body))

	def generate_updated_elf(self):
		section_headers = self.extract_section_headers()
		added_sections = False
		for name, body in self.new_sections:
			try:
				s = next(s for s in section_headers if s.name == name)
			except:
				added_sections = True
				name_off = len(self.section_names)
				self.section_names += name + '\x00'
				s = ElfSectionHeader([name_off, 1, 0, 0, -1, -1, 0, 0, 1, 0], file_offset=-1)
				s.name = name
				section_headers.append(s)
			s.offset = len(self.bytes)
			s.section_size = len(body)
			self.bytes += body

		h = self.header
		if added_sections:
			shstr = section_headers[h.shstrndx]
			shstr.section_size = len(self.section_names)
			shstr.offset = len(self.bytes)
			self.bytes += self.section_names
			h.shoff = len(self.bytes)
			h.shnum = len(section_headers)
			self.bytes += '\x00' * h.shentsize * h.shnum

		self._export_struct(h, self.header_off)
		for i, s in enumerate(section_headers):
			s.file_offset = h.shoff + i * h.shentsize
			self._export_struct(s, s.file_offset)

		return self.bytes

def add_sections_to_elf(from_file, to_file, sections):
	with open(from_file, 'rb') as f:
		bb = f.read()
	e = Elf(bb)

	for name, s in sections:
		e.add_section(name, s)
	out = e.generate_updated_elf()
	with open(to_file, 'wb') as f:
		f.write(out)


class DumbEnumValue:
	def __init__(self, name, code, desc): self.name, self.code, self.desc = name, code, desc
	def __repr__(self): return '%s(%r, %r)' % (self.name, self.code, self.desc)

class DumbEnum(object):
	class __metaclass__(type):
		def __init__(cls, *args):
			cls._bycode = {}
			for n in dir(cls):
				if n[0] != '_':
					v = DumbEnumValue(n, *getattr(cls, n))
					setattr(cls, n, v)
					cls._bycode[v.code] = v
		def __getitem__(cls, idx):
			try:
				return cls._bycode[idx]
			except KeyError:
				return DumbEnumValue("%s_%s" % (cls.__name__, idx), idx, "Unknown entry %d" % idx)


# All the constants are parsed from https://github.com/slorquet/elffile2/blob/master/elffile.py
class ElfClass(DumbEnum):
	"""
	Encodes the word size of the elf file as from the `ident portion
	of the ELF file header
	<http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.
	This encodes :py:attr:`ElfFileIdent.elfClass`.
	"""
	ELFCLASSNONE = 0, 'Invalid class'
	ELFCLASS32 = 1, '32-bit objects'
	ELFCLASS64 = 2, '64-bit objects'
	ELFCLASSNUM = 3, ''          # from libelf

class ElfData(DumbEnum):
	"""
	Encodes the byte-wise endianness of the elf file as from the
	`ident portion of the elf file header
	<http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.
	This encodes :py:attr:`ElfFileIdent.elfData`.
	"""
	ELFDATANONE = 0, 'Invalid data encoding'
	ELFDATA2LSB = 1, 'least significant byte first'
	ELFDATA2MSB = 2, 'most significant byte first'
	ELFDATANUM = 3, ''

class EV(DumbEnum):
	"""
	Encodes the elf file format version of this elf file as from the `ident portion of the elf file
	header
	<http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.
	"""
	EV_NONE = 0, 'Invalid version'
	EV_CURRENT = 1, 'Current version'
	EV_NUM = 2, ''

class ElfOsabi(DumbEnum):
	"""
	Encodes OSABI values which represent operating system ELF format
	extensions as from the `'ident' portion of the elf file header
	<http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.

	This encodes :py:attr:`ElfFileIdent.osabi`.
	"""
	ELFOSABI_NONE = 0, 'No extensions or unspecified'
	ELFOSABI_SYSV = 0, 'No extensions or unspecified'
	ELFOSABI_HPUX = 1, 'Hewlett-Packard HP-UX'
	ELFOSABI_NETBSD = 2, 'NetBSD'
	ELFOSABI_LINUX = 3, 'Linux'
	ELFOSABI_SOLARIS = 6, 'Sun Solaris'
	ELFOSABI_AIX = 7, 'AIX'
	ELFOSABI_IRIX = 8, 'IRIX'
	ELFOSABI_FREEBSD = 9, 'FreeBSD'
	ELFOSABI_TRU64 = 10, 'Compaq TRU64 UNIX'
	ELFOSABI_MODESTO = 11, 'Novell Modesto'
	ELFOSABI_OPENBSD = 12, 'Open BSD'
	ELFOSABI_OPENVMS = 13, 'Open VMS'
	ELFOSABI_NSK = 14, 'Hewlett-Packard Non-Stop Kernel'
	ELFOSABI_AROS = 15, 'Amiga Research OS'
	ELFOSABI_FENIXOS = 16, 'The FenixOS highly scalable multi-core OS'
	ELFOSABI_ARM_EABI = 64, 'ARM EABI'
	ELFOSABI_ARM = 97, 'ARM'
	ELFOSABI_STANDALONE = 255, 'Standalone (embedded) application'

class ET(DumbEnum):
	"""
	Encodes the type of this elf file, (relocatable, executable,
	shared library, etc.), as represented in the `ELF file header
	<http://www.sco.com/developers/gabi/latest/ch4.eheader.html>`_.
	This encodes :py:attr:`ElfFileHeader.type`.
	"""
	ET_NONE = 0, 'No file type'
	ET_REL = 1, 'Relocatable file'
	ET_EXEC = 2, 'Executable file'
	ET_DYN = 3, 'Shared object file'
	ET_CORE = 4, 'Core file'
	ET_NUM = 5, ''
	ET_LOOS = 0xfe00, 'Operating system-specific'
	ET_HIOS = 0xfeff, 'Operating system-specific'
	ET_LOPROC = 0xff00, 'Processor-specific'
	ET_HIPROC = 0xffff, 'Processor-specific'

class EM(DumbEnum):
	"""
	Encodes the processor type represented in this elf file as
	recorded in the `ELF file header <http://www.sco.com/developers/gabi/latest/ch4.eheader.html>`_.

	This encodes :py:attr:`ElfFileHeader.machine`.
	"""
	EM_NONE = 0, 'No machine'
	EM_M32 = 1, 'AT&T WE 32100'
	EM_SPARC = 2, 'SPARC'
	EM_386 = 3, 'Intel 80386'
	EM_68K = 4, 'Motorola 68000'
	EM_88K = 5, 'Motorola 88000'
	EM_486 = 6, 'Reserved for future use (was EM_486)'
	EM_860 = 7, 'Intel 80860'
	EM_MIPS = 8, 'MIPS I Architecture'
	EM_S370 = 9, 'IBM System/370 Processor'
	EM_MIPS_RS3_LE = 10, 'MIPS RS3000 Little-endian'
	# 11 - 14 reserved
	EM_PARISC = 15, 'Hewlett-Packard PA-RISC'
	# 16 reserved
	EM_VPP500 = 17, 'Fujitsu VPP500'
	EM_SPARC32PLUS = 18, 'Enhanced instruction set SPARC'
	EM_960 = 19, 'Intel 80960'
	EM_PPC = 20, 'PowerPC'
	EM_PPC64 = 21, '64-bit PowerPC'
	EM_S390 = 22, 'IBM System/390 Processor'
	EM_SPU = 23, 'IBM SPU/SPC'
	# 24 - 35 reserved
	EM_V800 = 36, 'NEC V800'
	EM_FR20 = 37, 'Fujitsu FR20'
	EM_RH32 = 38, 'TRW RH-32'
	EM_RCE = 39, 'Motorola RCE'
	EM_ARM = 40, 'Advanced RISC Machines ARM'
	EM_ALPHA = 41, 'Digital Alpha'
	EM_SH = 42, 'Hitachi SH'
	EM_SPARCV9 = 43, 'SPARC Version 9'
	EM_TRICORE = 44, 'Siemens TriCore embedded processor'
	EM_ARC = 45, 'Argonaut RISC Core, Argonaut Technologies Inc.'
	EM_H8_300 = 46, 'Hitachi H8/300'
	EM_H8_300H = 47, 'Hitachi H8/300H'
	EM_H8S = 48, 'Hitachi H8S'
	EM_H8_500 = 49, 'Hitachi H8/500'
	EM_IA_64 = 50, 'Intel IA-64 processor architecture'
	EM_MIPS_X = 51, 'Stanford MIPS-X'
	EM_COLDFIRE = 52, 'Motorola ColdFire'
	EM_68HC12 = 53, 'Motorola M68HC12'
	EM_MMA = 54, 'Fujitsu MMA Multimedia Accelerator'
	EM_PCP = 55, 'Siemens PCP'
	EM_NCPU = 56, 'Sony nCPU embedded RISC processor'
	EM_NDR1 = 57, 'Denso NDR1 microprocessor'
	EM_STARCORE = 58, 'Motorola Star*Core processor'
	EM_ME16 = 59, 'Toyota ME16 processor'
	EM_ST100 = 60, 'STMicroelectronics ST100 processor'
	EM_TINYJ = 61, 'Advanced Logic Corp. TinyJ embedded processor family'
	EM_X86_64 = 62, 'AMD x86-64 architecture'
	EM_PDSP = 63, 'Sony DSP Processor'
	EM_PDP10 = 64, 'Digital Equipment Corp. PDP-10'
	EM_PDP11 = 65, 'Digital Equipment Corp. PDP-11'
	EM_FX66 = 66, 'Siemens FX66 microcontroller'
	EM_ST9PLUS = 67, 'STMicroelectronics ST9+ 8/16 bit microcontroller'
	EM_ST7 = 68, 'STMicroelectronics ST7 8-bit microcontroller'
	EM_68HC16 = 69, 'Motorola MC68HC16 Microcontroller'
	EM_68HC11 = 70, 'Motorola MC68HC11 Microcontroller'
	EM_68HC08 = 71, 'Motorola MC68HC08 Microcontroller'
	EM_68HC05 = 72, 'Motorola MC68HC05 Microcontroller'
	EM_SVX = 73, 'Silicon Graphics SVx'
	EM_ST19 = 74, 'STMicroelectronics ST19 8-bit microcontroller'
	EM_VAX = 75, 'Digital VAX'
	EM_CRIS = 76, 'Axis Communications 32-bit embedded processor'
	EM_JAVELIN = 77, 'Infineon Technologies 32-bit embedded processor'
	EM_FIREPATH = 78, 'Element 14 64-bit DSP Processor'
	EM_ZSP = 79, 'LSI Logic 16-bit DSP Processor'
	EM_MMIX = 80, 'Donald Knuth\'s educational 64-bit processor'
	EM_HUANY = 81, 'Harvard University machine-independent object files'
	EM_PRISM = 82, 'SiTera Prism'
	EM_AVR = 83, 'Atmel AVR 8-bit microcontroller'
	EM_FR30 = 84, 'Fujitsu FR30'
	EM_D10V = 85, 'Mitsubishi D10V'
	EM_D30V = 86, 'Mitsubishi D30V'
	EM_V850 = 87, 'NEC v850'
	EM_M32R = 88, 'Mitsubishi M32R'
	EM_MN10300 = 89, 'Matsushita MN10300'
	EM_MN10200 = 90, 'Matsushita MN10200'
	EM_PJ = 91, 'picoJava'
	EM_OPENRISC = 92, 'OpenRISC 32-bit embedded processor'
	EM_ARC_COMPACT = 93, 'ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)'
	EM_XTENSA = 94, 'Tensilica Xtensa Architecture'
	EM_VIDEOCORE = 95, 'Alphamosaic VideoCore processor'
	EM_TMM_GPP = 96, 'Thompson Multimedia General Purpose Processor'
	EM_NS32K = 97, 'National Semiconductor 32000 series'
	EM_TPC = 98, 'Tenor Network TPC processor'
	EM_SNP1K = 99, 'Trebia SNP 1000 processor'
	EM_ST200 = 100, 'STMicroelectronics (www.st.com) ST200 microcontroller'
	EM_IP2K = 101, 'Ubicom IP2xxx microcontroller family'
	EM_MAX = 102, 'MAX Processor'
	EM_CR = 103, 'National Semiconductor CompactRISC microprocessor'
	EM_F2MC16 = 104, 'Fujitsu F2MC16'
	EM_MSP430 = 105, 'Texas Instruments embedded microcontroller msp430'
	EM_BLACKFIN = 106, 'Analog Devices Blackfin (DSP) processor'
	EM_SE_C33 = 107, 'S1C33 Family of Seiko Epson processors'
	EM_SEP = 108, 'Sharp embedded microprocessor'
	EM_ARCA = 109, 'Arca RISC Microprocessor'
	EM_UNICORE = 110, 'Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University'
	EM_EXCESS = 111, 'eXcess: 16/32/64-bit configurable embedded CPU'
	EM_DXP = 112, 'Icera Semiconductor Inc. Deep Execution Processor'
	EM_ALTERA_NIOS2 = 113, 'Altera Nios II soft-core processor'
	EM_CRX = 114, 'National Semiconductor CompactRISC CRX microprocessor'
	EM_XGATE = 115, 'Motorola XGATE embedded processor'
	EM_C166 = 116, 'Infineon C16x/XC16x processor'
	EM_M16C = 117, 'Renesas M16C series microprocessors'
	EM_DSPIC30F = 118, 'Microchip Technology dsPIC30F Digital Signal Controller'
	EM_CE = 119, 'Freescale Communication Engine RISC core'
	EM_M32C = 120, 'Renesas M32C series microprocessors'
	# 121 - 130 reserved
	EM_TSK3000 = 131, 'Altium TSK3000 core'
	EM_RS08 = 132, 'Freescale RS08 embedded processor'
	# 133 reserved
	EM_ECOG2 = 134, 'Cyan Technology eCOG2 microprocessor'
	EM_SCORE7 = 135, 'Sunplus S+core7 RISC processor'
	EM_DSP24 = 136, 'New Japan Radio (NJR) 24-bit DSP Processor'
	EM_VIDEOCORE3 = 137, 'Broadcom VideoCore III processor'
	EM_LATTICEMICO32 = 138, 'RISC processor for Lattice FPGA architecture'
	EM_SE_C17 = 139, 'Seiko Epson C17 family'
	EM_TI_C6000 = 140, 'The Texas Instruments TMS320C6000 DSP family'
	EM_TI_C2000 = 141, 'The Texas Instruments TMS320C2000 DSP family'
	EM_TI_C5500 = 142, 'The Texas Instruments TMS320C55x DSP family'
	# 143 - 159 reserved
	EM_MMDSP_PLUS = 160, 'STMicroelectronics 64bit VLIW Data Signal Processor'
	EM_CYPRESS_M8C = 161, 'Cypress M8C microprocessor'
	EM_R32C = 162, 'Renesas R32C series microprocessors'
	EM_TRIMEDIA = 163, 'NXP Semiconductors TriMedia architecture family'
	EM_QDSP6 = 164, 'QUALCOMM DSP6 Processor'
	EM_8051 = 165, 'Intel 8051 and variants'
	EM_STXP7X = 166, 'STMicroelectronics STxP7x family of configurable and extensible RISC processors'
	EM_NDS32 = 167, 'Andes Technology compact code size embedded RISC processor family'
	EM_ECOG1 = 168, 'Cyan Technology eCOG1X family'
	EM_ECOG1X = 168, 'Cyan Technology eCOG1X family'
	EM_MAXQ30 = 169, 'Dallas Semiconductor MAXQ30 Core Micro-controllers'
	EM_XIMO16 = 170, 'New Japan Radio (NJR) 16-bit DSP Processor'
	EM_MANIK = 171, 'M2000 Reconfigurable RISC Microprocessor'
	EM_CRAYNV2 = 172, 'Cray Inc. NV2 vector architecture'
	EM_RX = 173, 'Renesas RX family'
	EM_METAG = 174, 'Imagination Technologies META processor architecture'
	EM_MCST_ELBRUS = 175, 'MCST Elbrus general purpose hardware architecture'
	EM_ECOG16 = 176, 'Cyan Technology eCOG16 family'
	EM_CR16 = 177, 'National Semiconductor CompactRISC CR16 16-bit microprocessor'
	EM_ETPU = 178, 'Freescale Extended Time Processing Unit'
	EM_SLE9X = 179, 'Infineon Technologies SLE9X core'
	# 180-182 Reserved for future Intel use
	# 183-184 Reserved for future ARM use
	EM_AVR32 = 185, 'Atmel Corporation 32-bit microprocessor family'
	EM_STM8 = 186, 'STMicroeletronics STM8 8-bit microcontroller'
	EM_TILE64 = 187, 'Tilera TILE64 multicore architecture family'
	EM_TILEPRO = 188, 'Tilera TILEPro multicore architecture family'
	EM_MICROBLAZE = 189, 'Xilinx MicroBlaze 32-bit RISC soft processor core'
	EM_CUDA = 190, 'NVIDIA CUDA architecture'
	EM_TILEGX = 191, 'Tilera TILE-Gx multicore architecture family'
	EM_CLOUDSHIELD = 192, 'CloudShield architecture family'
	EM_COREA_1ST = 193, 'KIPO-KAIST Core-A 1st generation processor family'
	EM_COREA_2ND = 194, 'KIPO-KAIST Core-A 2nd generation processor family'

class SHN(DumbEnum):
	"""
	Encodes special section indices into the section header table.

	This is a subclass of :py:class:`coding.Coding`.
	"""
	SHN_UNDEF = 0, 'marks an undefined, missing, irrelevant, or otherwise meaningless section reference'
	SHN_LORESERVE = 0xff00, 'specifies the lower bound of the range of reserved indexes'
	SHN_BEFORE = 0xff00, 'Order section before all others (Solaris).'
	SHN_LOPROC = 0xff00, ''
	SHN_AFTER = 0xff01, 'Order section after all others (Solaris).'
	SHN_HIPROC = 0xff1f, ''
	SHN_LOOS = 0xff20, ''
	SHN_HIOS = 0xff3f, ''
	SHN_ABS = 0xfff1, 'specifies absolute values for the corresponding reference'
	SHN_COMMON = 0xfff2, 'symbols defined relative to this section are common symbols, such as FORTRAN COMMON or unallocated C external variables.'
	SHN_XINDEX = 0xffff, 'This value is an escape value. It indicates that the actual section header index is too large to fit in the containing field and is to be found in another location (specific to the structure where it appears). '
	SHN_HIRESERVE = 0xffff, 'specifies the upper bound of the range of reserved indexes'

class SHT(DumbEnum):
	"""
	Encodes the type of a section as represented in the section header
	entry of `the section header table
	<http://www.sco.com/developers/gabi/latest/ch4.sheader.html#section_header>`_.

	This encodes :py:attr:`ElfSectionHeader.type`.
	"""
	SHT_NULL = 0, 'marks the section header as inactive; it does not have an associated section. Other members of the section header have undefined values.'
	SHT_PROGBITS = 1, 'The section holds information defined by the program, whose format and meaning are determined solely by the program.'
	SHT_SYMTAB = 2, 'provides symbols for link editing, though it may also be used for dynamic linking.'
	SHT_STRTAB = 3, 'section holds a string table. An object file may have multiple string table sections.'
	SHT_RELA = 4, 'section holds relocation entries with explicit addends, such as type Elf32_Rela for the 32-bit class of object files or type Elf64_Rela for the 64-bit class of object files.'
	SHT_HASH = 5, 'section holds a symbol hash table'
	SHT_DYNAMIC = 6, 'section holds information for dynamic linking'
	SHT_NOTE = 7, 'section holds information that marks the file in some way'
	SHT_NOBITS = 8, 'A section of this type occupies no space in the file but otherwise resembles SHT_PROGBITS'
	SHT_REL = 9, 'section holds relocation entries without explicit addends'
	SHT_SHLIB = 10, 'section type is reserved but has unspecified semantics'
	SHT_DYNSYM = 11, 'holds a minimal set of dynamic linking symbols,'
	SHT_INIT_ARRAY = 14, 'section contains an array of pointers to initialization functions'
	SHT_FINI_ARRAY = 15, 'section contains an array of pointers to termination functions'
	SHT_PREINIT_ARRAY = 16, 'section contains an array of pointers to functions that are invoked before all other initialization functions'
	SHT_GROUP = 17, 'section defines a section group'
	SHT_SYMTAB_SHNDX = 18, 'section is associated with a section of type SHT_SYMTAB and is required if any of the section header indexes referenced by that symbol table contain the escape value SHN_XINDEX'
	SHT_LOOS = 0x60000000, ''
	SHT_GNU_ATTRIBUTES = 0x6ffffff5, 'Object attributes.'
	SHT_GNU_HASH = 0x6ffffff6, 'GNU-style hash table.'
	SHT_GNU_LIBLIST = 0x6ffffff7, 'Prelink library lis'
	SHT_CHECKSUM = 0x6ffffff8, 'Checksum for DSO content.'
	SHT_LOSUNW = 0x6ffffffa, 'Sun-specific low bound.'
	SHT_SUNW_move = 0x6ffffffa, 'efine SHT_SUNW_COMDAT'
	SHT_SUNW_COMDAT = 0x6ffffffb, ''
	SHT_SUNW_syminfo = 0x6ffffffc, ''
	SHT_GNU_verdef = 0x6ffffffd, 'Version definition section.'
	SHT_GNU_verneed = 0x6ffffffe, 'Version needs section.'
	SHT_GNU_versym = 0x6fffffff, 'Version symbol table.'
	SHT_HISUNW = 0x6fffffff, 'Sun-specific high bound.'
	SHT_HIOS = 0x6fffffff, ''
	SHT_LOPROC = 0x70000000, ''
	SHT_HIPROC = 0x7fffffff, ''
	SHT_LOUSER = 0x80000000, ''
	SHT_HIUSER = 0xffffffff, ''

class SHF(DumbEnum):
	"""
	Encodes the section flags as represented in the section header
	entry of `the section header table
	<http://www.sco.com/developers/gabi/latest/ch4.sheader.html#section_header>`_.

	This encodes :py:attr:`ElfSectionHeader.flags`.  These are bit flags which are
	or'd together.
	"""
	SHF_WRITE = 0x1, 'section contains data that should be writable during process execution'
	SHF_ALLOC = 0x2, 'section occupies memory during process execution'
	SHF_EXECINSTR = 0x4, 'section contains executable machine instructions'
	SHF_MERGE = 0x10, 'data in the section may be merged to eliminate duplication'
	SHF_STRINGS = 0x20, 'data elements in the section consist of null-terminated character strings'
	SHF_INFO_LINK = 0x40, 'The sh_info field of this section header holds a section header table index'
	SHF_LINK_ORDER = 0x80, 'adds special ordering requirements for link editors'
	SHF_OS_NONCONFORMING = 0x100, 'section requires special OS-specific processing'
	SHF_GROUP = 0x200, 'section is a member of a section group'
	SHF_TLS = 0x400, 'section holds Thread-Local Storage'
	SHF_MASKOS = 0x0ff00000, 'All bits included in this mask are reserved for operating system-specific semantics'
	SHF_MASKPROC = 0xf0000000, 'All bits included in this mask are reserved for processor-specific semantics'
	SHF_ORDERED = (1 << 30), 'Special ordering requirement (Solaris).'
	SHF_EXCLUDE = (1 << 31), 'Section is excluded unless referenced or allocated (Solaris).'

class PT(DumbEnum):
	"""
	Encodes the segment type as recorded in the `program header
	<http://www.sco.com/developers/gabi/latest/ch5.pheader.html>`_.

	This encodes :py:attr:`ElfProgramHeader.type`.
	"""
	PT_NULL = 0, 'array element is unused'
	PT_LOAD = 1, 'array element specifies a loadable segment'
	PT_DYNAMIC = 2, 'array element specifies dynamic linking information'
	PT_INTERP = 3, 'array element specifies the location and size of a null-terminated path name to invoke as an interpreter'
	PT_NOTE = 4, 'array element specifies the location and size of auxiliary information'
	PT_SHLIB = 5, 'segment type is reserved'
	PT_PHDR = 6, 'specifies the location and size of the program header table itself'
	PT_TLS = 7, 'array element specifies the Thread-Local Storage template'
	PT_LOOS = 0x60000000, ''
	PT_GNU_EH_FRAME = 0x6474e550, 'GCC .eh_frame_hdr segment'
	PT_GNU_STACK = 0x6474e551, 'Indicates stack executability'
	PT_GNU_RELRO = 0x6474e552, 'Read only after relocation'
	PT_LOSUNW = 0x6ffffffa, ''
	PT_SUNWBSS = 0x6ffffffa, 'Sun Specific segment'
	PT_SUNWSTACK = 0x6ffffffb, 'Stack segment'
	PT_HISUNW = 0x6fffffff, ''
	PT_HIOS = 0x6fffffff, ''
	PT_LOPROC = 0x70000000, ''
	PT_HIPROC = 0x7fffffff, ''

class PF(DumbEnum):
	"""
	Encodes the segment flags as recorded in the `program header
	<http://www.sco.com/developers/gabi/latest/ch5.pheader.html>`_.

	This encodes :py:attr:`ElfProgramHeader.flags`.
	"""
	PF_X = 0x1, 'Execute'
	PF_W = 0x2, 'Write'
	PF_R = 0x4, 'Read'
	PF_MASKOS = 0x0ff00000, 'Unspecified'
	PF_MASKPROC = 0xf0000000, 'Unspecified'

class GRP(DumbEnum):
	GRP_COMDAT = 0x1, 'This is a COMDAT group'
	GRP_MASKOS = 0x0ff00000, 'All bits included in this mask are reserved for operating system-specific semantics'
	GRP_MASKPROC = 0xf0000000, 'All bits included in this mask are reserved for processor-specific semantics'

if __name__ == '__main__':
	from sys import argv
	from glob import glob

	from_file = argv[1]
	to_file = argv[2]
	section_names = argv[3:]
	sections = [(n, open(n, 'rb').read()) for nu in section_names for n in glob(nu)]
	add_sections_to_elf(from_file, to_file, sections)
