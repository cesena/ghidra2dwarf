package libdwarf;
import com.sun.jna.Callback;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

public interface LibdwarfLibrary extends Library {
	public static final LibdwarfLibrary INSTANCE = (LibdwarfLibrary)Native.loadLibrary(Platform.isWindows() ? "libdwarf" : "dwarf", LibdwarfLibrary.class);

	// functions
	String dwarf_errmsg(LibdwarfLibrary.Dwarf_Error Dwarf_Error1);
	String dwarf_errmsg_by_number(long Dwarf_Unsigned1);
	int dwarf_producer_init(long Dwarf_Unsigned1, LibdwarfLibrary.Dwarf_Callback_Func Dwarf_Callback_Func1, LibdwarfLibrary.Dwarf_Handler Dwarf_Handler1, Pointer Dwarf_Ptr1, Pointer voidPtr1, String isa_name, String dwarf_version, String extra, PointerByReference Dwarf_P_DebugPtr1, PointerByReference Dwarf_ErrorPtr1);
	int dwarf_pro_set_default_string_form(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, int int1, PointerByReference Dwarf_ErrorPtr1);
	long dwarf_transform_to_disk_form(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, PointerByReference Dwarf_ErrorPtr1);
	Pointer dwarf_get_section_bytes(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, long Dwarf_Signed1, LongByReference Dwarf_SignedPtr1, LongByReference Dwarf_UnsignedPtr1, PointerByReference Dwarf_ErrorPtr1);
	int dwarf_producer_finish_a(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, PointerByReference Dwarf_ErrorPtr1);
	LibdwarfLibrary.Dwarf_P_Attribute dwarf_add_AT_targ_address(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die1, short Dwarf_Half1, long Dwarf_Unsigned1, long Dwarf_Signed1, PointerByReference Dwarf_ErrorPtr1);
	LibdwarfLibrary.Dwarf_P_Attribute dwarf_add_AT_unsigned_const(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die1, short Dwarf_Half1, long Dwarf_Unsigned1, PointerByReference Dwarf_ErrorPtr1);
	LibdwarfLibrary.Dwarf_P_Attribute dwarf_add_AT_reference(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die1, short Dwarf_Half1, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die2, PointerByReference Dwarf_ErrorPtr1);
	LibdwarfLibrary.Dwarf_P_Attribute dwarf_add_AT_location_expr(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die1, short Dwarf_Half1, LibdwarfLibrary.Dwarf_P_Expr Dwarf_P_Expr1, PointerByReference Dwarf_ErrorPtr1);
	LibdwarfLibrary.Dwarf_P_Attribute dwarf_add_AT_string(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die1, short Dwarf_Half1, String charPtr1, PointerByReference Dwarf_ErrorPtr1);
	LibdwarfLibrary.Dwarf_P_Attribute dwarf_add_AT_comp_dir(LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die1, String charPtr1, PointerByReference Dwarf_ErrorPtr1);
	LibdwarfLibrary.Dwarf_P_Attribute dwarf_add_AT_name(LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die1, String charPtr1, PointerByReference Dwarf_ErrorPtr1);
	long dwarf_add_directory_decl(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, String charPtr1, PointerByReference Dwarf_ErrorPtr1);
	long dwarf_add_file_decl(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, String charPtr1, long Dwarf_Unsigned1, long Dwarf_Unsigned2, long Dwarf_Unsigned3, PointerByReference Dwarf_ErrorPtr1);
	long dwarf_add_line_entry(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, long Dwarf_Unsigned1, long Dwarf_Addr1, long Dwarf_Unsigned2, long Dwarf_Signed1, int Dwarf_Bool1, int Dwarf_Bool2, PointerByReference Dwarf_ErrorPtr1);
	long dwarf_lne_set_address(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, long Dwarf_Unsigned1, long Dwarf_Unsigned2, PointerByReference Dwarf_ErrorPtr1);
	LibdwarfLibrary.Dwarf_P_Die dwarf_new_die(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, long Dwarf_Tag1, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die1, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die2, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die3, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die4, PointerByReference Dwarf_ErrorPtr1);
	int dwarf_add_die_to_debug_a(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, LibdwarfLibrary.Dwarf_P_Die Dwarf_P_Die1, PointerByReference Dwarf_ErrorPtr1);
	LibdwarfLibrary.Dwarf_P_Expr dwarf_new_expr(LibdwarfLibrary.Dwarf_P_Debug Dwarf_P_Debug1, PointerByReference Dwarf_ErrorPtr1);
	long dwarf_add_expr_gen(LibdwarfLibrary.Dwarf_P_Expr Dwarf_P_Expr1, byte Dwarf_Small1, long Dwarf_Unsigned1, long Dwarf_Unsigned2, PointerByReference Dwarf_ErrorPtr1);
	long dwarf_add_expr_addr_b(LibdwarfLibrary.Dwarf_P_Expr Dwarf_P_Expr1, long Dwarf_Unsigned1, long Dwarf_Unsigned2, PointerByReference Dwarf_ErrorPtr1);
	
	// callbacks
	public interface Dwarf_Handler extends Callback {
		void apply(Pointer Dwarf_Error1, Pointer Dwarf_Ptr1);
	};
	public interface Dwarf_Callback_Func extends Callback {
		int apply(Pointer charPtr1, int int1, long Dwarf_Unsigned1, long Dwarf_Unsigned2, long Dwarf_Unsigned3, long Dwarf_Unsigned4, LongByReference Dwarf_UnsignedPtr1, Pointer voidPtr1, IntByReference intPtr1);
	};

	// classes
	public static class Dwarf_P_Debug extends PointerType {
		public Dwarf_P_Debug(Pointer address) {
			super(address);
		}
		public Dwarf_P_Debug() {
			super();
		}
	};
	public static class Dwarf_P_Expr extends PointerType {
		public Dwarf_P_Expr(Pointer address) {
			super(address);
		}
		public Dwarf_P_Expr() {
			super();
		}
	};
	public static class Dwarf_Error extends PointerType {
		public Dwarf_Error(Pointer address) {
			super(address);
		}
		public Dwarf_Error() {
			super();
		}
	};
	public static class Dwarf_P_Die extends PointerType {
		public Dwarf_P_Die(Pointer address) {
			super(address);
		}
		public Dwarf_P_Die() {
			super();
		}
	};
	public static class Dwarf_P_Attribute extends PointerType {
		public Dwarf_P_Attribute(Pointer address) {
			super(address);
		}
		public Dwarf_P_Attribute() {
			super();
		}
	};

	// constants
	public static final int DW_ATE_address = (int)0x01;
	public static final int DW_ATE_boolean = (int)0x02;
	public static final int DW_ATE_complex_float = (int)0x03;
	public static final int DW_ATE_float = (int)0x04;
	public static final int DW_ATE_signed = (int)0x05;
	public static final int DW_ATE_signed_char = (int)0x06;
	public static final int DW_ATE_unsigned = (int)0x07;
	public static final int DW_ATE_unsigned_char = (int)0x08;
	public static final int DW_AT_byte_size = (int)0x0b;
	public static final int DW_AT_const_value = (int)0x1c;
	public static final int DW_AT_count = (int)0x37;
	public static final int DW_AT_data_member_location = (int)0x38;
	public static final int DW_AT_decl_file = (int)0x3a;
	public static final int DW_AT_decl_line = (int)0x3b;
	public static final int DW_AT_encoding = (int)0x3e;
	public static final int DW_AT_frame_base = (int)0x40;
	public static final int DW_AT_high_pc = (int)0x12;
	public static final int DW_AT_linkage_name = (int)0x6e;
	public static final int DW_AT_location = (int)0x02;
	public static final int DW_AT_low_pc = (int)0x11;
	public static final int DW_AT_type = (int)0x49;
	public static final int DW_DLC_OFFSET32 = (int)0x00010000;
	public static final int DW_DLC_POINTER64 = (int)0x40000000;
	public static final int DW_DLC_SYMBOLIC_RELOCATIONS = (int)0x04000000;
	public static final int DW_DLC_TARGET_LITTLEENDIAN = (int)0x00100000;
	public static final int DW_DLC_WRITE = (int)1;
	public static final Pointer DW_DLV_BADADDR = new Pointer((long)(~0));
	public static final long DW_DLV_NOCOUNT = (long)-1;
	public static final int DW_DLV_OK = (int)0;
	public static final int DW_FORM_string = (int)0x08;
	public static final int DW_FRAME_HIGHEST_NORMAL_REGISTER = (int)188;
	public static final int DW_FRAME_LAST_REG_NUM = (int)(DW_FRAME_HIGHEST_NORMAL_REGISTER + 3);
	public static final int DW_OP_breg0 = (int)0x70;
	public static final int DW_OP_breg1 = (int)0x71;
	public static final int DW_OP_breg2 = (int)0x72;
	public static final int DW_OP_breg3 = (int)0x73;
	public static final int DW_OP_breg4 = (int)0x74;
	public static final int DW_OP_breg5 = (int)0x75;
	public static final int DW_OP_breg6 = (int)0x76;
	public static final int DW_OP_breg7 = (int)0x77;
	public static final int DW_OP_breg8 = (int)0x78;
	public static final int DW_OP_breg9 = (int)0x79;
	public static final int DW_OP_breg10 = (int)0x7a;
	public static final int DW_OP_breg11 = (int)0x7b;
	public static final int DW_OP_breg12 = (int)0x7c;
	public static final int DW_OP_breg13 = (int)0x7d;
	public static final int DW_OP_breg14 = (int)0x7e;
	public static final int DW_OP_breg15 = (int)0x7f;
	public static final int DW_OP_breg16 = (int)0x80;
	public static final int DW_OP_breg17 = (int)0x81;
	public static final int DW_OP_breg18 = (int)0x82;
	public static final int DW_OP_breg19 = (int)0x83;
	public static final int DW_OP_breg20 = (int)0x84;
	public static final int DW_OP_breg21 = (int)0x85;
	public static final int DW_OP_breg22 = (int)0x86;
	public static final int DW_OP_breg23 = (int)0x87;
	public static final int DW_OP_breg24 = (int)0x88;
	public static final int DW_OP_breg25 = (int)0x89;
	public static final int DW_OP_breg26 = (int)0x8a;
	public static final int DW_OP_breg27 = (int)0x8b;
	public static final int DW_OP_breg28 = (int)0x8c;
	public static final int DW_OP_breg29 = (int)0x8d;
	public static final int DW_OP_breg30 = (int)0x8e;
	public static final int DW_OP_breg31 = (int)0x8f;
	public static final int DW_OP_call_frame_cfa = (int)0x9c;
	public static final int DW_OP_fbreg = (int)0x91;
	public static final int DW_OP_plus_uconst = (int)0x23;
	public static final int DW_OP_regx = (int)0x90;
	public static final int DW_TAG_array_type = (int)0x01;
	public static final int DW_TAG_base_type = (int)0x24;
	public static final int DW_TAG_compile_unit = (int)0x11;
	public static final int DW_TAG_enumeration_type = (int)0x04;
	public static final int DW_TAG_enumerator = (int)0x28;
	public static final int DW_TAG_formal_parameter = (int)0x05;
	public static final int DW_TAG_member = (int)0x0d;
	public static final int DW_TAG_pointer_type = (int)0x0f;
	public static final int DW_TAG_structure_type = (int)0x13;
	public static final int DW_TAG_subprogram = (int)0x2e;
	public static final int DW_TAG_subrange_type = (int)0x21;
	public static final int DW_TAG_variable = (int)0x34;
}
