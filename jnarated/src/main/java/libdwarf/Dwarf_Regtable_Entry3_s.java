package libdwarf;
import com.ochafik.lang.jnaerator.runtime.Structure;
import com.sun.jna.Pointer;
import java.util.Arrays;
import java.util.List;
/**
 * This file was autogenerated by <a href="http://jnaerator.googlecode.com/">JNAerator</a>,<br>
 * a tool written by <a href="http://ochafik.com/">Olivier Chafik</a> that <a href="http://code.google.com/p/jnaerator/wiki/CreditsAndLicense">uses a few opensource projects.</a>.<br>
 * For help, please visit <a href="http://nativelibs4java.googlecode.com/">NativeLibs4Java</a> , <a href="http://rococoa.dev.java.net/">Rococoa</a>, or <a href="http://jna.dev.java.net/">JNA</a>.
 */
public class Dwarf_Regtable_Entry3_s extends Structure<Dwarf_Regtable_Entry3_s, Dwarf_Regtable_Entry3_s.ByValue, Dwarf_Regtable_Entry3_s.ByReference > {
	/**
	 * For each index i (naming a hardware register with dwarf number<br>
	 * i) the following is true and defines the value of that register:<br>
	 * If dw_regnum is Register DW_FRAME_UNDEFINED_VAL<br>
	 * it is not DWARF register number but<br>
	 * a place holder indicating the register has no defined value.<br>
	 * If dw_regnum is Register DW_FRAME_SAME_VAL<br>
	 * it  is not DWARF register number but<br>
	 * a place holder indicating the register has the same<br>
	 * value in the previous frame.<br>
	 * DW_FRAME_UNDEFINED_VAL, DW_FRAME_SAME_VAL and<br>
	 * DW_FRAME_CFA_COL3 are only present at libdwarf runtime.<br>
	 * Never on disk.<br>
	 * DW_FRAME_* Values present on disk are in dwarf.h<br>
	 * Because DW_FRAME_SAME_VAL and DW_FRAME_UNDEFINED_VAL<br>
	 * and DW_FRAME_CFA_COL3 are definable at runtime<br>
	 * consider the names symbolic in this comment, not absolute.<br>
	 * Otherwise: the register number is a DWARF register number<br>
	 * (see ABI documents for how this translates to hardware/<br>
	 * software register numbers in the machine hardware)<br>
	 * and the following applies:<br>
	 * In a cfa-defining entry (rt3_cfa_rule) the regnum is the<br>
	 * CFA 'register number'. Which is some 'normal' register,<br>
	 * not DW_FRAME_CFA_COL3, nor DW_FRAME_SAME_VAL, nor<br>
	 * DW_FRAME_UNDEFINED_VAL.<br>
	 * If dw_value_type == DW_EXPR_OFFSET (the only  possible case for<br>
	 * dwarf2):<br>
	 * If dw_offset_relevant is non-zero, then<br>
	 * the value is stored at at the address<br>
	 * CFA+N where N is a signed offset.<br>
	 * dw_regnum is the cfa register rule which means<br>
	 * one ignores dw_regnum and uses the CFA appropriately.<br>
	 * So dw_offset_or_block_len is a signed value, really,<br>
	 * and must be printed/evaluated as such.<br>
	 * Rule: Offset(N)<br>
	 * If dw_offset_relevant is zero, then the value of the register<br>
	 * is the value of (DWARF) register number dw_regnum.<br>
	 * Rule: register(R)<br>
	 * If dw_value_type  == DW_EXPR_VAL_OFFSET<br>
	 * the  value of this register is CFA +N where N is a signed offset.<br>
	 * dw_regnum is the cfa register rule which means<br>
	 * one ignores dw_regnum and uses the CFA appropriately.<br>
	 * Rule: val_offset(N)<br>
	 * If dw_value_type  == DW_EXPR_EXPRESSION<br>
	 * The value of the register is the value at the address<br>
	 * computed by evaluating the DWARF expression E.<br>
	 * Rule: expression(E)<br>
	 * The expression E byte stream is pointed to by dw_block_ptr.<br>
	 * The expression length in bytes is given by<br>
	 * dw_offset_or_block_len.<br>
	 * If dw_value_type  == DW_EXPR_VAL_EXPRESSION<br>
	 * The value of the register is the value<br>
	 * computed by evaluating the DWARF expression E.<br>
	 * Rule: val_expression(E)<br>
	 * The expression E byte stream is pointed to by dw_block_ptr.<br>
	 * The expression length in bytes is given by<br>
	 * dw_offset_or_block_len.<br>
	 * Other values of dw_value_type are an error.<br>
	 * C type : Dwarf_Small
	 */
	public byte dw_offset_relevant;
	/** C type : Dwarf_Small */
	public byte dw_value_type;
	/** C type : Dwarf_Half */
	public short dw_regnum;
	/** C type : Dwarf_Unsigned */
	public long dw_offset_or_block_len;
	/** C type : Dwarf_Ptr */
	public Pointer dw_block_ptr;
	public Dwarf_Regtable_Entry3_s() {
		super();
	}
	protected List<? > getFieldOrder() {
		return Arrays.asList("dw_offset_relevant", "dw_value_type", "dw_regnum", "dw_offset_or_block_len", "dw_block_ptr");
	}
	/**
	 * @param dw_offset_relevant For each index i (naming a hardware register with dwarf number<br>
	 * i) the following is true and defines the value of that register:<br>
	 * If dw_regnum is Register DW_FRAME_UNDEFINED_VAL<br>
	 * it is not DWARF register number but<br>
	 * a place holder indicating the register has no defined value.<br>
	 * If dw_regnum is Register DW_FRAME_SAME_VAL<br>
	 * it  is not DWARF register number but<br>
	 * a place holder indicating the register has the same<br>
	 * value in the previous frame.<br>
	 * DW_FRAME_UNDEFINED_VAL, DW_FRAME_SAME_VAL and<br>
	 * DW_FRAME_CFA_COL3 are only present at libdwarf runtime.<br>
	 * Never on disk.<br>
	 * DW_FRAME_* Values present on disk are in dwarf.h<br>
	 * Because DW_FRAME_SAME_VAL and DW_FRAME_UNDEFINED_VAL<br>
	 * and DW_FRAME_CFA_COL3 are definable at runtime<br>
	 * consider the names symbolic in this comment, not absolute.<br>
	 * Otherwise: the register number is a DWARF register number<br>
	 * (see ABI documents for how this translates to hardware/<br>
	 * software register numbers in the machine hardware)<br>
	 * and the following applies:<br>
	 * In a cfa-defining entry (rt3_cfa_rule) the regnum is the<br>
	 * CFA 'register number'. Which is some 'normal' register,<br>
	 * not DW_FRAME_CFA_COL3, nor DW_FRAME_SAME_VAL, nor<br>
	 * DW_FRAME_UNDEFINED_VAL.<br>
	 * If dw_value_type == DW_EXPR_OFFSET (the only  possible case for<br>
	 * dwarf2):<br>
	 * If dw_offset_relevant is non-zero, then<br>
	 * the value is stored at at the address<br>
	 * CFA+N where N is a signed offset.<br>
	 * dw_regnum is the cfa register rule which means<br>
	 * one ignores dw_regnum and uses the CFA appropriately.<br>
	 * So dw_offset_or_block_len is a signed value, really,<br>
	 * and must be printed/evaluated as such.<br>
	 * Rule: Offset(N)<br>
	 * If dw_offset_relevant is zero, then the value of the register<br>
	 * is the value of (DWARF) register number dw_regnum.<br>
	 * Rule: register(R)<br>
	 * If dw_value_type  == DW_EXPR_VAL_OFFSET<br>
	 * the  value of this register is CFA +N where N is a signed offset.<br>
	 * dw_regnum is the cfa register rule which means<br>
	 * one ignores dw_regnum and uses the CFA appropriately.<br>
	 * Rule: val_offset(N)<br>
	 * If dw_value_type  == DW_EXPR_EXPRESSION<br>
	 * The value of the register is the value at the address<br>
	 * computed by evaluating the DWARF expression E.<br>
	 * Rule: expression(E)<br>
	 * The expression E byte stream is pointed to by dw_block_ptr.<br>
	 * The expression length in bytes is given by<br>
	 * dw_offset_or_block_len.<br>
	 * If dw_value_type  == DW_EXPR_VAL_EXPRESSION<br>
	 * The value of the register is the value<br>
	 * computed by evaluating the DWARF expression E.<br>
	 * Rule: val_expression(E)<br>
	 * The expression E byte stream is pointed to by dw_block_ptr.<br>
	 * The expression length in bytes is given by<br>
	 * dw_offset_or_block_len.<br>
	 * Other values of dw_value_type are an error.<br>
	 * C type : Dwarf_Small<br>
	 * @param dw_value_type C type : Dwarf_Small<br>
	 * @param dw_regnum C type : Dwarf_Half<br>
	 * @param dw_offset_or_block_len C type : Dwarf_Unsigned<br>
	 * @param dw_block_ptr C type : Dwarf_Ptr
	 */
	public Dwarf_Regtable_Entry3_s(byte dw_offset_relevant, byte dw_value_type, short dw_regnum, long dw_offset_or_block_len, Pointer dw_block_ptr) {
		super();
		this.dw_offset_relevant = dw_offset_relevant;
		this.dw_value_type = dw_value_type;
		this.dw_regnum = dw_regnum;
		this.dw_offset_or_block_len = dw_offset_or_block_len;
		this.dw_block_ptr = dw_block_ptr;
	}
	protected ByReference newByReference() { return new ByReference(); }
	protected ByValue newByValue() { return new ByValue(); }
	protected Dwarf_Regtable_Entry3_s newInstance() { return new Dwarf_Regtable_Entry3_s(); }
	public static Dwarf_Regtable_Entry3_s[] newArray(int arrayLength) {
		return Structure.newArray(Dwarf_Regtable_Entry3_s.class, arrayLength);
	}
	public static class ByReference extends Dwarf_Regtable_Entry3_s implements Structure.ByReference {
		
	};
	public static class ByValue extends Dwarf_Regtable_Entry3_s implements Structure.ByValue {
		
	};
}