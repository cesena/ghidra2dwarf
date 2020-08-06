import re

s = open('src/main/java/libdwarf/LibdwarfLibrary.java.old', 'rb').read()

FUNCS = [
	'dwarf_add_AT_comp_dir',
	'dwarf_add_AT_location_expr',
	'dwarf_add_AT_name',
	'dwarf_add_AT_reference',
	'dwarf_add_AT_string',
	'dwarf_add_AT_targ_address',
	'dwarf_add_AT_unsigned_const',
	'dwarf_add_die_to_debug',
	'dwarf_add_directory_decl',
	'dwarf_add_expr_addr_b',
	'dwarf_add_expr_gen',
	'dwarf_add_file_decl',
	'dwarf_add_line_entry',
	'dwarf_errmsg',
	'dwarf_get_section_bytes',
	'dwarf_lne_set_address',
	'dwarf_new_die',
	'dwarf_new_expr',
	'dwarf_pro_set_default_string_form',
	'dwarf_producer_finish',
	'dwarf_producer_init',
	'dwarf_transform_to_disk_form',
]

def rep(m):
	if m.group(1) in FUNCS:
		print m.group(1)
		return m.group(0)
	return ''

res = re.sub(r'/\*\*\n(?:\t \*.*\n)+\s+(?:@.+\s+)*\S+ (\w+)\(.+;\n', rep, s)
open('src/main/java/libdwarf/LibdwarfLibrary.java', 'wb').write(res)
