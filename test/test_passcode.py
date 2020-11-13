#!/usr/bin/env python3

from util import Gdb

def test_function():
    gdb = Gdb("binaries", "passcode_dbg", debug=True)
    gdb.breakpoint(193)
    gdb.breakpoint(166)

    NAME = 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
    INPUT = f'{NAME} 1 2'
    gdb.run(stdin=INPUT)

    assert NAME == gdb.get_string("(char *)name")
    gdb.execute_raw("c")

    assert 0x61616179 == gdb.get_int("passcode1")
    assert 'scanf' in gdb.get_line(166)
