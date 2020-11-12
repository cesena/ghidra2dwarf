#!/usr/bin/env python3

from util import Gdb

def test_function():
    gdb = Gdb("binaries", "passcode_dbg")
    gdb.breakpoint(193)
    gdb.breakpoint(166)

    NAME = 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
    INPUT = f'{NAME} 1 2'
    gdb.execute_gdb(f"r < <(echo {INPUT})")

    assert NAME == gdb.get_string("name")
    gdb.execute_gdb("c")

    assert 0x61616179 == gdb.get_int("passcode1")
    assert 'scanf' in gdb.get_line(166)
