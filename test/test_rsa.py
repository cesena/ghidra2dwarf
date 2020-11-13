#!/usr/bin/env python3

from util import Gdb


def test_function():
    gdb = Gdb("binaries", "rsa_dbg", debug=False)
    gdb.breakpoint(434)
    gdb.run()

    assert 0xC5 == gdb.get_int("local_ac0")
    assert "local_abf = 0xd6;" == gdb.get_line(434)

    gdb.execute_raw("n")
    assert 0xD6 == gdb.get_int("local_abf")
