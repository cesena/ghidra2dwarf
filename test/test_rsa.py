#!/usr/bin/env python3

from util import Gdb

def test_function():
    gdb = Gdb("binaries", "rsa_dbg")
    gdb.breakpoint(434)
    gdb.execute_mi("-exec-run")

    assert 0xc5 == gdb.get_int("local_ac0")
    assert "local_abf = 0xd6;" == gdb.get_line(434)

    gdb.execute_gdb("n")
    assert 0xd6 == gdb.get_int("local_abf")
