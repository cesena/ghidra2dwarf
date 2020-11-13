#!/usr/bin/env python3

from util import Gdb


def test_function():
    gdb = Gdb("binaries", "test_ghidra_dbg", debug=True)
    gdb.breakpoint(136)
    gdb.breakpoint(142)
    gdb.run()

    gdb.execute_raw("c 2")
    assert 2 == gdb.get_int("i")
    assert "i = i + 1;" == gdb.get_line(136)

    gdb.execute_raw("c 3")
    d = gdb.get_struct("*ex_2")
    assert 15 == d["x"]
    assert 20 == d["y"]
    assert "Example 1" in d["name"]

    assert 15 == gdb.get_int("ex_2->x")

    assert "print_example(ex_2);" == gdb.get_line(144)
