#!/usr/bin/env python3

from util import *


def test_function():
    init("./rsa_dbg")
    execute_cmd("-break-insert 434")
    execute_cmd("-exec-run")

    assert 0xC5 == get_int("local_ac0")
    assert "local_abf = 0xd6;" == get_line(434)

    execute_cmd("n")
    assert 0xD6 == get_int("local_abf")
