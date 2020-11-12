#!/usr/bin/env python3

from util import *


def test_function():
    init("./passcode_dbg")
    execute_cmd("-break-insert 193")
    execute_cmd("-break-insert 166")
    execute_cmd("r < ./passcode_input.txt")

    assert (
        0x616161796161617861616177616161766161617561616174616161736161617261616171616161706161616F6161616E6161616D6161616C6161616B6161616A616161696161616861616167616161666161616561616164616161636161616261616161
        == get_hex("name")
    )
    execute_cmd("c")

    assert 0x61616179 == get_hex("passcode1")
    assert "__isoc99_scanf(&DAT_08048783,passcode1);" == get_line(166)
