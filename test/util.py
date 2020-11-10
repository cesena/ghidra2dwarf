#!/usr/bin/env python3

from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import re
import pytest

gdbmi = GdbController()

get_payload = lambda x: x[1]["payload"]


def execute_cmd(cmd: str, debug=False) -> list:
    response = gdbmi.write(cmd)
    if debug:
        pprint(response)
    return response


def get_struct(var: str) -> dict:
    _, payload = get_payload(execute_cmd(f"print {var}")).split("{")
    values = payload.split(", ")
    d = {}
    for v in values:
        key, value = v.split(" = ")
        if v == values[-1]:
            value = value.replace("}\\n", "")
        d[key] = value
    return d


def get_int(var: str) -> int:
    value = get_payload(execute_cmd(f"print {var}")).replace("\\n", "")
    return int(value.split(" = ")[1])


def get_line(line: int) -> str:
    res = execute_cmd(f"list {line}")
    _, payload = get_payload(res).split(f"{line}\\t")
    return payload.replace("\\n", "").strip()
