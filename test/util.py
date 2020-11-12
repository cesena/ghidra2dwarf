#!/usr/bin/env python3

from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
from itertools import dropwhile
import os


class Gdb:
    def __init__(self, directory: str, filename: str, *, debug: bool = False) -> None:
        os.chmod(os.path.join(directory, filename), 0o755)
        self.gdbmi = GdbController()
        self.debug = debug
        self.execute_raw(f"cd {directory}")
        self.execute_raw(f"-file-exec-and-symbols {filename}")
        self.execute_raw("set listsize 1")

    def execute_raw(self, cmd: str) -> list:
        self.gdbmi.write("")
        response = self.gdbmi.write(cmd)
        if self.debug:
            print("CMD:", cmd)
            pprint(response)
        return response

    def execute_mi(self, cmd: str) -> dict:
        return self.execute_raw(cmd)[0]["payload"]

    def breakpoint(self, addr: int):
        return self.execute_mi(f"-break-insert {addr}")

    def execute_gdb(self, cmd: str) -> str:
        lines = dropwhile(lambda x: x["type"] != "log", self.execute_raw(cmd))
        r = "".join(x["payload"] for x in lines if x["type"] == "console" and x["stream"] == "stdout" and x["payload"])
        r = r.encode("utf-8").decode("unicode_escape")
        if self.debug:
            print("RESP:", r)
        return r

    def create_var(self, name: str) -> dict:
        if isinstance(name, dict):
            return name
        out = self.execute_mi(f'-var-create - * "{name}"')
        return out

    def var_to_python(self, var: dict):
        t = var["type"]
        if t == "char *":
            return self.get_string(var)
        elif t[-1] == "]":
            return self.get_array(var)
        else:
            return self.get_int(var)

    def get_list_children(self, var: dict) -> list:
        # TODO: has_more?
        return self.execute_mi(f'-var-list-children {var["name"]}')["children"]

    def get_struct(self, expr: str) -> dict:
        var = self.create_var(expr)
        children = self.get_list_children(var)
        return {c["exp"]: self.var_to_python(c) for c in children}

    def get_array(self, expr: str) -> list:
        var = self.create_var(expr)
        return [self.var_to_python(c) for c in self.get_list_children(var)]

    def get_int(self, expr: str) -> int:
        var = self.create_var(expr)
        value = self.var_evaluate(var, format="hexadecimal")
        return int(value, 16)

    def get_string(self, expr: str) -> str:
        var = self.create_var(expr)
        value = self.var_evaluate(var)
        return value.split(" ", 1)[1].strip('"').encode("utf-8").decode("unicode_escape")

    def var_evaluate(self, var, *, format="natural") -> str:
        name = var["name"] if isinstance(var, dict) else var
        return self.execute_mi(f"-var-evaluate-expression -f {format} {name}")["value"]

    def get_line(self, line: int) -> str:
        res = self.execute_gdb(f"list {line}")
        _, payload = res.split(f"{line}\t")
        return payload.replace("\n", "").strip()
