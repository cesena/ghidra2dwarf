#!/bin/bash

[ ! -f src/main/resources/linux-x86-64/libdwarf.so ] && \
    curl -o src/main/resources/linux-x86-64/libdwarf.so -L --create-dirs https://github.com/cesena/libdwarf-ghidra2dwarf/releases/download/latest/libdwarf.so

[ ! -f src/main/resources/win32-x86-64/libdwarf.dll ] && \
    curl -o src/main/resources/win32-x86-64/libdwarf.dll -L --create-dirs https://github.com/cesena/libdwarf-ghidra2dwarf/releases/download/latest/libdwarf.dll

[ ! -f src/main/resources/darwin/libdwarf.dylib ] && \
    curl -o src/main/resources/darwin/libdwarf.dylib -L --create-dirs https://github.com/cesena/libdwarf-ghidra2dwarf/releases/download/latest/libdwarf.dylib

mvn package
