#!/bin/bash

if [ ! -f src/main/resources/linux-x86-64/libdwarf.so ]; then
	curl -o src/main/resources/linux-x86-64/libdwarf.so -L --create-dirs https://github.com/cesena/libdwarf-ghidra2dwarf/releases/download/latest/libdwarf.so
fi
if [ ! -f src/main/resources/win32-x86-64/libdwarf.dll ]; then
	curl -o src/main/resources/win32-x86-64/libdwarf.dll -L --create-dirs https://github.com/cesena/libdwarf-ghidra2dwarf/releases/download/latest/libdwarf.dll
fi
if [ ! -f src/main/resources/darwin/libdwarf.dylib ]; then
	curl -o src/main/resources/darwin/libdwarf.dylib -L --create-dirs https://github.com/cesena/libdwarf-ghidra2dwarf/releases/download/latest/libdwarf.dylib
fi

mvn package
