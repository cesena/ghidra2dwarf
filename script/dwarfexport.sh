#!/bin/bash

#script to automatically decompile and output source code of a binary with ghidra

GHIDRA_PATH=/opt/ghidra/
if [ "$#" -ne 1 ]
then 
    echo "$0 <binary path>"
    exit
fi

#remove gpr and rep files first (CAREFUL!)
rm -rf *.gpr *.rep

time $GHIDRA_PATH/support/analyzeHeadless ../test/ ghidra2dwarf -process test.exe -noanalysis -postscript ./dwarfexport.py

cp /tmp/debug_info ../test/.debug_info
cp /tmp/debug_abbrev ../test/.debug_abbrev
cp /tmp/debug_line ../test/.debug_line
cd ../test
cp test.exe test_bho.exe
objcopy --add-section .debug_info=.debug_info test_bho.exe
objcopy --add-section .debug_line=.debug_line test_bho.exe
objcopy --add-section .debug_abbrev=.debug_abbrev test_bho.exe

