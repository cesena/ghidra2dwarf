#!/bin/bash

#script to automatically decompile and output source code of a binary with ghidra

GHIDRA_PATH=~/Tools/ghidra_9.1.2/build/dist/ghidra_9.1_DEV/
if [ "$#" -ne 1 ]
then 
    echo "$0 <binary path>"
    exit
fi

#remove gpr and rep files first (CAREFUL!)
rm -rf *.gpr *.rep

time $GHIDRA_PATH/support/analyzeHeadless ../test/ ghidra2dwarf -process test.exe -postscript ./dwarfexport.py


