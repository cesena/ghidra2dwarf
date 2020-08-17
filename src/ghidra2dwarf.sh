#!/bin/bash

#script to automatically decompile and output source code of a binary with ghidra

GHIDRA_PATH=~/Tools/ghidra_9.1.2/build/dist/ghidra_9.1_DEV/
if [ "$#" -ne 4 ]
then 
    echo "$0 <Project directory> <Project name> <Binary path> <Binary>"
    exit
fi

DIR=$1
NAME=$2
BINARY_PATH=$3
BINARY=$4

#remove gpr and rep files first (CAREFUL!)
rm -rf *.gpr *.rep

time $GHIDRA_PATH/support/analyzeHeadless $DIR/ $NAME -process $BINARY -postscript ./ghidra2dwarf.py

cp /tmp/debug_info ${BINARY_PATH}/.debug_info
cp /tmp/debug_abbrev ${BINARY_PATH}/.debug_abbrev
cp /tmp/debug_line ${BINARY_PATH}/.debug_line
cp ${BINARY}.c $BINARY_PATH
cd $BINARY_PATH
cp $BINARY ${BINARY}.sym.exe
objcopy --add-section .debug_info=.debug_info ${BINARY}.sym.exe
objcopy --add-section .debug_line=.debug_line ${BINARY}.sym.exe
objcopy --add-section .debug_abbrev=.debug_abbrev ${BINARY}.sym.exe
