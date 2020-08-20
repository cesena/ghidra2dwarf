#!/bin/sh

BINARY_PATH=$1
BINARY=$2

echo ${BINARY_PATH}
echo ${BINARY}
cd $BINARY_PATH
cp $BINARY ${BINARY}.sym.exe
objcopy --add-section .debug_info=.debug_info ${BINARY}.sym.exe
objcopy --add-section .debug_line=.debug_line ${BINARY}.sym.exe
objcopy --add-section .debug_abbrev=.debug_abbrev ${BINARY}.sym.exe
