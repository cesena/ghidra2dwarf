#!/bin/sh

BINARY_PATH=$1
BINARY=$2

echo ${BINARY_PATH}
echo ${BINARY}
mv /tmp/debug_info ${BINARY_PATH}/.debug_info
mv /tmp/debug_abbrev ${BINARY_PATH}/.debug_abbrev
mv /tmp/debug_line ${BINARY_PATH}/.debug_line
mv ${BINARY}.c $BINARY_PATH
cd $BINARY_PATH
cp $BINARY ${BINARY}.sym.exe
objcopy --add-section .debug_info=.debug_info ${BINARY}.sym.exe
objcopy --add-section .debug_line=.debug_line ${BINARY}.sym.exe
objcopy --add-section .debug_abbrev=.debug_abbrev ${BINARY}.sym.exe
