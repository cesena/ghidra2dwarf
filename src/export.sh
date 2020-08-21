#!/bin/sh

BINARY_PATH=$1
BINARY=$2
BINARY_NEW=${BINARY}_dbg

echo ${BINARY_PATH} ${BINARY}
cd $BINARY_PATH
cp $BINARY $BINARY_NEW

# Remove unneded sections...
echo '[*] Removing unneeded debug sections'
objcopy -g $BINARY_NEW

echo '[*] Adding the debug sections'
objcopy --add-section .debug_info=.debug_info $BINARY_NEW
objcopy --add-section .debug_line=.debug_line $BINARY_NEW
objcopy --add-section .debug_abbrev=.debug_abbrev $BINARY_NEW

