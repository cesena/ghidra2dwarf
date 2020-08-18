#!/bin/bash

#script to automatically decompile and output source code of a binary with ghidra

GHIDRA_PATH=/opt/ghidra
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

