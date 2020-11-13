#!/bin/sh

./generate_dbg.py $1 && pytest .
