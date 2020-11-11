#!/bin/sh

chmod +x ./test_ghidra_dbg
chmod +x ./rsa_dbg
pytest test_dbg.py
pytest test_rsa.py
