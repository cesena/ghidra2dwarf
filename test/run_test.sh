#!/bin/sh

chmod +x ./test_ghidra_dbg
chmod +x ./rsa_dbg
chmod +x ./passcode_dbg
pytest test_ghidra.py
pytest test_rsa.py
pytest test_passcode.py
