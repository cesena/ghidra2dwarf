#!/usr/bin/env python3

import os
import sys
import tempfile
import subprocess

BINS_DIR = 'binaries'

ghidra_dir = sys.argv[1]
headless_path = os.path.join(ghidra_dir, 'support', 'analyzeHeadless')

with tempfile.TemporaryDirectory(prefix='temp_ghidra2dwarf_') as temp_dir:
	for f in os.listdir(BINS_DIR):
		if not f.endswith('.gzf'):
			continue
		name, _ = os.path.splitext(f)
		print(name)
		cmd = [
			headless_path, temp_dir, name, '-readonly', '-noanalysis',
			'-import', os.path.join(BINS_DIR, f), '-scriptPath', os.path.join('..', 'src'),
			'-postScript', 'ghidra2dwarf.py', os.path.join(BINS_DIR, name)
		]
		print(' '.join(cmd))
		p = subprocess.run(cmd, check=True, stderr=subprocess.PIPE)
		print(p.stderr.decode())
		exception = b'Traceback' in p.stderr
		assert not exception
