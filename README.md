# Ghidra2Dwarf

![](./img/ghidra2dwarf.png)

Inspired by: [dwarfexport](https://github.com/ALSchwalm/dwarfexport)

Contributions are welcome, feel free to open an issue if something is broken.

Ghidra2Dwarf is a ghidra plugin that allows to exports informations (such as functions,
decompiled code, types) from ghidra to dwarf sections inside ELF binaries.

More specifically it exports inside a source file named `${program}_dbg.c` all the decompiled
functions, and create an ELF binary named `${program}_dbg` that can be used to
do source code level debugging.

Example:

![](./img/gdb.png)

Inside gdb now you can use:

1. `list <function>` to display the function's source code.
2. `n` to step one source code line instruction.
3. `ni` to step one assembly instruction.
4. `p variable` to print the variable's value.

## Install

- Unzip the [latest release](https://github.com/cesena/ghidra2dwarf/releases/latest).
- In the script manager -> script directories add the `ghidra2dwarf` directory:

![](./img/script-directories.png)

## Run

Run `ghidra2dwarf.py` inside the script manager:

![](./img/run-script.png)

### Headless mode

This mode only works in ghidra 9.1.2 at the moment https://github.com/NationalSecurityAgency/ghidra/issues/2561

#### Linux

If you saved the project and ghidra is closed, you can launch [ghidra2dwarf.sh](./src/ghidra2dwarf.sh)
to run ghidra in headless mode and export the dwarf informations:

```sh
$ ./src/ghidra2dwarf.sh <Project directory> <Project name> <Binary path> <Binary>
$ # Example: ./src/ghidra2dwarf.sh ~/.local/share/ghidra/ TEST ~/CTF/ chall
```

#### Windows

TODO

