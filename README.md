# Ghidra2Dwarf

![](./ghidra2dwarf.png)

Inspired by: [dwarfexport](https://github.com/ALSchwalm/dwarfexport)

Contributions are welcome, feel free to open an issue if something is broken.

Ghidra2Dwarf is a ghidra plugin that allows to exports informations (such as functions,
decompiled code, types) from ghidra to dwarf sections inside ELF binaries.

More specifically it exports inside a source file named `${program}.ghidra.c` all the decompiled
functions, and create an ELF binary named `${program}_dbg` that can be used to
do source code level debugging.

Example:

![](./img/gdb.png)

Inside gdb now you can use:

1. `list <function>` to display the function's source code.
2. `n` to step one source code line instruction.
3. `ni` to step one assembly instruction.

## Install

Copy [libdwarf.jar](./lib/target/libdwarf.jar) inside `~/.ghidra/.${GHIDRA_VERSION}/plugins`.
In the script manager -> script directories add the `src` directory:

![](./img/script-directories.png)

### Linux

Bash:

```sh
git clone https://github.com/cesena/ghidra2dwarf.git
cd ghidra2dwarf
export GHIDRA_VERSION="ghidra_9.1.2_PUBLIC" # Change here with correct version
mkdir -p ~/.ghidra/.${GHIDRA_VERSION}/plugins
cp ./lib/target/libdwarf.jar ~/.ghidra/.${GHIDRA_VERSION}/plugins
```

### Windows

Powershell:

```powershell
git clone https://github.com/cesena/ghidra2dwarf.git
cd ghidra2dwarf
Set-Variable -Name "GHIDRA_VERSION" -Value "ghidra_9.1.2_PUBLIC"
mkdir -p ~\.ghidra\.$GHIDRA_VERSION\plugins
cp .\lib\target\libdwarf.jar ~\.ghidra\.$GHIDRA_VERSION\plugins
```

## Run

Run `ghidra2dwarf.py` inside the script manager:

![](./img/run-script.png)

### Headless mode

#### Linux

If you saved the project and ghidra is closed, you can launch [ghidra2dwarf.sh](./src/ghidra2dwarf.sh)
to run ghidra in headless mode and export the dwarf informations:

```sh
$ ./src/ghidra2dwarf.sh <Project directory> <Project name> <Binary path> <Binary>
$ # Example: ./src/ghidra2dwarf.sh ~/.local/share/ghidra/ TEST ~/CTF/ chall
```

#### Windows

TODO

