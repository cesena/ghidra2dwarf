# Ghidra2Dwarf

![](./ghidra2dwarf.png)

Inspired by: [dwarfexport](https://github.com/ALSchwalm/dwarfexport)

## Installation

### Linux

```sh
git clone https://github.com/cesena/ghidra2dwarf.git
cd ghidra2dwarf
mkdir -p ~/.ghidra/${GHIDRA_VERSION}/plugins
cp ./jnarated/target/libdwarf.jar ~/.ghidra/${GHIDRA_VERSION}/plugins/
```

### Windows

TODO

## Run

In the script manager -> script directories add the `src` directory:

![](./img/script-directories.png)

And then run `ghidra2dwarf`:

![](./img/run-script.png)

### Headless mode

#### Linux

If you saved the project and ghidra is closed, you can launch [ghidra2dwarf.sh](./src/ghidra2dwarf.sh)
to run ghidra in headless mode and export the dwarf informations:

```
./src/ghidra2dwarf.sh <Project directory> <Project name> <Binary path> <Binary>
# Example: ./src/ghidra2dwarf.sh ~/.local/share/ghidra/ TEST ~/CTF/ chall
```

#### Windows

TODO

## Known issues

* If the ELF binary is PIE, you need to rebase the memory map to the address `0`:

![](./img/rebase-pie.gif)

* Sometimes you get an `IndexError`, try to re-run the script until it works.

## Build libdwarf

### Linux

```sh
rm -rf /tmp/dwbuildexample
mkdir /tmp/dwbuildexample
cd /tmp/dwbuildexample
git clone git://git.code.sf.net/p/libdwarf/code libdwarf-code
cd libdwarf-code
sh scripts/FIX-CONFIGURE-TIMES
mkdir /tmp/dwbuild
cd /tmp/dwbuild
/tmp/dwbuildexample/libdwarf-code/configure --enable-shared
make
```

Alternative way using cmake:

```sh
git clone git://git.code.sf.net/p/libdwarf/code libdwarf-code
cd libdwarf-code
mkdir build && cd build
cmake .. -DBUILD_SHARED=TRUE
cmake --build .
```

Now there is the header file of libdwarf in `/tmp/dwbuild/libdwarf.h` and the
shared library in `/tmp/dwbuild/libdwarf/.libs/libdwarf.so`. They are already
available in [include](./include) and [libs](./lib)

### Windows

TODO

## Build libdwarf java wrapper

We want to generate a java wrapper and we opted for [JNAerator](https://github.com/nativelibs4java/JNAerator),
availabe in [jar](./jar/jnaerator-0.12.jar). With this tool we can create the
interfaces needed for [JNA](https://github.com/java-native-access/jna) to work 
using `libdwarf.h`. We have modified a bit the [pom.xml](./jnarated/pom.xml) to 
generate the jar which already includes JNA and the shared library.

## Use libdwarf in ghidra's jython

Copy the generated [libdwarf.jar](./jar/jnarated/target/libdwarf.jar) inside `~/.ghidra/.${GHIDRA_VERSION}_PUBLIC/plugins`.

Now in ghidra we can access the libdwarf through jython with `import libdwarf`.

To use the library:

```py
from libdwarf import LibdwarfLibrary
from com.sun.jna.ptr import PointerByReference
l = LibdwarfLibrary.INSTANCE
r1 = PointerByReference()
r2 = PointerByReference()
l.dwarf_producer_init(l.DW_DLC_WRITE | l.DW_DLC_SYMBOLIC_RELOCATIONS | l.DW_DLC_POINTER64 | l.DW_DLC_OFFSET32 |  l.DW_DLC_TARGET_LITTLEENDIAN, lambda x: 0, None, None, None, 'x86_64', 'V2', '', r1, r2)
```
