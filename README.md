# Ghidra2Dwarf

![](./ghidra2dwarf.png)

Inspired by: [dwarfexport](https://github.com/ALSchwalm/dwarfexport)

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

This is the [libdwarf-linux](./jar/libdwarf-linux.jar) generated from JNAerator. Now you can
move this jar inside `~/.ghidra/.${GHIDRA_VERSION}_PUBLIC/plugins`

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
