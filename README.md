# Ghidra2Dwarf

Inspired by: [dwarfexport](https://github.com/ALSchwalm/dwarfexport)

## Build

### Linux

```
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

Now there is the header file of libdwarf in `/tmp/dwbuild/libdwarf.h` and the
shared library in `/tmp/dwbuild/libdwarf/.libs/libdwarf.so`. They are already
available in [include](./include) and [libs](./lib)

We want to generate a java wrapper and we opted for [JNAerator](https://github.com/nativelibs4java/JNAerator),
availabe in [jar](./jar/jnaerator-0.12.jar). With this tool we can create the
interfaces needed for [JNA](https://github.com/java-native-access/jna) to work.

This is the [libdwarf](./jar/libdwarf.jar) generated from JNAerator.

Now in ghidra we can access through jython to the libdwarf with `import libdwarf`.

However we didn't specify how the `libdwarf` jar communicate with `libdwarf.so` --> TODO

