# Ghidra Jupyther notebook

Warning: very high quality code, definitely use this in prod!

## How it works
The python/ghidra script (`jupyther_proxy.py`) opens a TCP listener executing whichever code it receives.  
It tries to be smart and does some fancy stuff to get the value of the last expression if there is one, à la repl.

The client (`repl.py`) then simply opens a TCP client and sends the server the code it wants to execute, getting the output (both "return value" and stdout/stderr) back from the server.

## Install
### Jupyther kernel
I'm lazy, so you'll have to first install [ghidra-jython-kernel](https://github.com/AllsafeCyberSecurity/ghidra-jython-kernel) (the even more retarded (as in, it's not even working) version of this thing).
```bash
python3 -m pip install ghidra-jython-kernel
```
Then replace the file `repl.py` inside `<python3-dir>/Lib/site-packages/ghidra-jython-kernel` with the one provided in this folder.

### Ghidra script
Simply copy `jupyther_proxy.py` into the `~/ghidra_scripts` folder.

## Run
First open Ghidra and load the program you want to analyze.  
Then from the Script Manager start `jupyther_proxy.py`.

Now you can start the jupyther notebook which will automatically find the kernel `GhidraJython`.
```bash
jupyter notebook
```
