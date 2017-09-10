We recommand you to not compile grap yourself on Windows because it can be tedious (see [COMPILE_WINDOWS.md](doc/COMPILE_WINDOWS.md) if you wish to compile it yourself) .

This document explains how to use pre-compiled version of grap and its bindings on Windows.

#Requirements

- If you only intendo to use the IDA plugin **no requirement is needed**.
- If you want to use grap as a standalone tool, you will need to meet the **python2.7** requirements from [COMPILE_WINDOWS.md](doc/COMPILE_WINDOWS.md) (python2.7, add it to PATH, with pip install pefile, pyelftools and capstone-windows).

# grap and python bindings
You will find compiled files (windows_compiled_1_0_0.zip) in the downloads panel (https://bitbucket.org/cybertools/grap/downloads/).

- Extract the .zip file
- Copy python\pygrap.py into C:\Python27\Lib\site-packages\
- Copy python\_pygrap.pyd into C:\Python27\Lib\site-packages\

# grap-match.exe and grap.py
You may use the compiled grap-match.exe and grap.py with the -nt option (multi-threading does not work on Windows for now, please update the path to match your setup):

- grap-match.exe (in binaries\ folder) may be directly used within a cmd.exe prompt:
```
E:\windows_compiled_1_0_0\binaries\grap-match.exe -nt pattern.dot test.dot
```
- The grap.py wrapper (and disassembler) can be used but the path of the grap-match.exe binary should be specified:
```
python E:\windows_compiled_1_0_0\binaries\grap.py -nt -b E:\windows_compiled_1_0_0\binaries\grap-match.exe pattern.dot test.dot
```


# IDA plugin
Read [IDA.md](IDA.md) for installation and usage instruction of the IDA plugin.
