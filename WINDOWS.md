We recommand you to not compile grap yourself on Windows because it can be tedious (see [COMPILE_WINDOWS.md](doc/COMPILE_WINDOWS.md) if you wish to compile) .

This document explains how to use pre-compiled version of grap and its bindings on Windows.

# grap and python bindings
You will find compiled files in the src/compiled/ folder and need to copy them:

- pygrap.py into C:\Python27\Lib\site-packages\
- _pygrap.pyd into C:\Python27\Lib\site-packages\

# grap-match.exe and grap.py
You may use the compiled grap-match.exe and grap.py with the -nt option (multi-threading does not work on Windows for now):

- grap-match.exe may be directly used within a cmd.exe prompt:
```
E:\grap\build\Release\grap-match.exe -nt pattern.dot test.dot
```
- The grap.py wrapper (and disassembler) can be used but the path of the grap-match.exe binary should be specified:
```
python E:\grap\src\tools\grap\grap.py -nt -b E:\grap\build\Release\grap-match.exe pattern.dot test.dot
```


# IDA plugin
Read [IDA.md](IDA.md) for installation and usage instruction of the IDA plugin.
