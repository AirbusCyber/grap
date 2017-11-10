We recommand you to not compile grap yourself on Windows because it can be tedious (see [COMPILE_WINDOWS.md](doc/COMPILE_WINDOWS.md) if you wish to compile it yourself) .

This document explains how to use pre-compiled version of grap and its bindings on Windows.

# Requirements

- If you only intend to use the IDA plugin, you will only need to install capstone: within a cmd.exe admin prompt, run `pip install capstone-windows` (you might need to change directory to where pip is, for instance C:\python27-x64\Scripts)
- If you want to use grap as a standalone tool, you will need also need pefile and pyelftools (install them with pip)

# grap, python bindings and IDA plugin
You will find compiled files (grap\_1-1-0\_ida700\_windows.zip for instance) in the release panel. You can find release information (SHA256SUM) in the [releases/](releases/) folder.

- Extract the .zip file
- Follow the instructions in the README.txt (you will need to copy 4 files / folders)

# grap-match.exe and grap.py
You may use the compiled grap-match.exe and grap.py with the -nt option since multi-threading does not work on Windows for now (please update the path to match your setup):

- grap-match.exe (in binaries\ folder) may be directly used within a cmd.exe prompt:
```
E:\windows_compiled_1_0_0\binaries\grap-match.exe -nt pattern.dot test.dot
```
- The grap.py wrapper (and disassembler) can be used but the path of the grap-match.exe binary should be specified:
```
python E:\windows_compiled_1_0_0\binaries\grap.py -nt -b E:\windows_compiled_1_0_0\binaries\grap-match.exe pattern.dot test.dot
```

# IDA plugin
Read [IDA.md](IDA.md) for addtionnal usage instruction of the IDA plugin.
