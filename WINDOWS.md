We recommand you to not compile grap yourself on Windows because it can be tedious (see [COMPILE_WINDOWS.md](doc/COMPILE_WINDOWS.md) if you wish to compile) .

This document explains how to use pre-compiled version of grap and its bindings on Windows.

# Requirements
You need to install the VC++ runtime library, [here on microsoft.com](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads).

# grap and python bindings
You will find compiled files in the src/compiled/ folder and need to copy them:

- pygrap.py into C:\Python27\Lib\site-packages\
- _pygrap.pyd into C:\Python27\Lib\site-packages\

# IDA plugin
Read [IDA.md](IDA.md) for installation and usage instruction of the IDA plugin.
