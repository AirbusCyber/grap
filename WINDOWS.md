We recommand you to not compile grap yourself on Windows because it can be tedious (see [COMPILE_WINDOWS.md](doc/COMPILE_WINDOWS.md) if you wish to compile) .

This document explains how to use pre-compiled version of grap and its bindings on Windows.

# grap and python bindings
You will find compiled files in the src/compiled/ folder and need to copy them:
- pygrap.py to C:\Python27\Lib\site-packages
- _pygrap.pyd to C:\Python27\Lib\site-packages

# IDA plugin
IDA plugin is in the src/IDA/grap/ folder, you need to copy them:
- grap.py to C:\Program Files (x86)\IDA\plugins
- idagrap/ to C:\Program Files (x86)\IDA\plugins
