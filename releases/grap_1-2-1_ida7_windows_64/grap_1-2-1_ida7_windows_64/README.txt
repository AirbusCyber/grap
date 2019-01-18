If you want to use the IDA plugin only:
- If you use the normal (64 bits) version of IDA (>=7):
  - Copy pygrap\x64\pygrap.py into C:\python27-x64\Lib\site-packages\
  - Copy pygrap\x64\_pygrap.pyd into C:\python27-x64\Lib\site-packages\
  - Copy IDA\grap.py into C:\Program Files\IDA 7.0\plugins\
  - Copy folder IDA\idagrap\ into C:\Program Files\IDA 7.0\plugins\
- In an administrative prompt (cmd.exe), perform:
  - pip install capstone-windows
  - (you may need to run it from directory C:\Python27-x64\Scripts or C:\Python27\Scripts)

If you want to use grap as a standalone tool:
- Perform the previous steps
- If it is not installed, install python2.7 (64 bits) and ask the installation wizard to add python to path
- Open an administrative prompt (cmd.exe) and perform:
  - pip install pefile
  - pip install pyelftools
  - pip install capstone-windows

Please refer to https://github.com/QuoScient/grap/ for further information:
- IDA plugin usage (IDA.md)
- grap binaries usage (WINDOWS.md)

