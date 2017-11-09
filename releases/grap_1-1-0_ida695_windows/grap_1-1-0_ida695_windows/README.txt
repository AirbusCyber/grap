If you want to use the IDA plugin only:
- Copy pygrap\pygrap.py into C:\Python27\Lib\site-packages\
- Copy pygrap\_pygrap.pyd into C:\Python27\Lib\site-packages\
- Copy IDA\grap.py into C:\Program Files (x86)\IDA\plugins\
- Copy folder IDA\idagrap\ into C:\Program Files (x86)\IDA\plugins\
- In an administrative prompt (cmd.exe), perform:
  - pip install capstone-windows
  - (you may need to run it from directory C:\Python27\Scripts)

If you want to use grap as a standalone tool:
- Perform the previous steps
- Install python2.7 (32 bits) and ask the installation wizard to add python to path
- Open an administrative prompt (cmd.exe) and perform:
  - pip install pefile
  - pip install pyelftools
  - pip install capstone-windows

Please refer to https://github.com/AirbusCyber/grap/ for further information:
- IDA plugin usage (IDA.md)
- grap binaries usage (WINDOWS.md)

