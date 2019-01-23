# Tests
Note that grap is a python script that will:

- Use the python disassembler to create DOT files from binaries
- Call the installed C++ binary grap-match to match patterns to the DOT files

Some examples of pattern files and test files are given in the src/tests_graphs/ directory.
For troubleshooting purposes you can test them all.

- `./tests` will use the C++ library to test them against expected values, `./tests -h` gives information about each test.
- `make test` will use `test_all.py` (in the build/ directory) and test the C++ library, the grap-match binary, grap-match.py and python bindings for disassembly and matching. It needs bindings to be built and installed
- `grap` or `grap-match` can be used to test them individually

`test_all.py` takes options:

- -nt: no threads
- -nc: no colors
- -t tests_path, -gm grap_match_path, -gmpy grap_match_py_path, -g grap_path: specifies where those binaries and scripts are found
- -v: verbose
- -l log.txt: log output

On GNU/Linux, once grap is installed you may call directly either `make test` or `test_all.py` with no options.

On Windows, the following command is recommended:
```
test_all.py -l log.txt -nt -nc -t Release\tests.exe -gm Release\grap-match.exe -gmpy ..\src\tools\grap-match\grap-match.py -g ..\src\tools\grap\grap.py
```

It is normal and expected that some WARNING will show.

More options for debug can be found in [doc/DEBUG.md](doc/DEBUG.md).

