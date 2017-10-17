# grap: define and match graph patterns within binaries
grap takes patterns and binary files, uses a Casptone-based disassembler to obtain the control flow graphs from the binaries, then matches the patterns against them.

Patterns are user-defined graphs with instruction conditions ("opcode is xor and arg1 is eax") and repetition conditions (3 identical instructions, basic blocks...).

grap is available as a standalone tool with a disassembler and python bindings, and as an IDA plugin which takes advantage of the disassembly done by IDA and the reverser.

# Installation
This document describes how to build and install grap on a Linux distribution.

You may also read:

- [WINDOWS.md](WINDOWS.md): building (optional) and installing grap on Windows
- [IDA.md](IDA.md): installation and usage instruction of the IDA plugin

## Requirements
Besides compilers (build-essential), the following dependencies must be installed:

- cmake
- bison
- flex 
- libboost-regex-dev
- libboost-system-dev
- libboost-filesystem-dev
- libseccomp-dev
- python2.7-dev
- python-pefile
- python-pyelftools
- python-capstone
- swig (version 3 or newer is mandatory)

Please note that those were tested for the latest Ubuntu LTS (16.04) and the latest debian stable (9.1.0 - Strech).
Packages may differ depending on your distribution.

## Build and install
The following commands will build and install the project:

- `mkdir build; cd build/` as we advise you to build the project in a dedicated directory
- `cmake ../src/; make` will build with cmake and make
- `sudo make install` will install grap into /usr/local/bin/

## Options
Compilation options are chosen with cmake (`cmake -DNOSECCOMP=1 ../src` for instance):

- TOOLS: build tools (grap-match, todot and test binaries), default
- PYTHON_BINDING: build python bindings, default
- NOSECCOMP: disable support of the grap-match binary for privilege drop through seccomp, not default

On GNU/Linux grap-match's use of seccomp restricts the number of system calls available to the binary for security purposes. 
In particular the "open" syscall is mostly unavailable after the initial argument parsing.
You may want to disable this feature if it generates the "Bad system call" or other errors but will lose the security provided.

Note that seccomp is only enabled within the `grap-match` binary and its wrapper (grap and grap.py scripts), and **not** within the bindings.


# Usage
The tool can be launched by using the following command:

`$ grap [options] pattern_file.dot test_files`

Below are a few examples of supported options:

- `grap -h`: describes supported options
- `grap patterns/basic_block_loop.dot -o ls.dot /bin/ls`: disassemble ls into ls.dot and looks for basic block loops
- `grap -od (pattern.dot) (samples/*)`: disassemble files with no attempt at matching
- `grap -q -sa (pattern.dot) (samples/*.dot)`: match disassembled files, show matching and non matching files, one per line
- `grap -m (pattern.dot) (test.dot)`: show all matched nodes
- `grap -f (pattern.dot) (test.exe)`: force re-disassembling the binary, then matches it against pattern.dot

Note that you can only pass one pattern file as argument but this file may contain multiple pattern graphs.

# Pattern examples
The following pattern detects a decryption loop consisting of a xor followed by sub found in a Backspace sample:
```
digraph decryption_md5_4ee00c46da143ba70f7e6270960823be {
A [cond=true, repeat=3]
B [cond="opcode is xor and arg2 is 0x11"]
C [cond="opcode is sub and arg2 is 0x25"]
D [cond=true, repeat=3]
E [cond="opcode beginswith j and nchildren == 2"]

A -> B
B -> C
C -> D
D -> E
E -> A [childnumber=2]
}
```

You may find additional pattern examples in two directories:

- [patterns/](patterns/) contains a few patterns that can be useful on any binary such as a pattern to detect short loops or to detect a loop on basic blocks,
- [examples/](examples/) contains patterns used against the Backspace malware (see [examples/backspace_samples.md](examples/backspace_samples.md) to obtain the binary samples).

# Documentation
You will find more documentation in the [doc/](doc/) folder. The syntax of pattern and test graphs is detailed in the file grap\_graphs.pdf within the download section on BitBucket ([https://bitbucket.org/cybertools/grap/downloads/grap_graphs.pdf](https://bitbucket.org/cybertools/grap/downloads/grap_graphs.pdf)).

The [examples/](examples/) folder contains a python file demonstrating how to use the python bindings to analyze Backspace samples.

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

# License
grap is licensed under the MIT license. The full license text can be found in [src/LICENSE](src/LICENSE).
