# grap: define and match graph patterns within binaries
grap takes patterns and binary files, uses a Casptone-based disassembler to obtain the control flow graphs from the binaries, then matches the patterns against them.

Patterns are user-defined graphs with instruction conditions ("opcode is xor and arg1 is eax") and repetition conditions (3 identical instructions, basic blocks...).

grap is both available as a standalone tool with a disassembler and as an IDA plugin which takes advantage of the disassembly done by IDA and the reverser.

# Installation
We describe how to build and install grap on a Linux distribution.
For building and installing grap and the IDA plugin on Windows, please read WINDOWS.md.

## Requirements
The following dependencies must be installed:

- cmake
- bison
- flex 
- libboost-regex-dev
- libseccomp-dev
- python2.7
- python-pefile
- python-pyelftools
- python-capstone

Please note that those were tested for the latest Ubuntu LTS (16.04) and may differ depending on your distribution.

## Build and install
The following commands will build and install the project:

- `mkdir build; cd build/` as we advise you to build the project in a dedicated directory
- `cmake ../src/; make` will build with cmake and make
- `sudo make install` will install grap into /usr/local/bin/

### Python bindings
By default python bindings are not built. In order to build them you will need the following additional dependencies :

- python2.7-dev
- swig

Then you need to add the option PYTHON_BINDING=1 option to cmake: for instance `cmake -DPYTHON_BINDING=1 ../src`


### Options
The default build type is "Release", the others can be obtained through cmake options (such as `cmake -DCMAKE_BUILD_TYPE=Debug ../src`):

- Release: best performance, default
- Debug: with debug information and address sanitizer
- Valgrind: with debug information, good to use when debugging with valgrind


Other options are also chosen with cmake (`cmake -DTOOLS=0` or `cmake -DNOSECCOMP=1` for instance):

- TOOLS: build tools (grap-match, todot and test binaries), default
- PYTHON_BINDING: build python bindings, not default
- NOSECCOMP: disable support of the grap-match binary for privilege drop through seccomp, not default

# Usage
The tool can be launched by using the following command:

`$ grap [options] pattern_file.dot test_files`

## Examples
* `grap -h`: describes supported options
* `grap patterns/basic_block_loop.dot -o ls.dot /bin/ls`: disassemble ls into ls.dot and looks for basic block loops
* `grap -od backspace.dot samples/*`: disassemble files with no attempt at matching
* `grap -q -sa backspace.dot samples/*.dot`: match disassembled files, show matching and non matching files, one per line
* `grap -m pattern.dot test.dot`: show all matched nodes
* `grap -f pattern.dot test.exe`: force re-disassembling the binary, then matches it against pattern.dot


# Reference examples and tests
Some examples of pattern files and test files are given in the src/tests_graphs/ directory.
For troubleshooting purposes you can test them all.

- `./tests` will use the C++ library to test them against expected values, `./tests -h` gives information about each test.
- `make test` will use the C++ library, the grap-match binary, grap-match.py and python bindings for disassembly and matching to test them. It needs bindings to be built and installed
- `grap` or `grap-match` can be used to test them individually
