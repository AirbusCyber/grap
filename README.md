# grap: define and match graph patterns within binaries
### [https://github.com/QuoSecGmbH/grap](https://github.com/QuoSecGmbH/grap)
grap takes patterns and binary files, uses a Casptone-based disassembler to obtain the control flow graphs from the binaries, then matches the patterns against them.

Patterns are user-defined graphs with instruction conditions ("opcode is xor and arg1 is eax") and repetition conditions (3 identical instructions, basic blocks...).

grap is available as a standalone tool with a disassembler and python bindings, and as an IDA plugin which takes advantage of the disassembly done by IDA and the reverser.

Support:
* Files: disassembly of PE, ELF and raw binary, further files should work within IDA
* Architecture: x86 and x86_64

### Match quick pattern:
![Match quick pattern](https://github.com/yaps8/yaps8.github.io/raw/master/grap/figures/backspace_quick_pattern.png)

### Match full pattern:
![Match full pattern](https://github.com/yaps8/yaps8.github.io/raw/master/grap/figures/backspace_full_pattern.png)

### Match on multiple files:
![Match on multiple files](https://github.com/yaps8/yaps8.github.io/raw/master/grap/figures/backspace_quiet.png)

### Create patterns interactively from IDA:
![Create and match patterns directly from IDA](https://github.com/yaps8/yaps8.github.io/raw/master/grap/figures/ida_create_pattern_v1_2_1.png)

# Installation
This document describes how to build and install grap on a Linux distribution.

You may also read:

- [WINDOWS.md](WINDOWS.md): installing grap on Windows
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
- python3-dev
- python3-pefile
- python3-pyelftools
- python3-capstone
- swig (version 3 or newer is mandatory)

Thus on Ubuntu / Debian, this should work :
```
sudo apt-get install build-essential cmake bison flex libboost-regex-dev libboost-system-dev libboost-filesystem-dev libseccomp-dev python3-dev python3-pefile python3-pyelftools python3-capstone swig
```

Please note that those were tested for the latest Ubuntu LTS (18.04.3).
Packages may differ depending on your distribution.

## Build and install
The following commands will build and install the project:

- `mkdir build; cd build/` as we advise you to build the project in a dedicated directory
- `cmake ../src/; make` will build with cmake and make
- `sudo make install` will install grap into /usr/local/bin/

SWIG might fail to find python3 if your default version is python2, this can be overcome by switching to python3 as default.
For instance on Ubuntu:
```
sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 10
```

# Usage
The tool can be launched by using the following command:

`$ grap [options] pattern test_paths`

Below are a few examples of supported options:

- `grap -h`: describes supported options

One can let grap infer a pattern from a string. Only few options are supported but this is useful for prototyping:

- `grap "opcode is xor and arg1 contains '['" (test.exe)`: look for a xor with a memory write
- `grap -v "sub->xor->sub" (test.exe)`: -v will output the path of the inferred pattern

Choose how the binaries are disassembled:

- `grap -od (pattern.grapp) samples/*`: disassemble files in folder samples/ with no attempt at matching
- `grap -f (pattern.grapp) (test.exe)`: force re-disassembling the binary, then matches it against pattern.grapp
- `grap --raw (pattern.grapp) (test.bin)`: disassembling raw file (use --raw-64 for 64 bits binaries)

Control the verbosity of the output:

- `grap -q -sa (pattern.grapp) (samples/*.grapcfg)`: match disassembled files, show matching and non matching files, one per line
- `grap -m (pattern.grapp) (test.grapcfg)`: show all matched nodes

Choose where the disassembled file(s) (.grapcfg) are written; match multiple files against multiple patterns:

- `grap patterns/basic_block_loop.grapp -o ls.grapcfg /bin/ls`: disassemble ls into ls.grapp and looks for basic block loops
- `grap (pattern1.grapp) -p (pattern2.grapp) (test.exe)`: match against multiple pattern files
- `grap -r -q patterns/ /bin/ -o /tmp/` : disassemble all files from /bin/ into /tmp/ and matches them against all .grapp patterns from patterns/ (recursive option -r applies to /bin/, not to patterns/)

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

Note that pattern files can contain multiple pattern graphs.

You may find additional pattern examples in two directories:

- [patterns/](patterns/) contains a few patterns that can be useful on any binary such as a pattern to detect short loops or to detect a loop on basic blocks,
- [examples/](examples/) contains patterns used against the Backspace malware (see [examples/backspace_samples.md](examples/backspace_samples.md) to obtain the binary samples).

# Tutorials & further examples
On malware samples:

- Navigating malware samples with grap (CLI, IDA): https://quosecgmbh.github.io/blog/grap_qakbot_navigation
- Automating function parsing and decryption (python bindings): https://quosecgmbh.github.io/blog/grap_qakbot_strings

Python bindings usage:

- Python file demonstrating how to use bindings to analyze Backspace samples: [examples/analyze_backspace.py](examples/analyze_backspace.py)
- Examples of IDApython scripting are integrated within the IDA plugin, you can see them here: [https://yaps8.github.io/grap/html/scripting_css.html](https://yaps8.github.io/grap/html/scripting_css.html)

# Documentation
You will find more documentation in the [doc/](doc/) folder:

- [doc/COMPILE_OPTIONS.md](doc/COMPILE_OPTIONS.md)
- [doc/DEBUG.md](doc/DEBUG.md)
- [doc/TESTS.md](doc/TESTS.md)
- [doc/syntax_highlighting.md](doc/syntax_highlighting.md)

The syntax of pattern and test graphs is detailed in the file [grap\_graphs.pdf](https://github.com/QuoSecGmbH/grap/releases/download/v1.1.0/grap_graphs.pdf) within the release section.

# License
grap is licensed under the MIT license. The full license text can be found in [LICENSE](LICENSE).
