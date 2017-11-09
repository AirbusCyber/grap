This document will guide you through the compilation of *grap* and its bindings on Windows.

Alternatively you can use pre-compiled binaries (see [WINDOWS.md](../WINDOWS.md))

# Requirements
This guide is written for Windows 7 (64 bits) and focuses on compilation of the x86\_64 version of grap.

Note that the Visual Studio Installer is greedy, if you use a virtual machine please make sure it has **at the very least 2 GB of RAM and 2 CPU** available.

## Visual Studio
We used Visual Studio 2017 - Community Edition with the following components installed:

- .NET Framework 4.6.1 SDK
- .NET Framework 4.6.1 targeting pack
- C++ / CLI support
- VC++ 2017 v141 toolset (x86, x64)
- Visual C++ 2017 Redistributable Update
- Visual C++ tools for CMake
- Visual Studio C++ core features

## CMake

Install the latest version of *CMake* available on their website https://cmake.org/download/. During the installation wizard, enable the option to add *CMake* to the PATH.

## Python 2.7 + required packages

Install the latest version of *Python* 2.7 (64-bit) available on their website https://www.python.org/downloads/windows/. During the installation wizard, enable the option to add *Python* to the PATH.

Install the packages required by *grap* with these commands (in a command shell as an administrator):
```
pip install pefile
pip install pyelftools
pip install capstone-windows
```
Note that `capstone-windows` package includes prebuilt Windows core of *Capstone*, so no external *Capstone* library is needed�.

## Boost

Download the latest version of *Boost* for Windows (for example https://dl.bintray.com/boostorg/release/1.64.0/source/boost_1_64_0.zip at the time of writing).

Extract it, then launch `bootstrap.bat` in boost_<version> directory with VS developper command prompt 64 bits (*x64 Native Tools Command Prompt for VS 2017*).

Edit `project-config.jam` to configure compilation with your version of MSVC. You should change the folder to match your version, for instance:
```
import option ;

using msvc : 14.1 : "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.10.25017\bin\HostX64\x64\cl.exe";

option.set keep-going : false ;
```
Within the VS developper command prompt 64 bits, in the Boost directory (where `project-config.jam` is located), run 
```
b2 address-model=64 toolset=msvc-14.1 threading=multi runtime-link=static variant=release
```

## Flex + Bison
Install the latest version of *Win flex-bison* available on their website https://sourceforge.net/projects/winflexbison/. Once the file decompressed, rename `win_bison.exe` and `win_flex.exe` binairies respectively to `bison.exe` and `flex.exe`.

Add then the directory where these two executables are located to the PATH.

For instance, to add the path to the current PATH variable (in the active cmd.exe prompt):
```
set PATH=%PATH%;C:\Users\dev\Downloads\win_flex_bison-latest
```

## SWIG
Install the latest version of *SWIG* available on their website http://www.swig.org/download.html (note that prebuilt executable is available for Windows).
Add then the directory where the executable are located to the PATH.

For instance:
```
set PATH=%PATH%;C:\Users\dev\Downloads\swigwin-3.0.12\swigwin-3.0.12
```

# Compilation
## Grap

Now that all dependencies are installed we can compile *grap*. To do so, open a Command Prompt (cmd.exe), move to the *grap* directory and execute the following lines (change the path to match your setup):
```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 15 Win64" -DBOOST_ROOT=C:\Users\dev\Downloads\boost_1_64_0\boost_1_64_0 ..\src
cmake --build . --config Release
```

It may be necessary to *run again the last command* (`cmake --build . --config Release`) if errors occur during the build.

## Binaries
Built binaries should be located in the Release/ subdirectory of the build/ directory.

# Install
You will find the required pygrap.py and _pygrap.pyd in the build/bindings/python/ and build/bindinds/python/Release/ directories.
Please apply the instructions in [WINDOWS.md](../WINDOWS.md) to copy them to the right folders.

# Tests
You can verify that grap is working correctly by running those commands (refer to [README.md](../README.md) for more information):

- `tests.exe ..\..\src\tests_graphs`: simple test
- `test_all.py -l log.txt -nt -nc -t Release\tests.exe -gm Release\grap-match.exe -gmpy ..\src\tools\grap-match\grap-match.py -g ..\src\tools\grap\grap.py`

# Compile 32 bits version
If you wish to compile the 32 bits version, it should be enough to:

- Modify the Boost compile option (**address-model=32** instead of **address-model=64**)
- Modify the CMake command (**Visual Studio 15** instead of **Visual Studio 15 Win64**)

# Troubleshooting
## Boost
One common issue is a version mismatch between the compiled boost version compiled and what is expected by CMake.
You can try to make a clean build (within a VS command prompt):
```
bjam --clean
b2 -a ...
```

You should replace "..." by the compilation options (see before).