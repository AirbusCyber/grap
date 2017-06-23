This document will guide you through the compilation of *grap* and its bindings on Windows.

Alternatively you can use pre-compiled binaries (see [WINDOWS.md](../WINDOWS.md))

# Requirements
This guide is written for Windows 7 with Visual Studio 2017.
The compilation of *grap* needs the following tools.

## CMake

Install the latest version of *CMake* available on their website https://cmake.org/download/. During the installation wizard, enable the option to add *CMake* to the PATH.

## Python 2.7 + required packages

Install the latest version of *Python* 2.7 (32-bit) available on their website https://www.python.org/downloads/windows/. During the installation wizard, enable the option to add *Python* to the PATH.

Install the packages required by *grap* with these commands (in a command shell as an administrator):
```
pip install pefile
pip install pyelftools
pip install capstone-windows
```
Note that “`capstone-windows` package includes prebuilt Windows core of *Capstone*, so no external *Capstone* library is needed”.

## Boost

Download the latest version of *Boost* for Windows (for example https://dl.bintray.com/boostorg/release/1.64.0/source/boost_1_64_0.zip at the time of writing).
Extract it, then launch `bootstrap.bat` in boot_<version> directory.
Edit `project-config.jam` to configure compilation with your version of MSVC. For example, with Visual Studio 2017:
```
import option ;

using msvc : 14.1 : "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.10.25017\bin\HostX64\x64\cl.exe";

option.set keep-going : false ;
```
Open the *Developer Command Prompt for VS*, and in the Boost directory (where `project-config.jam` is located), run `b2 toolset=msvc-14.1 address-model=32 runtime-link=static`.

## Flex + Bison
Install the latest version of *Win flex-bison* available on their website https://sourceforge.net/projects/winflexbison/. Once the file decompressed, rename `win_bison.exe` and `win_flex.exe` binairies respectively to `bison.exe` and `flex.exe`.

Add then the directory where these two executables are located to the PATH.

## SWIG
Install the latest version of *SWIG* available on their website http://www.swig.org/download.html (note that prebuilt executable is available for Windows).
Add then the directory where the executable are located to the PATH.

# Compilation
## Grap

Now that all dependencies are installed we can compile *grap*. To do so, open a Command Prompt, move to the *grap* directory and execute the following lines:

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 15" -DBOOST_ROOT=<boost root> -DPYTHON_BINDING=1 ../src
cmake --build . --config Release
```

It may be necessary to run again the last command (`cmake --build`) if errors occur during the build.

## Binding

To create the python binding you must specify the following option:

```
cmake -DPYTHON_BINDING=1
```

The installation can be done with command below:

```
(make install)
```

## Tools

The creation of the *grap* tools can be created with the option below:

```
cmake -DTOOLS=1
```

