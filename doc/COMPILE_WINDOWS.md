This document will guide you through the compilation of grap and its bindings on Windows.

Alternatively you can use pre-compiled binaries (see [WINDOWS.md](../WINDOWS.md))

# Requirements 
This guide is written for Windows 7 with Visual Studio 2015.
The compilation of grap needs the following tools.

## MinGW

First thing first we need Mingw
(https://sourceforge.net/projects/mingw/files/latest/download?source=files).
Once installed, it's necessary to open the package manager of Wingw
(`guimain.exe` which can be found in the flowing directory
`C:\MinGW\libexec\mingw-get\`) and install those tools:

```
mingw-developer-toolkit
mingw32-base
mingw32-gcc-g++
msys-base
msys-system-builder
```


Then, it's essential to remove the deprecated version of gcc which is
`msys-gcc`. To finish, you must add the Mingw binairies path to the environment
variables. To do so, go to `Start> (click droit sur computer) Properties>
Advanced system settings> (onglet Advanced) Environment Variables` and the user
variable `Path` with the value `C:\MinGW`.


## Flex + Bison
MinGW has a version of Flex and Bison which are deprecated. To fix this, you
must install the last version available on their website
https://sourceforge.net/projects/winflexbison/. Once the file decompressed, you
must rename `win_bison` and `win_flex` binairies respectively to `bison`,
`flex`. Then moved those two files and the `data` directory in
`C:\MinGW\msys\1.0\bin`.

## SWIG
The installation of SWIG will take place in two stages:
- compilation
- installation

First of all, you must download the sources
https://sourceforge.net/projects/swig/files/swigwin/swigwin-3.0.8/swigwin-3.0.8.zip/download?use_mirror=tenet
. Then, unzip the archive in `C:\MinGW\msys\1.0\home\[USER]\` and execute the
msys *bat* script (`C:\MinGW\msys\1.0\msys.bat`). Finally, run the following
lines in the terminal:

```
cd swigwin-x.x.x
./autogen.sh
./configure --without-pcre
make
make install
```
## Boost

Download the 32-bit MSCV Boost at
https://sourceforge.net/projects/boost/files/boost-binaries/1.61.0/boost_1_61_0-msvc-14.0-32.exe/download
and install it in `C:\Program Files\`. Then rename the `lib32-xxxx` directory
in `C:\Program Files\boost_x_xx_x` to `lib`.

# Compilation
## Grap 

Now that all dependencies are installed we can compile `grap`. To do
so, open a msys terminal, move to the `grap` directory and execute the
following lines: 

```
mkdir build
cd build
cmake ../src -G "Visual Studio 14" -DPYTHON_BINDING=1
make
make install
```


## Binding

To create the python binding you must specify the following option:

```
cmake -DPYTHON_BINDING=1
```

The installation can be done with command below:


```
make install
```

## Tools

The creation of the grap tools can be created with the option below:

```
cmake -DTOOLS=1
```

