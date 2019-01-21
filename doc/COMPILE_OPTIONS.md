# Compilation options
Compilation options are chosen with cmake (`cmake -DSECCOMP=1 ../src` for instance):

- TOOLS: build tools (grap-match, todot and test binaries), default
- PYTHON_BINDING: build python bindings, default
- SECCOMP: enable support of the grap-match binary for privilege drop through seccomp, **not default**

On GNU/Linux enabling seccomp on grap-match restricts the number of system calls available to the binary for security purposes. 
In particular the "open" syscall is mostly unavailable after the initial argument parsing.

Note that seccomp is only implemented within the `grap-match` binary and its wrapper (grap and grap.py scripts), and **not** within the bindings (hence not within the IDA plugin).

The seccomp filters have only been testing against the latest Ubuntu LTS (18.04.1).
