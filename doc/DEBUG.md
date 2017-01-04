# Build types
The default build type is "Release", the others can be obtained through cmake options (such as `cmake -DCMAKE_BUILD_TYPE=Debug ../src`):

- Release: best performance, default
- Debug: with debug information and address sanitizer
- Valgrind: with debug information, good to use when debugging with valgrind
- Errall: all gcc warnings activated, all warnings are fatal to build

## Valgrind
This command will work to try the ./test binary against Valgrind:

- `valgrind --max-stackframe=2000344 --leak-check=full --track-origins=yes --show-reachable=yes ./tests`

