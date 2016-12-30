Pour les tests (sur la partie graphes):
cd graphes/
./tests

Tests avec -fsanitize=address:
cmake -DCMAKE_BUILD_TYPE=Debug .
./tests

Tests avec Valgrind:
cmake -DCMAKE_BUILD_TYPE=Valgrind .
make
valgrind --max-stackframe=2000344 --leak-check=full --track-origins=yes --show-reachable=yes ./tests

## Build types
The default build type is "Release", the others can be obtained through cmake options (such as `cmake -DCMAKE_BUILD_TYPE=Debug ../src`):

- Release: best performance, default
- Debug: with debug information and address sanitizer
- Valgrind: with debug information, good to use when debugging with valgrind
- Errall: all gcc warnings activated, all warnings are fatal to build


