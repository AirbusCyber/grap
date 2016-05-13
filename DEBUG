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

