#ifndef TESTS_H
#define TESTS_H

#include <iostream>
#include <limits>
#include <fstream>
#include <cstdlib>
#include "node_info.hpp"
#include "graphIO.hpp"
#include "graphParser.hpp"
#include "Traversal.hpp"
#include "my_alloc.hpp"

#ifndef _WIN32
  #include <seccomp.h>
#endif

char optionFuncs;

void drop_privileges();
int main(int argc, char *argv[]);
vsize_t print_leaf_result(bool r, string, bool);
vsize_t test_NodeInfo();
void printDescription ();
vsize_t test_GTSI (graph_t ** grPattern, size_t nPattern, graph_t * grTest, size_t expected, bool checkLabels, std::string desc, bool exportTree, string treePath);

#endif
