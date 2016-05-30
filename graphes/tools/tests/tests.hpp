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

#ifndef _MSC_VER
  #include <seccomp.h>
#endif

char optionFuncs;

void drop_privileges();
int main(int argc, char *argv[]);
void print_leaf_result(bool r, string, bool);
void test_NodeInfo();
void printDescription ();
void test_GTSI (graph_t ** grPattern, size_t nPattern, graph_t * grTest, size_t expected, bool checkLabels, std::string desc, bool exportTree, string treePath);

#endif
