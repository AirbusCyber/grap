#ifndef TESTS_H
#define TESTS_H

#include <sys/time.h>
#include <semaphore.h>
#include <stdlib.h>
#include <iostream>
#include <limits>
#include <fstream>
#include <cstdlib>
#include "node_info.hpp"
#include "graphIO.hpp"
#include "graphParser.hpp"
#include "Traversal.hpp"
char optionFuncs;

void print_leaf_result(bool r, string, bool);
void test_NodeInfo();
void printDescription ();
void test_GTSI (graph_t ** grPattern, size_t nPattern, graph_t * grTest, size_t expected, bool checkLabels, std::string desc, bool exportTree, string treePath);

#endif
