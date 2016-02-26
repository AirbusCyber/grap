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

extern "C" {
#include "graphIO.h"
//#include "libGraphBinAlgo.h"
#include "graphParser.h"
}
#include "Traversal.hpp"
char optionFuncs;

void print_leaf_result(bool r, string, bool);
void test_NodeInfo();
void printDescription ();
void test_GTSI (graph_t ** grPattern, int nPattern, graph_t * grTest, int expected, bool checkLabels, std::string desc, bool exportTree, string treePath);

#endif
