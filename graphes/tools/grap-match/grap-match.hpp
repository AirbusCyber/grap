#ifndef GTSIGRAP_H
#define GTSIGRAP_H

#include "Traversal.hpp"
#include "graphParser.hpp"

void printUsage();
int main(int argc, char *argv[]);
void matchPatternToTest(bool optionVerbose, bool optionQuiet, bool checkLabels, vsize_t n_pattern, string pathPattern, graph_t* pattern_graph, Parcours* pattern_parcours, string pathTest);

#endif