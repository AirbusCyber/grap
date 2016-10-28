#ifndef GRAP_MATCH_HPP
#define GRAP_MATCH_HPP

#include "Traversal.hpp"
#include "graphParser.hpp"
#include <thread>
#include <mutex>

void printUsage();
int main(int argc, char *argv[]);
typedef std::tuple <bool, bool, bool, ParcoursNode*, vsize_t, string, graph_t*, Parcours*, string, bool, bool> ArgsMatchPatternToTest;
void worker_queue(list< ArgsMatchPatternToTest >* args_queue, mutex* queue_mutex, mutex* cout_mutex, bool use_tree);
void matchPatternToTest(bool optionVerbose, bool optionQuiet, bool checkLabels, vsize_t n_pattern, string pathPattern, graph_t* pattern_graph, Parcours* pattern_parcours, string pathTest, bool printNoMatches, bool printAllMatches, std::mutex* cout_mutex);
void matchTreeToTest(bool optionVerbose, bool optionQuiet, bool checkLabels, ParcoursNode* tree, vsize_t n_pattern, string pathPattern, graph_t* pattern_graph, Parcours* pattern_parcours, string pathTest, bool printNoMatches, bool printAllMatches, mutex* cout_mutex);

#endif