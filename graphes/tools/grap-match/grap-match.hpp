#ifndef GRAP_MATCH_HPP
#define GRAP_MATCH_HPP

#include "Traversal.hpp"
#include "graphParser.hpp"
#include <thread>
#include <mutex>

void printUsage();
int main(int argc, char *argv[]);
typedef std::tuple <bool, bool, bool, ParcoursNode*, string, Parcours*, string, bool, bool, vsize_t> ArgsMatchPatternToTest;
void worker_queue(list< ArgsMatchPatternToTest >* args_queue, mutex* queue_mutex, mutex* cout_mutex, bool use_tree);
void matchPatternToTest(bool optionVerbose, bool optionQuiet, bool checkLabels, string pathPattern, Parcours* pattern_parcours, string pathTest, bool printNoMatches, bool printAllMatches, vsize_t pattern_size, std::mutex* cout_mutex);
void matchTreeToTest(bool optionVerbose, bool optionQuiet, bool checkLabels, ParcoursNode* tree, string pathPattern, Parcours* pattern_parcours, string pathTest, bool printNoMatches, bool printAllMatches, vsize_t maxSiteSize, mutex* cout_mutex);

#endif