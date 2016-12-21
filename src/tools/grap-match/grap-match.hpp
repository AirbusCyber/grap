#ifndef GRAP_MATCH_HPP
#define GRAP_MATCH_HPP

#include "Traversal.hpp"
#include "graphParser.hpp"
#include <thread>
#include <mutex>

#ifndef _WIN32
  #include <seccomp.h>
#endif

void printUsage();

#ifndef _WIN32
#ifndef NOSECCOMP
void drop_initial_privileges();
void drop_privileges();
#endif
#endif

int main(int argc, char *argv[]);
typedef std::tuple <bool, bool, bool, bool, ParcoursNode*, string, Parcours*, std::pair<std::string, FILE*>, bool, bool, vsize_t> ArgsMatchPatternToTest;
void worker_queue(list< ArgsMatchPatternToTest >* args_queue, mutex* queue_mutex, mutex* cout_mutex, bool use_tree);
void matchPatternToTest(bool optionVerbose, bool optionQuiet, bool optionShowAll, bool checkLabels, string pathPattern, Parcours* pattern_parcours, string pathTest, FILE* fileTest, bool printNoMatches, bool printAllMatches, vsize_t maxSiteSize, mutex* cout_mutex);
void matchTreeToTest(bool optionVerbose, bool optionQuiet, bool optionShowAll, bool checkLabels, ParcoursNode* tree, string pathPattern, Parcours* pattern_parcours, string pathTest, FILE* fileTest, bool printNoMatches, bool printAllMatches, vsize_t maxSiteSize, mutex* cout_mutex);

#endif