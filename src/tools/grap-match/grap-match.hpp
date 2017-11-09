#ifndef GRAP_MATCH_HPP
#define GRAP_MATCH_HPP

#include "Traversal.hpp"
#include "graphParser.hpp"
#include <thread>
#include <mutex>
#include <sstream>

#include "boost/filesystem.hpp"
#include <iostream>
#include <dirent.h>

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
bool filter_path(boost::filesystem::path p, bool option_filter, string extension_filter);
std::list<string> list_files(string path, bool recursive, bool option_filter, string extension_filter);
typedef std::tuple <bool, bool, bool, bool, bool, bool, ParcoursNode*, Parcours*, std::pair<std::string, FILE*>, bool, bool, vsize_t> ArgsMatchPatternToTest;
void worker_queue(list< ArgsMatchPatternToTest >* args_queue, mutex* queue_mutex, mutex* cout_mutex, bool use_tree);
void matchPatternToTest(bool optionVerbose, bool optionQuiet, bool optionDebug, bool optionShowAll, bool checkLabels, bool multipleTestFiles, Parcours* pattern_parcours, string pathTest, FILE* fileTest, bool printNoMatches, bool printAllMatches, vsize_t maxSiteSize, mutex* cout_mutex);
void matchTreeToTest(bool optionVerbose, bool optionQuiet, bool optionDebug, bool optionShowAll, bool checkLabels, bool multipleTestFiles, ParcoursNode* tree, Parcours* pattern_parcours, string pathTest, FILE* fileTest, bool printNoMatches, bool printAllMatches, vsize_t maxSiteSize, mutex* cout_mutex);

#endif
