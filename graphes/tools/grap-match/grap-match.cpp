#include "grap-match.hpp"
#include <boost/concept_check.hpp>

char optionFuncs;
char optionLabels;

void printUsage() {
  printf("Use grap-match to look for a pattern in a .dot test file.\n");
  printf("Usage : ./grap-match [options] patternFile testFile\n");
  printf("Options are :\n");
  printf("        -h or --help: print this message\n");
  printf("        -v or --verbose\n");
  printf("        -d or --debug\n");
  printf("        -q or --quiet\n");
  printf("        -m or --print-all-matches         : always print matched nodes (overrides getid fields)\n");
  printf("        -nm or --print-no-matches         : never print matched nodes (overrides getid fields)\n");
  printf("        -ncl or -ncs or --no-check-labels : do not check the symbols (labels) of sites\n");
}

int main(int argc, char *argv[]) {
  optionFuncs = 0;

  if (argc <= 2) {
    printUsage();
    return 0;
  }

  FILE *fpPattern = NULL;
  string pathPattern;
  FILE *fpTest = NULL;
  std::list<string> pathTests = std::list<string>();
  bool learnOk = false;
  bool scanOk = false;
  bool checkLabels = true;
  bool optionVerbose = false;
  bool optionDebug = false;
  bool optionQuiet = false;
  bool printAllMatches = false;
  bool printNoMatches = false;

  // Parsing options
  int a;
  for (a = 1; a < argc; a++) {
    if (strcmp(argv[a], "-h") == 0 || strcmp(argv[a], "--help") == 0) {
      printUsage();
      return 0;
    }
    else if (strcmp(argv[a], "-v") == 0 || strcmp(argv[a], "--verbose") == 0) {
      optionVerbose = true;
    }
    else if (strcmp(argv[a], "-q") == 0 || strcmp(argv[a], "--quiet") == 0) {
      optionQuiet = true;
    }
    else if (strcmp(argv[a], "-d") == 0 || strcmp(argv[a], "--debug") == 0) {
      optionDebug = true;
    }
    else if (strcmp(argv[a], "-ncl") == 0 || strcmp(argv[a], "-ncs") == 0 || strcmp(argv[a], "--no-check-labels") == 0) {
      checkLabels = false;
    }
    else if (strcmp(argv[a], "-m") == 0 || strcmp(argv[a], "--print-all-matches") == 0) {
      if (not printNoMatches) printAllMatches = true;
      else std::cerr << "WARNING: --print-all-matches conflicts with --print-no-matches, ignored." << std::endl;
    }
    else if (strcmp(argv[a], "-nm") == 0 || strcmp(argv[a], "--print-no-matches") == 0) {
      if (not printAllMatches) printNoMatches = true;
      else std::cerr << "WARNING: --print-no-matches conflicts with --print-all-matches, ignored." << std::endl;
    }
    else if (strcmp(argv[a], "-ncl") == 0 || strcmp(argv[a], "-ncs") == 0 || strcmp(argv[a], "--no-check-labels") == 0) {
      checkLabels = false;
    }
    else {
      if (!learnOk) {
        pathPattern = std::string(argv[a]);
        fpPattern = fopen(pathPattern.c_str(), "r");

        if (fpPattern == NULL) {
          std::cout << "Can't open pattern graph " << pathPattern << std::endl;
          return 1;
        }
        learnOk = true;
      }
      else {
        pathTests.push_back(std::string(argv[a]));
        scanOk = true;
      }
    }
  }

  if (not learnOk or not scanOk) {
    printf("Missing pattern or test graph.\n");
    printUsage();
    return 1;
  }

  if (optionVerbose){
    cout << "Parsing pattern file." << endl; 
  }
  
  graph_t *pattern_graph = getGraphFromFile(fpPattern);
  if (pattern_graph == NULL){
    std::cerr <<  "Pattern graph could not be opened, existing.\n";
    return 1;
  }
  
  vsize_t n_pattern = pattern_graph->nodes.size;
  fclose(fpPattern);
  
  if (optionVerbose){
    cout << "Done." << endl; 
  }

  // Generate Parcours from a breadth-first-search of the pattern graph
  Parcours *pattern_parcours = parcoursLargeur(pattern_graph, pattern_graph->root->list_id, pattern_graph->nodes.size);
  
  if (optionDebug){
    cout << "Pattern Parcours is:\n" << pattern_parcours->toString() << "\n";
  }

  if (not pattern_parcours->complete) {
    printf("Warning: Pattern graph is not connected.\n");
  }
  
  if (not optionQuiet){
    std::cout << "Pattern graph (" << pathPattern << ") has " << (int) n_pattern <<   " nodes." << std::endl;
  }
  
  std::list<string>::iterator test_iterator;
  for (test_iterator = pathTests.begin();  test_iterator != pathTests.end(); test_iterator++){    
    if (not optionQuiet){
      std::cout << std::endl; 
    }
    
    string pathTest = (std::string) *test_iterator;
    matchPatternToTest(optionVerbose, optionQuiet, checkLabels, n_pattern, pathPattern, pattern_graph, pattern_parcours, pathTest, printAllMatches, printNoMatches);
  }
  
  pattern_parcours->freeParcours(true);
  graph_free(pattern_graph, true);
}

void matchPatternToTest(bool optionVerbose, bool optionQuiet, bool checkLabels, vsize_t n_pattern, string pathPattern, graph_t* pattern_graph, Parcours* pattern_parcours, string pathTest, bool printNoMatches, bool printAllMatches){
  if (optionVerbose){
    cout << "Parsing test file." << endl; 
  }
  
  graph_t *test_graph = getGraphFromPath(pathTest.c_str());
  if (test_graph == NULL){
    std::cerr <<  "Test graph " << pathTest << " could not be opened, aborting.\n";
    return;
  }
  
  vsize_t n_test;
  n_test = test_graph->nodes.size;
  
  if (optionVerbose){
    cout << "Done." << endl; 
  }
  
  // Find possible traversals of parcours in test graph
  Parcours::RetourParcours rt = pattern_parcours->parcourir(test_graph, pattern_graph->nodes.size, checkLabels, true, (not optionQuiet and not printNoMatches) or printAllMatches, printAllMatches);
  vsize_t count = rt.first;

  if (not optionQuiet) {
    std::cout << "Test graph (" << pathTest << ") has " << (int) test_graph->nodes.size <<  " nodes." << std::endl;
    std::cout << (int) count << " traversal(s) possible in " << pathTest << "." << std::endl;
  }
  else{
    if (count > 0){
     std::cout << pathTest << " " << count << std::endl;
    }
  }

  // Parse matches and print the extracted nodes
  std::set < std::map < string, std::list < node_t * >*>*>* set_gotten = rt.second;
  if (not set_gotten->empty()) {
    std::cout << "\nExtracted nodes:\n";
    std::set < std::map < string, std::list < node_t * >*>*>::iterator it;

    vsize_t i = 1;
    for (it = set_gotten->begin(); it != set_gotten->end(); it++) {
      if (it != set_gotten->begin()) std::cout << std::endl;
      std::cout << "Match " << std::dec << i << "\n";

      std::map < string, std::list < node_t * >*>*p_found_nodes = *it;
      std::map < string, std::list < node_t * >*>::iterator it2;
      for (it2 = p_found_nodes->begin(); it2 != p_found_nodes->end(); it2++) {
        std::list < node_t * >*node_list = (*it2).second;

        if (not node_list->empty()) {
          vsize_t k = 0;
          for (std::list < node_t * >::iterator itn = node_list->begin(); itn != node_list->end(); ++itn) {
            node_t *n = *itn;
            cout << (*it2).first;
            if (node_list->size() > 1) cout << k;
            cout << ": ";
            if (n->info->has_address) cout << "0x" << std::hex << n->info->address << ", ";
            cout << n->info->inst_str;
            cout << endl;
            k++;
          }
        }
      }

      i++;
      
      freeMapGotten(p_found_nodes);
    }
  }
  
  delete(set_gotten);
  graph_free(test_graph, true);
}