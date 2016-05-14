#include "GTSI-grap.hpp"

char optionFuncs;
char optionLabels;

void printUsage() {
  printf("Use GTSI-grap to learn and scan sites.\n");
  printf("Usage : ./GTSI-grap [options] patternFile testFile\n");
  printf("Options are :\n");
  printf("        -h or --help: print this message\n");
  printf("        -v or --verbose\n");
  printf("        -d or --debug\n");
  printf("        -q or --quiet\n");
  printf("        -ncl or -ncs or --no-check-labels : do not check the symbols (labels) of sites\n");
}

int main(int argc, char *argv[]) {
  optionFuncs = 0;

  if (argc <= 2) {
    printUsage();
    return 0;
  }

  FILE *fpPattern = NULL;
  char *pathPattern;
  FILE *fpTest = NULL;
  char *pathTest;
  bool learnOk = false;
  bool scanOk = false;
  bool checkLabels = true;
  bool optionVerbose = false;
  bool optionDebug = false;
  bool optionQuiet = false;

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
    else {
      if (!learnOk) {
        fpPattern = fopen(argv[a], "r");

        if (fpPattern == NULL) {
          printf("Can't open pattern graph %s\n", argv[a]);
          return 1;
        }
        pathPattern = argv[a];
        learnOk = true;
      }
      else if (!scanOk) {
        fpTest = fopen(argv[a], "r");

        if (fpTest == NULL) {
          printf("Can't open test graph %s\n", argv[a]);
          return 1;
        }
        pathTest = argv[a];
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
  vsize_t n_pattern = pattern_graph->nodes.size;
  fclose(fpPattern);
  
  if (optionVerbose){
    cout << "Done." << endl; 
  }

  // Generate Parcours from a breadth-first-search of the pattern graph
  Parcours *parcours = parcoursLargeur(pattern_graph, pattern_graph->root->list_id, pattern_graph->nodes.size);
  
  if (optionDebug){
    cout << "Pattern Parcours is:\n" << parcours->toString() << "\n";
  }

  if (not parcours->complete) {
    printf("Warning: Pattern graph is not connected.\n");
  }
  
  // Free test graph but not nodes' info: they are referenced by parcours
//   graph_free(gr, false);
  
  if (optionVerbose){
    cout << "Parsing test file." << endl; 
  }

  graph_t *test_graph = getGraphFromFile(fpTest);
  vsize_t n_test;
  n_test = test_graph->nodes.size;
  fclose(fpTest);
  
  if (optionVerbose){
    cout << "Done." << endl; 
  }

  // Find possible traversals of parcours in test graph
  Parcours::RetourParcours rt = parcours->parcourir(test_graph, pattern_graph->nodes.size, checkLabels, true, not optionQuiet);
  vsize_t count = rt.first;

  if (not optionQuiet) {
    printf("%d traversal(s) possible in %s.\n", (int) count, pathTest);
    printf("Pattern graph (%s) has %d nodes.\nTest graph (%s) has %d nodes.\n", pathPattern, (int) n_pattern, pathTest, (int) test_graph->nodes.size);
  }
  else{
    if (count > 0){
     printf("%s %d\n", pathTest, (int) count); 
    }
  }

  // Parse matches and print the extracted nodes
  std::unordered_set < std::map < string, std::list < node_t * >*>*>* set_gotten = rt.second;
  if (not set_gotten->empty()) {
    std::cout << "\nExtracted nodes:\n";
    std::unordered_set < std::map < string, std::list < node_t * >*>*>::iterator it;

    vsize_t i = 1;
    for (it = set_gotten->begin(); it != set_gotten->end(); it++) {
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
    }
  }

  delete(set_gotten);
  graph_free(pattern_graph, true);
  graph_free(test_graph, true);
}
