#include "GTSI-grap.h"

char optionFuncs;
char optionLabels;

void printUsage() {
  printf("Use GTSI-grap to learn and scan sites.\n");
  printf("Usage : ./GTSI-grap [options] patternFile testFile\n");
  printf("Options are :\n");
  printf("        -v verbose\n");
  printf("        -q quiet\n");
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
  bool optionQuiet = false;

  int a;
  for (a = 1; a < argc; a++) {
    if (strcmp(argv[a], "-h") == 0 || strcmp(argv[a], "-help") == 0 || strcmp(argv[a], "--help") == 0) {
      printUsage();
      return 0;
    }
    else if (strcmp(argv[a], "-v") == 0 || strcmp(argv[a], "--verbose") == 0) {
      optionVerbose = true;
    }
    else if (strcmp(argv[a], "-q") == 0 || strcmp(argv[a], "--quiet") == 0) {
      optionQuiet = true;
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

  char valence = 2;
  int n = 0;

  graph_t *gr;
  gr = getGraphFromFile(fpPattern);
  vsize_t n_pattern = gr->nodes.size;
  fclose(fpPattern);

  vsize_t siteSize = gr->nodes.size;

  Parcours *parcours = parcoursLargeur(gr, gr->root->list_id, siteSize);
//   cout << parcours->toString() << "\n";

  if (not parcours->complete) {
    printf("Warning: Pattern graph is not connected.\n");
  }
  graph_free(gr);

  gr = getGraphFromFile(fpTest);
  vsize_t n_test = gr->nodes.size;
  fclose(fpTest);

  Parcours::RetourParcours rt = parcours->parcourir(gr, siteSize, checkLabels, true, not optionQuiet);
  vsize_t count = rt.first;

  if (not optionQuiet) {
    printf("%d traversal(s) possible in %s.\n", count, pathTest);
    printf("Pattern graph (%s) has %d nodes.\nTest graph (%s) has %d nodes.\n", pathPattern, n_pattern, pathTest, gr->nodes.size);
  }
  else{
    if (count > 0){
     printf("%s %d\n", pathTest, count); 
    }
  }

  std::unordered_set < std::map < string, std::list < node_t * >*>*>set_gotten = rt.second;

  if (not set_gotten.empty()) {
    std::cout << "\nExtracted nodes:\n";
    std::unordered_set < std::map < string, std::list < node_t * >*>*>::iterator it;

    vsize_t k = 1;
    for (it = set_gotten.begin(); it != set_gotten.end(); it++) {
      std::cout << "Match " << std::dec << k << "\n";

      std::map < string, std::list < node_t * >*>*p_found_nodes = *it;
      std::map < string, std::list < node_t * >*>::iterator it2;
      for (it2 = p_found_nodes->begin(); it2 != p_found_nodes->end(); it2++) {
        std::list < node_t * >*node_list = (*it2).second;
        vsize_t k;

        if (not node_list->empty()) {
          vsize_t k = 0;
          for (std::list < node_t * >::iterator itn = node_list->begin(); itn != node_list->end(); ++itn) {
            node_t *n = *itn;
            cout << (*it2).first;
            if (node_list->size() > 1)
              cout << k;
            cout << ": ";
            if (n->hasAddress)
              cout << "0x" << std::hex << n->address << ", ";
            cout << n->csymb;
            cout << endl;
            k++;
          }
        }
      }

      k++;
    }
  }

  graph_free(gr);
}
