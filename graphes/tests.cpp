#include "tests.h"

void printDescription() {
  std::cout << "Tests are done as follows.\n";
  std::cout << "There are test folders. Each test folder:\n";
  std::cout << "  Tests:\n";
  std::cout << "    pattern_*.dot are learnt.\n";
  std::cout << "    test.dot is tested against learnt graphs.\n";
  std::cout << "    Once with symbols (labels) checking, once without.\n";
  std::cout << "\n";
  std::cout << "GTSI:\n";
  std::cout << "  Pattern graphs are cut into sites (site size: minimum size between pattern graphs).\n";
  std::cout << "  Learning: via traversal tree.\n";
  std::cout << "  Testing: via traversal tree (with sites)\n";
  std::cout << "  The result is the sum, for each node in the test graph, of the number of traversals possible from this node.\n";
  std::cout << "\n";
//   std::cout << "Considerations:\n";
//   std::cout << "  1 - GTSI and SIDT use trees and won't process twice the same pattern graph ; Ullmann will. Hence one should be careful not to submit identical pattern graphs to Ullmann and expect to compare results with GTSI or SIDT.\n";
//   std::cout << "  2 - On these tests the libraries are used in a way that allow easy comparison of results and the expected SIDT <= GTSI <= Ullmann. This is because the pattern graphs always have the same size which is the site size. Be careful that this is not always the case. \n";
//   std::cout << "\n";
  std::cout << "Test 0:  [manual] small identical graphs.\n";
  std::cout << "Test 1:  [manual] small test graph with one child more (to a leaf) than pattern.\n";
  std::cout << "Test 2:  [manual] small test graph with one edge more (leaf -> leaf) than pattern.\n";
  std::cout << "Test 3:  [manual] small test graph with one child more (to a leaf) and an edge more (leaf -> root) than pattern.\n";
  std::cout << "Test 4:  [manual] same as test 3 but with different labels.\n";
  std::cout << "Test 5:  [manual] small test graph with two JCC (that have two children).\n";
  std::cout << "Test 6:  [manual] bigger test graph with 4 pattern graphs.\n";
  std::cout << "Test 7:  [manual] small graph with node repetition (INST*).\n";
  std::cout << "Test 8:  [manual] small graph with node repetition (INST*) with extraction.\n";
  std::cout << "Test 9:  [reference] generic pattern on Mirage sample.\n";
  std::cout << "Test 10: [reference] generic pattern on Mirage sample with extraction.\n";
  std::cout << "Test 11: [reference] simple loop pattern on Mirage sample.\n";
}

string Red = "\e[1;31m";
string Green = "\e[1;32m";
string Blue = "\e[1;33m";
string Color_Off = "\e[0m";

int main(int argc, char *argv[]) {
  if (argc >= 2) {
    printDescription();
    return 1;
  }

  string color;
  graph_t **grPattern;
  graph_t *grTest;

  FILE *fpPattern;
  FILE *fpTest;

  int i = 0;
  while (i < std::numeric_limits < int >::max()) {
    std::string dirPath = "tests_graphs/test" + std::to_string(i) + "/";
    std::string pathTest = dirPath + "test.dot";

    // read expected results
    int expected_gtsi_with_labels = -1;
    int expected_gtsi_no_labels = -1;
    std::ifstream f_res_gtsi(dirPath + "expected_gtsi");

    if (f_res_gtsi.good()) {
      string sLine;

      getline(f_res_gtsi, sLine);
      expected_gtsi_with_labels = atoi(sLine.c_str());
      getline(f_res_gtsi, sLine);
      expected_gtsi_no_labels = atoi(sLine.c_str());
    }

    f_res_gtsi.close();

    if (fpTest == NULL) {
//       fprintf(stderr, "Can't open pattern or test graph\n");
      break;
    }
    cout << Blue;
    std::cout << "Running test " + std::to_string(i) + "\n";
    cout << Color_Off;

    int j = 0;
    int nPattern = 0;
    grPattern = (graph_t **) std::malloc(sizeof(graph_t *));

    while (j < std::numeric_limits < int >::max()) {
      std::string pathPattern = dirPath + "pattern_" + to_string(j) + ".dot";
      grPattern = (graph_t **) std::realloc(grPattern, (j + 1) * sizeof(graph_t *));
      fpPattern = fopen(pathPattern.c_str(), "r");

      if (fpPattern == NULL)
        break;
      fclose(fpPattern);
      grPattern[j] = getGraphFromPath(pathPattern.c_str());
//       graph_fprint(stdout, grPattern[j]);
//       graph_from_file(&grPattern[j], fpPattern);
      j++;
      nPattern++;
    }

    if (nPattern == 0)
      break;

    grTest = getGraphFromPath(pathTest.c_str());

//     graph_fprint (stdout, grTest);

    // GTSIs
    test_GTSI(grPattern, nPattern, grTest, expected_gtsi_with_labels, true, " (Check labels)", true, "gtsi-l-" + std::to_string(i) + ".dot");
    test_GTSI(grPattern, nPattern, grTest, expected_gtsi_no_labels, false, " (Don't check labels)", true, "gtsi-nl-" + std::to_string(i) + ".dot");

    std::cout << "\n";
    i++;
  }
}

void test_GTSI(graph_t ** grPattern, int nPattern, graph_t * grTest, int expected, bool checkLabels, std::string desc, bool exportTree, string treePath) {
  string color;
  std::cout << "GTSI" + desc + ":\n";

  int i;
  int siteSize = grPattern[0]->nodes.count;
  for (i = 1; i < nPattern; i++) {
    if (grPattern[i]->nodes.count < siteSize)
      siteSize = grPattern[i]->nodes.count;
  }

  ParcoursNode *tree = new ParcoursNode();

  for (i = 0; i < nPattern; i++) {
    bool added = tree->addGraphFromNode(grPattern[i], grPattern[i]->root, siteSize, checkLabels);

    if (not added)
      printf("WARNING: pattern graph %d was not added to traversal tree because it already exists there.\n", i);
  }

  tree->saveParcoursNodeToDot(treePath);

  printf("%d traversals reconstructed from pattern graph.\n", tree->countLeaves());

  vsize_t count = tree->parcourir(grTest, siteSize, checkLabels, true);
  if (count != expected) {
    color = Red;
  }
  else {
    color = Green;
  }
  printf("%s%d traversals possible in test graph (expected: %d) with tree.%s\n", color.c_str(), count, expected, Color_Off.c_str());

  if (nPattern == 1) {
    Parcours *p = parcoursLargeur(grPattern[0], grPattern[0]->root->list_id, siteSize);
    Parcours::RetourParcours rt = p->parcourir(grTest, siteSize, checkLabels, true, true);
    vsize_t count2 = rt.first;

    if (rt.first != expected) {
      color = Red;
    }
    else {
      color = Green;
    }
    printf("%s%d traversals possible in test graph (expected: %d) with a single traversal.%s\n", color.c_str(), count2, expected, Color_Off.c_str());
  }

}
