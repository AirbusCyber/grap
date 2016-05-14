#ifndef TESTS_CPP
#define TESTS_CPP

#include "tests.hpp"

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
  std::cout << "  Learning: via traversal tree and with a single traversal (when there is only one pattern graph).\n";
  std::cout << "  Testing: via traversal tree (with sites) and with a single traversal.\n";
  std::cout << "  The result is the sum, for each node in the test graph, of the number of traversals possible from this node.\n";
  std::cout << "  Note that if two pattern graphs are identical, they will produce the same traversal and this traversal will only be counted once.\n";
  std::cout << "\n";

  std::cout << "Test 0:  [manual] small identical graphs.\n";
  std::cout << "Test 1:  [manual] small test graph with one child more (to a leaf) than pattern.\n";
  std::cout << "Test 2:  [manual] small test graph with one edge more (leaf -> leaf) than pattern.\n";
  std::cout << "Test 3:  [manual] small test graph with one child more (to a leaf) and an edge more (leaf -> root) than pattern.\n";
  std::cout << "Test 4:  [manual] same as test 3 but with different labels.\n";
  std::cout << "Test 5:  [manual] small test graph with two JCC (that have two children).\n";
  std::cout << "Test 6:  [manual] bigger test graph with 4 pattern graphs.\n";
  std::cout << "Test 7:  [manual] small graph with node repetition (INST*).\n";
  std::cout << "Test 8:  [manual] small graph with node repetition (INST*) with extraction.\n";
  std::cout << "Test 9:  [manual] generic pattern on Mirage sample.\n";
  std::cout << "Test 10: [manual] generic pattern on Mirage sample with extraction.\n";
  std::cout << "Test 11: [manual] simple loop pattern on Mirage sample.\n";
  std::cout << "Test 12: [reference to 9] same as test 9  but with PandaPE's disassembler.\n";
  std::cout << "Test 13: [reference to 10] same as test 10 but with PandaPE's disassembler.\n";
  std::cout << "Test 14: [reference to 11] same as test 11 but with PandaPE's disassembler. PandaPE does not loop rep instructions (hence 12 -> 2).\n";
  std::cout << "Test 15: [manual] Non-regression test for bug in graph traversal (child number i in -k>i terms was not checked).\n";
  std::cout << "Test 16: [manual] Test for lazy repeat option (zero out of three match).\n";
  std::cout << "Test 17: [manual] Test for lazy repeat option (one out of three match).\n";
}

string Red = "\x1b[1;31m";
string Green = "\x1b[1;32m";
string Blue = "\x1b[1;33m";
string Color_Off = "\x1b[0m";

void drop_privileges(){
  scmp_filter_ctx ctx;
  
  // release: SCMP_ACT_KILL
  // use SCMP_ACT_TRAP or SCMP_ACT_TRACE(0) for debug
  ctx = seccomp_init(SCMP_ACT_TRAP); 

  // TODO: remove at least the open syscall by dropping privileges at a later stage
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  
  int r = seccomp_load(ctx);
  RELEASE_ASSERT(r == 0);
}

int main(int argc, char *argv[]) {
  //TODO: fix seccomp
//   drop_privileges();

  
  if (argc >= 2) {
    printDescription();
    return 1;
  }
  
  test_NodeInfo();

  string color;
  graph_t **grPattern = nullptr;
  graph_t *grPattern2 = nullptr;
  graph_t *grTest = nullptr;

  FILE* fpPattern;
  FILE* fpTest;
  
  vsize_t i = 0;
  while (i < std::numeric_limits < vsize_t >::max()) {
    std::string dirPath = "tests_graphs/test" + std::to_string(i) + "/";
    std::string pathTest = dirPath + "test.dot";

    // read expected results
    size_t expected_gtsi_with_labels = 0;
    size_t expected_gtsi_no_labels = 0;
    std::ifstream f_res_gtsi(dirPath + "expected_gtsi");

    if (f_res_gtsi.good()) {
      string sLine;

      getline(f_res_gtsi, sLine);
      expected_gtsi_with_labels = (size_t) atoi(sLine.c_str());
      getline(f_res_gtsi, sLine);
      expected_gtsi_no_labels = (size_t) atoi(sLine.c_str());
    }

    f_res_gtsi.close();

    fpTest = fopen(pathTest.c_str(), "r");
    if (fpTest == NULL) {
//       fprintf(stderr, "Can't open pattern or test graph\n");
      break;
    }
    cout << Blue;
    std::cout << "Running test " + std::to_string(i) + "\n";
    cout << Color_Off;

    vsize_t j = 0;
    vsize_t nPattern = 0;
//     grPattern = (graph_t **) std::malloc(0*sizeof(graph_t *));

    while (j < std::numeric_limits < vsize_t >::max()) {
      std::string pathPattern = dirPath + "pattern_" + to_string(j) + ".dot";
//       fpPattern = fopen(pathPattern.c_str(), "r");

//       if (fpPattern == NULL)
//         break;
//       fclose(fpPattern);
      
      grPattern = (graph_t **) realloc_or_quit(grPattern, (j + 1) * sizeof(graph_t *));
      grPattern[j] = getGraphFromPath(pathPattern.c_str());
      
      if (grPattern[j] == NULL){
       break; 
      }
      
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

    for (j=0; j<nPattern; j++){
      graph_free(grPattern[j], true);
    }
    
    graph_free(grTest, true);
    
    std::cout << "\n";
    i++;
  }
}

void test_NodeInfo(){
  std::cout << "Testing comparisons (NodeList)." << endl;
  NodeInfo* np = new NodeInfo();
  NodeInfo* nt = new NodeInfo();

  
  std::cout << "Testing bool_equals: ";
  CondNode* cn = new CondNode();
  cn->pattern_field = (void* NodeInfo::*) &NodeInfo::has_address;
  cn->test_field = (void* NodeInfo::*) &NodeInfo::has_address;
  cn->comparison = ComparisonFunEnum::bool_equals;
  cn->children = new std::list<CondNode*>();
    
  np->has_address = false;
  nt->has_address = false;
  bool r = cn->evaluate(np, nt);
  print_leaf_result(r, "= ", false);
  
  np->has_address = false;
  nt->has_address = true;
  r = cn->evaluate(np, nt);
  print_leaf_result(not r, "!= ", true);
  
  delete cn;
  
  
  std::cout << "Testing bool_test_true: ";
  cn = new CondNode();
  cn->test_field = (void* NodeInfo::*) &NodeInfo::has_address;
  cn->comparison = ComparisonFunEnum::bool_test_true;
  cn->children = new std::list<CondNode*>();
    
  nt->has_address = true;
  r = cn->evaluate(np, nt);
  print_leaf_result(r, "= ", false);
  
  nt->has_address = false;
  r = cn->evaluate(np, nt);
  print_leaf_result(not r, "!= ", true);
  
  delete cn;
  
  
  std::cout << "Testing str_equals: ";
  cn = new CondNode();
  cn->pattern_field = (void* NodeInfo::*) &NodeInfo::inst_str;
  cn->test_field = (void* NodeInfo::*) &NodeInfo::inst_str;
  cn->comparison = ComparisonFunEnum::str_equals;
  cn->children = new std::list<CondNode*>();
    
  np->inst_str = "xor";
  nt->inst_str = "xor";
  r = cn->evaluate(np, nt);
  print_leaf_result(r, "= ", false);
  
  nt->inst_str = "mov";
  r = cn->evaluate(np, nt);
  print_leaf_result(not r, "!= ", true);
  
  delete cn;
  
  
  std::cout << "Testing uint8_equals: ";
  cn = new CondNode();
  cn->pattern_field = (void* NodeInfo::*) &NodeInfo::maxChildrenNumber;
  cn->test_field = (void* NodeInfo::*) &NodeInfo::childrenNumber;
  cn->comparison = ComparisonFunEnum::uint8t_equals;
  cn->children = new std::list<CondNode*>();
    
  np->maxChildrenNumber = 2;
  nt->childrenNumber = 2;
  r = cn->evaluate(np, nt);
  print_leaf_result(r, "= ", false);
  
  np->maxChildrenNumber = 1;
  r = cn->evaluate(np, nt);
  print_leaf_result(not r, "!= ", true);

  delete cn;
  
  
  // Shoud return true iff pattern >= test
  std::cout << "Testing uint8_gt: ";
  cn = new CondNode();
  cn->pattern_field = (void* NodeInfo::*) &NodeInfo::maxChildrenNumber;
  cn->test_field = (void* NodeInfo::*) &NodeInfo::childrenNumber;
  cn->comparison = ComparisonFunEnum::uint8t_gt;
  cn->children = new std::list<CondNode*>();
    
  np->maxChildrenNumber = 2;
  nt->childrenNumber = 2;
  r = cn->evaluate(np, nt);
  print_leaf_result(r, "= ", false);
  
  np->maxChildrenNumber = 1;
  r = cn->evaluate(np, nt);
  print_leaf_result(not r, "< ", false);
  
  np->maxChildrenNumber = 3;
  r = cn->evaluate(np, nt);
  print_leaf_result(r, "> ", true);

  delete cn;
  
  
  std::cout << "Testing vsizet_equals: ";
  cn = new CondNode();
  cn->pattern_field = (void* NodeInfo::*) &NodeInfo::address;
  cn->test_field = (void* NodeInfo::*) &NodeInfo::address;
  cn->comparison = ComparisonFunEnum::vsizet_equals;
  cn->children = new std::list<CondNode*>();
    
  np->address = 2;
  nt->address = 2;
  r = cn->evaluate(np, nt);
  print_leaf_result(r, "= ", false);
  
  np->address = 1;
  r = cn->evaluate(np, nt);
  print_leaf_result(not r, "!= ", true);
  
  
  // cn evaluates to false
  std::cout << "Testing not and not not: ";
  std::list<CondNode*>* children = new std::list<CondNode*>();
  children = new std::list<CondNode*>();
  children->push_front(cn);
  CondNode* cn_not = new CondNode(children, UnOpEnum::logical_not);
  
  r = cn_not->evaluate(np, nt);
  print_leaf_result(r, "! ", false);
  
  CondNode* cn_not2 = new CondNode();
  cn_not2->children = new std::list<CondNode*>();
  cn_not2->children->push_front(cn_not);
  cn_not2->unary_operator = UnOpEnum::logical_not;
  r = cn_not2->evaluate(np, nt);
  print_leaf_result(not r, "!! ", true);
  
  
  std::cout << "Testing or on multiple operands: ";
  std::list<CondNode*>* children2 = new std::list<CondNode*>();
  children2 = new std::list<CondNode*>();
  children2->push_front(cn);
  children2->push_front(cn_not);
  
  CondNode* cn_or = new CondNode(children2, BinOpEnum::logical_or);
  r = cn_or->evaluate(np, nt);
  print_leaf_result(r, "2 ", false);
  
  cn_or->children->push_front(cn_not2);
  r = cn_or->evaluate(np, nt);
  print_leaf_result(r, "3 ", true);
  
  
  std::cout << "Testing and on multiple operands: ";
  CondNode* cn_and = new CondNode();
  cn_and->children = new std::list<CondNode*>();
  cn_and->children->push_front(cn);
  cn_and->children->push_front(cn_not);
  cn_and->binary_operator =  BinOpEnum::logical_and;
  r = cn_and->evaluate(np, nt);
  print_leaf_result(not r, "2 ", false);
  
  cn_and->children->push_front(cn_not2);
  r = cn_and->evaluate(np, nt);
  print_leaf_result(not r, "3 ", true);
  
  cout << endl;
}

void test_GTSI(graph_t ** grPattern, size_t nPattern, graph_t * grTest, size_t expected, bool checkLabels, std::string desc, bool exportTree, string treePath) {
  string color;
  std::cout << "GTSI" + desc + ":\n";

  vsize_t i;
  vsize_t siteSize = grPattern[0]->nodes.count;
  for (i = 1; i < nPattern; i++) {
    if (grPattern[i]->nodes.count < siteSize)
      siteSize = grPattern[i]->nodes.count;
  }

  ParcoursNode tree = ParcoursNode();

  for (i = 0; i < nPattern; i++) {    
    bool added = tree.addGraphFromNode(grPattern[i], grPattern[i]->root, siteSize, checkLabels);

    if (not added){
      printf("WARNING: pattern graph %d was not added to traversal tree because it already exists there.\n", (int) i);
    }
  }

  if (exportTree){
    tree.saveParcoursNodeToDot(treePath);
  }
  
  printf("%d traversals reconstructed from pattern graph.\n", (int) tree.countLeaves());

  vsize_t count = tree.parcourir(grTest, siteSize, checkLabels, true);
  if (count != expected) {
    color = Red;
  }
  else {
    color = Green;
  }
  printf("%s%d traversals possible in test graph (expected: %d) with tree.%s\n", color.c_str(), (int) count, (int) expected, Color_Off.c_str());
  

  if (nPattern == 1) {    
    Parcours *p = parcoursLargeur(grPattern[0], grPattern[0]->root->list_id, siteSize);
    Parcours::RetourParcours rt = p->parcourir(grTest, siteSize, checkLabels, true, false);
    delete p;
    vsize_t count2 = rt.first;

    if (count2 != expected) {
      color = Red;
    }
    else {
      color = Green;
    }
    printf("%s%d traversals possible in test graph (expected: %d) with a single traversal.%s\n", color.c_str(), (int) count2, (int) expected, Color_Off.c_str());
  
    delete(rt.second);
  }
  
}


void print_leaf_result(bool r, string desc, bool end_bool){
  string end_str = "";
  if (end_bool) end_str = "\n";
  
  if (r){
    cout << Green << desc << Color_Off << end_str;
  }
  else{
    cout << Red << desc << Color_Off << end_str;
  }
}

#endif