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
  bool optionThreads = true;
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
    else if (strcmp(argv[a], "-nt") == 0 || strcmp(argv[a], "--no-threads") == 0) {
      optionThreads = false;
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
  std::list<ArgsMatchPatternToTest>* args_queue = new std::list<ArgsMatchPatternToTest>();
  std::mutex* queue_mutex = new std::mutex();
  std::mutex* cout_mutex = new std::mutex();
  for (test_iterator = pathTests.begin();  test_iterator != pathTests.end(); test_iterator++){  
    string pathTest = (std::string) *test_iterator;
    args_queue->push_back(std::make_tuple(optionVerbose, optionQuiet, checkLabels, n_pattern, pathPattern, pattern_graph, pattern_parcours, pathTest, printNoMatches, printAllMatches));
  }
  
  if (optionThreads){
    std::list<std::thread*> threads;
    std::list<std::thread*>::iterator threads_iterator;
    
    vsize_t max_threads = 4;
    vsize_t k_thread;
    
    for (k_thread = 0; k_thread < max_threads; k_thread++){
      threads.push_back(new std::thread(worker_queue, args_queue, queue_mutex, cout_mutex));
    }
    
    for (threads_iterator = threads.begin(); threads_iterator != threads.end(); threads_iterator++){
      std::thread* thread = (std::thread*) *threads_iterator;
      thread->join();
      delete(thread);
    }
  }
  else {
    worker_queue(args_queue, queue_mutex, cout_mutex);
  }
  
  delete(queue_mutex);
  delete(cout_mutex);
  pattern_parcours->freeParcours(true);
  graph_free(pattern_graph, true);
}

void worker_queue(std::list<ArgsMatchPatternToTest>* args_queue, std::mutex* queue_mutex, std::mutex* cout_mutex){
  while(true){
    ArgsMatchPatternToTest args;
    queue_mutex->lock();
    bool found_next = false;
    if (not args_queue->empty()){
      args = args_queue->front();
      args_queue->pop_front();
      found_next = true;
    }
    queue_mutex->unlock();
    
    if (found_next){
      matchPatternToTest_tree(std::get<0>(args), std::get<1>(args), std::get<2>(args), std::get<3>(args), std::get<4>(args), std::get<5>(args), std::get<6>(args), std::get<7>(args), std::get<8>(args), std::get<9>(args), cout_mutex);
    }
    else{
      break; 
    }
  }
}

void matchPatternToTest(bool optionVerbose, bool optionQuiet, bool checkLabels, vsize_t n_pattern, string pathPattern, graph_t* pattern_graph, Parcours* pattern_parcours, string pathTest, bool printNoMatches, bool printAllMatches, std::mutex* cout_mutex){
  ostringstream out_stream;
  ostringstream err_stream;
  
  if (not optionQuiet){
    out_stream << std::endl; 
  }
  
  if (optionVerbose){
    out_stream << "Parsing test file." << endl; 
  }
  
  graph_t *test_graph = getGraphFromPath(pathTest.c_str());
  if (test_graph == NULL){
    err_stream <<  "Test graph " << pathTest << " could not be opened, aborting.\n";
    return;
  }
  
  vsize_t n_test;
  n_test = test_graph->nodes.size;
  
  if (optionVerbose){
    out_stream << "Done." << endl; 
  }
  
  // Find possible traversals of parcours in test graph
  bool getids = (not optionQuiet and not printNoMatches) or printAllMatches;
  Parcours::RetourParcours rt = pattern_parcours->parcourir(test_graph, pattern_graph->nodes.size, checkLabels, true, getids, printAllMatches);
  vsize_t count = rt.first;

  if (not optionQuiet) {
    out_stream << "Test graph (" << pathTest << ") has " << (int) test_graph->nodes.size <<  " nodes." << std::endl;
    out_stream << (int) count << " traversal(s) possible in " << pathTest << "." << std::endl;
  }
  else{
    if (count > 0){
     out_stream << pathTest << " " << count << std::endl;
    }
  }

  // Parse matches and print the extracted nodes
  std::list < std::map < string, std::list < node_t * >*>*>* list_gotten = rt.second;
  if (not list_gotten->empty()) {
//     std::cout << "\nExtracted nodes:\n";
    std::list < std::map < string, std::list < node_t * >*>*>::iterator it;

    vsize_t i = 1;
    for (it = list_gotten->begin(); it != list_gotten->end(); it++) {
      if (it != list_gotten->begin()) out_stream << std::endl;
      out_stream << "Match " << std::dec << i << "\n";

      std::map < string, std::list < node_t * >*>*p_found_nodes = *it;
      std::map < string, std::list < node_t * >*>::iterator it2;
      for (it2 = p_found_nodes->begin(); it2 != p_found_nodes->end(); it2++) {
        std::list < node_t * >*node_list = (*it2).second;

        if (not node_list->empty()) {
          vsize_t k = 0;
          for (std::list < node_t * >::iterator itn = node_list->begin(); itn != node_list->end(); ++itn) {
            node_t *n = *itn;
            out_stream << (*it2).first;
            if (node_list->size() > 1) out_stream << k;
            out_stream << ": ";
            if (n->info->has_address) out_stream << "0x" << std::hex << n->info->address << std::dec << ", ";
            out_stream << n->info->inst_str;
            out_stream << endl;
            k++;
          }
        }
      }
      i++;
      
      freeMapGotten(p_found_nodes);
    }
  }
  
  delete(list_gotten);
  graph_free(test_graph, true);
  
  cout_mutex->lock();
  std::cout << out_stream.str();
  std::cerr << err_stream.str();
  cout_mutex->unlock();
}

void matchPatternToTest_tree(bool optionVerbose, bool optionQuiet, bool checkLabels, vsize_t n_pattern, string pathPattern, graph_t* pattern_graph, Parcours* pattern_parcours, string pathTest, bool printNoMatches, bool printAllMatches, std::mutex* cout_mutex){
  ostringstream out_stream;
  ostringstream err_stream;
  
  if (not optionQuiet){
    out_stream << std::endl; 
  }
  
  if (optionVerbose){
    out_stream << "Parsing test file." << endl; 
  }
  
  graph_t *test_graph = getGraphFromPath(pathTest.c_str());
  if (test_graph == NULL){
    err_stream <<  "Test graph " << pathTest << " could not be opened, aborting.\n";
    return;
  }
  
  vsize_t n_test;
  n_test = test_graph->nodes.size;
  
  if (optionVerbose){
    out_stream << "Done." << endl; 
  }
  
  vsize_t i;
  vsize_t maxSiteSize = pattern_graph->nodes.count;

  ParcoursNode* tree = new ParcoursNode();

  bool added = tree->addGraphFromNode(pattern_graph, pattern_graph->root,
                                      pattern_graph->nodes.count, checkLabels);
    
  if (not added) {
    printf("WARNING: pattern graph was not added to traversal tree "
            "because it already exists there.\n");
  }
  
  out_stream << (int) tree->countLeaves() << " traversals reconstructed from pattern graph.\n";

  ParcoursNode::RetourParcourir rt = tree->parcourir(test_graph, maxSiteSize, checkLabels, true);
  vsize_t count = std::get<0>(rt);
  out_stream << (int) count << " traversals possible in test graph with tree.\n";
  
  tree->freeParcoursNode(); 
  
  // Parse matches and print the extracted nodes
//   std::set < std::map < string, std::list < node_t * >*>*>* set_gotten = rt.second;
//   if (not set_gotten->empty()) {
// //     std::cout << "\nExtracted nodes:\n";
//     std::set < std::map < string, std::list < node_t * >*>*>::iterator it;
// 
//     vsize_t i = 1;
//     for (it = set_gotten->begin(); it != set_gotten->end(); it++) {
//       if (it != set_gotten->begin()) out_stream << std::endl;
//       out_stream << "Match " << std::dec << i << "\n";
// 
//       std::map < string, std::list < node_t * >*>*p_found_nodes = *it;
//       std::map < string, std::list < node_t * >*>::iterator it2;
//       for (it2 = p_found_nodes->begin(); it2 != p_found_nodes->end(); it2++) {
//         std::list < node_t * >*node_list = (*it2).second;
// 
//         if (not node_list->empty()) {
//           vsize_t k = 0;
//           for (std::list < node_t * >::iterator itn = node_list->begin(); itn != node_list->end(); ++itn) {
//             node_t *n = *itn;
//             out_stream << (*it2).first;
//             if (node_list->size() > 1) out_stream << k;
//             out_stream << ": ";
//             if (n->info->has_address) out_stream << "0x" << std::hex << n->info->address << std::dec << ", ";
//             out_stream << n->info->inst_str;
//             out_stream << endl;
//             k++;
//           }
//         }
//       }
//       i++;
//       
//       freeMapGotten(p_found_nodes);
//     }
//   }
  
//   delete(set_gotten);
  graph_free(test_graph, true);
  
  cout_mutex->lock();
  std::cout << out_stream.str();
  std::cerr << err_stream.str();
  cout_mutex->unlock();
}