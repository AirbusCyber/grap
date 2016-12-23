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
  printf("        -nt or --no-thread                : don't multithread (defaut: 4 threads)\n");
  printf("        -ncl or -ncs or --no-check-labels : do not check the symbols (labels) of sites\n");
  printf("        -st or --single-traversal         : use single traversal algorithm (default with one pattern)\n");
  printf("        -sa or --show-all                 : show all tested files (not default when quiet, default otherwise)\n");
  printf("        -t or --tree                      : use tree algorithm (default with multiple patterns)\n");
}

#ifndef _WIN32
#ifndef NOSECCOMP
void drop_initial_privileges(){
  scmp_filter_ctx ctx;
  
  // release: SCMP_ACT_KILL
  // use SCMP_ACT_TRAP or SCMP_ACT_TRACE(0) for debug
  ctx = seccomp_init(SCMP_ACT_KILL); 

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(seccomp), 0);
  
  int r = seccomp_load(ctx);
  RELEASE_ASSERT(r == 0);
}

void drop_privileges(){
    scmp_filter_ctx ctx;
  
  // release: SCMP_ACT_KILL
  // use SCMP_ACT_TRAP or SCMP_ACT_TRACE(0) for debug
  ctx = seccomp_init(SCMP_ACT_ALLOW); 

  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(prctl), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(seccomp), 0);
  
  int r = seccomp_load(ctx);
  RELEASE_ASSERT(r == 0);
}
#endif
#endif

int main(int argc, char *argv[]) {
  #ifndef _WIN32
  #ifndef NOSECCOMP
    drop_initial_privileges();
  #endif
  #endif
  
  optionFuncs = 0;

  if (argc <= 2) {
    printUsage();
    return 0;
  }

  FILE *fpPattern = NULL;
  string pathPattern;
  FILE *fpTest = NULL;
  std::list<std::pair<std::string, FILE*>> testsInfo = std::list<std::pair<std::string, FILE*>>();
  bool learnOk = false;
  bool scanOk = false;
  bool checkLabels = true;
  bool optionVerbose = false;
  bool optionDebug = false;
  bool optionQuiet = false;
  bool optionThreads = true;
  bool printAllMatches = false;
  bool printNoMatches = false;
  bool optionTree = false;
  bool optionSingleTraversal = false;
  bool optionShowAll = false;

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
    else if (strcmp(argv[a], "-t") == 0 || strcmp(argv[a], "--tree") == 0) {
      optionTree = true;
    }
    else if (strcmp(argv[a], "-st") == 0 || strcmp(argv[a], "--single-traversal") == 0) {
      optionSingleTraversal = true;
    }
    else if (strcmp(argv[a], "-sa") == 0 || strcmp(argv[a], "--show-all") == 0) {
      optionShowAll = true;
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
          std::cerr << "ERROR: Can't open pattern graph " << pathPattern << std::endl;
          return 1;
        }
        learnOk = true;
      }
      else {
        std::string path = std::string(argv[a]);
        FILE* fp = fopen(path.c_str(), "r");

        if (fp == NULL) {
          std::cerr << "WARNING: Can't open test graph " << path << std::endl;
        }
        else{
          testsInfo.push_back(std::pair<std::string, FILE*>(path, fp)); 
          scanOk = true;
        }
      }
    }
  }
  
  #ifndef _WIN32
  #ifndef NOSECCOMP
    if (optionVerbose){
      std::cout << "Dropping privileges (seccomp)." << std::endl;
    }
    drop_privileges();
  #endif
  #endif

  if (not learnOk or not scanOk) {
    std::cerr << "ERROR: Missing pattern or test graph." << std::endl;
    printUsage();
    return 1;
  }
  
  bool use_tree = not optionSingleTraversal;
  if (optionVerbose){
    std::cout << "Using algorithm: ";
    if (use_tree){
      std::cout << "tree" << std::endl; 
    }
    else{
      std::cout << "single traversal" << std::endl; 
    }
  }
  
  GraphList* pattern_graphs = getGraphListFromFile(fpPattern);
  if (pattern_graphs == NULL or pattern_graphs->size == 0){
    std::cerr <<  "Pattern graph could not be opened or is empty, existing.\n";
    return 1;
  }
  
  fclose(fpPattern);
  
  graph_t* pattern_graph;
  ParcoursNode* tree;
  Parcours *pattern_parcours;
  vsize_t maxSiteSize;
  
  if (not use_tree){
    if (pattern_graphs->size >= 2){
      std::cerr << "WARNING: only the first pattern will be processed with the single traversal algorithm." << std::endl;
    }
    
    pattern_graph = popfreeFirstGraph(pattern_graphs);
    
    if (pattern_graph == NULL){
      std::cerr << "ERROR: No pattern found, exiting." << std::endl;
      return 1; 
    }
    
    maxSiteSize = pattern_graph->nodes.size;
    
    // Generate Parcours from the pattern graph
    pattern_parcours = parcoursGen(pattern_graph, pattern_graph->root->list_id, pattern_graph->nodes.size);
    
    if (optionDebug){
      cout << "Pattern Parcours is:\n" << pattern_parcours->toString() << "\n";
    }

    if (not pattern_parcours->complete) {
      std::cerr << "WARNING: Pattern graph is not connected." << std::endl;
    }
    
    if (not optionQuiet){
      std::cout << "Pattern graph (" << pathPattern << ") has " << (int) maxSiteSize <<   " nodes." << std::endl;
    }
  }
  else {
    tree = new ParcoursNode();

    vsize_t k;
    vsize_t n_patterns = 0;
    maxSiteSize = 0;
    for (k = 0; k < pattern_graphs->size; k++){
      graph_t* gr = pattern_graphs->graphes[k];
      bool added = tree->addGraphFromNode(gr, gr->root, gr->nodes.count, checkLabels);
      if (added){
        n_patterns++;
        if (gr->nodes.count > maxSiteSize){
          maxSiteSize = gr->nodes.count; 
        }
      }
      else {
        std::cerr << "WARNING: one duplicate pattern was not added." << std::endl; 
      }
    }
    
    if (not optionQuiet){
      std::cout << (int) n_patterns << " unique patterns added to tree." << std::endl;
    }    
    
    if (n_patterns == 0) {
      std::cerr << "ERROR: No pattern found, exiting." << std::endl;
      return 1;
    }
  }
  
  std::list<std::pair<std::string, FILE*>>::iterator test_iterator;
  std::list<ArgsMatchPatternToTest>* args_queue = new std::list<ArgsMatchPatternToTest>();
  std::mutex* queue_mutex = new std::mutex();
  std::mutex* cout_mutex = new std::mutex();
  for (test_iterator = testsInfo.begin();  test_iterator != testsInfo.end(); test_iterator++){  
    std::pair<std::string, FILE*> testInfo = (std::pair<std::string, FILE*>) *test_iterator;
    args_queue->push_back(std::make_tuple(optionVerbose, optionQuiet, optionShowAll, checkLabels, tree, pathPattern, pattern_parcours, testInfo, printNoMatches, printAllMatches, maxSiteSize));
  }
  
  if (optionThreads){
    std::list<std::thread*> threads;
    std::list<std::thread*>::iterator threads_iterator;
    
    vsize_t max_threads = 4;
    vsize_t k_thread;
    
    for (k_thread = 0; k_thread < max_threads; k_thread++){
      threads.push_back(new std::thread(worker_queue, args_queue, queue_mutex, cout_mutex, use_tree));
    }
    
    for (threads_iterator = threads.begin(); threads_iterator != threads.end(); threads_iterator++){
      std::thread* thread = (std::thread*) *threads_iterator;
      thread->join();
      delete(thread);
    }
  }
  else {
    worker_queue(args_queue, queue_mutex, cout_mutex, use_tree);
  }
  
  delete(args_queue);
  delete(queue_mutex);
  delete(cout_mutex);
  if (use_tree){
    freeGraphList(pattern_graphs, true, true);
    tree->freeParcoursNode(); 
  }
  else{
    pattern_parcours->freeParcours(true);
    graph_free(pattern_graph, true);
  }
  
  return 0;
}

void worker_queue(std::list<ArgsMatchPatternToTest>* args_queue, std::mutex* queue_mutex, std::mutex* cout_mutex, bool use_tree){
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
      std::pair<std::string, FILE*> pair = std::get<7>(args);
      std::string test_path = pair.first;
      FILE* test_file = pair.second;
      
      if (use_tree){
        matchTreeToTest(std::get<0>(args), std::get<1>(args), std::get<2>(args), std::get<3>(args), std::get<4>(args), std::get<5>(args), std::get<6>(args), test_path, test_file, std::get<8>(args), std::get<9>(args), std::get<10>(args), cout_mutex);
      }
      else{
        matchPatternToTest(std::get<0>(args), std::get<1>(args), std::get<2>(args), std::get<3>(args), std::get<5>(args), std::get<6>(args), test_path, test_file, std::get<8>(args), std::get<9>(args), std::get<10>(args), cout_mutex);
      }
    }
    else{
      break; 
    }
  }
}

void matchPatternToTest(bool optionVerbose, bool optionQuiet, bool optionShowAll, bool checkLabels, string pathPattern, Parcours* pattern_parcours, string pathTest, FILE* fileTest, bool printNoMatches, bool printAllMatches, vsize_t maxSiteSize, std::mutex* cout_mutex){
  ostringstream out_stream;
  ostringstream err_stream;
  
  if (not optionQuiet){
    out_stream << std::endl; 
  }
  
  if (optionVerbose){
    out_stream << "Parsing test file." << endl; 
  }
  
  graph_t *test_graph = getGraphFromFile(fileTest);
  if (test_graph == NULL){
    err_stream <<  "Test graph " << pathTest << " could not be opened, aborting.\n";
    
    cout_mutex->lock();
    std::cout << out_stream.str();
    std::cerr << err_stream.str();
    cout_mutex->unlock();
    
    return;
  }
  
  vsize_t n_test;
  n_test = test_graph->nodes.size;
  
  if (optionVerbose){
    out_stream << "Done." << endl; 
  }
  
  // Find possible traversals of parcours in test graph
  bool getids = (not optionQuiet and not printNoMatches) or printAllMatches;
  Parcours::RetourParcours rt = pattern_parcours->parcourir(test_graph, maxSiteSize, checkLabels, true, getids, printAllMatches);
  vsize_t count = rt.first;

  if (not optionQuiet) {
    out_stream << "Test graph (" << pathTest << ") has " << (int) test_graph->nodes.size <<  " nodes." << std::endl;
    out_stream << (int) count << " traversal(s) possible in " << pathTest << "." << std::endl;
  }
  else{
    if (count > 0 or optionShowAll){
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

      Match* match = *it;
      std::map < string, std::list < node_t * >*>::iterator it2;
      for (it2 = match->begin(); it2 != match->end(); it2++) {
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
      
      freeMatch(match);
    }
  }
  
  delete(list_gotten);
  graph_free(test_graph, true);
  
  cout_mutex->lock();
  std::cout << out_stream.str();
  std::cerr << err_stream.str();
  cout_mutex->unlock();
}

void matchTreeToTest(bool optionVerbose, bool optionQuiet, bool optionShowAll, bool checkLabels, ParcoursNode* tree, string pathPattern, Parcours* pattern_parcours, string pathTest, FILE* fileTest, bool printNoMatches, bool printAllMatches, vsize_t maxSiteSize, std::mutex* cout_mutex){
  ostringstream out_stream;
  ostringstream err_stream;
  
  if (not optionQuiet){
    out_stream << std::endl; 
  }
  
  if (optionVerbose){
    out_stream << "Parsing test file." << endl; 
  }
  
  graph_t *test_graph = getGraphFromFile(fileTest);
  if (test_graph == NULL){
    err_stream <<  "Test graph " << pathTest << " could not be opened, aborting.\n";
    
    cout_mutex->lock();
    std::cout << out_stream.str();
    std::cerr << err_stream.str();
    cout_mutex->unlock();
    
    return;
  }
  
  vsize_t n_test;
  n_test = test_graph->nodes.size;
  
  if (optionVerbose){
    out_stream << "Done." << endl; 
  }

  bool getids = (not optionQuiet and not printNoMatches) or printAllMatches;
  ParcoursNode::RetourParcourir rt = tree->parcourir(test_graph, maxSiteSize, checkLabels, getids, printAllMatches);
  vsize_t count = std::get<0>(rt);
  PatternsMatches* pattern_matches = std::get<1>(rt);
  PatternsMatches::iterator it_patternsmatches;
  
  if (not optionQuiet){
    out_stream << "Test graph (" << pathTest << ") has " << (int) test_graph->nodes.size <<  " nodes." << std::endl;
    out_stream << (int) count << " traversal(s) possible in " << pathTest;
    
    if (count == 0){
      out_stream << "." << std::endl;
    }
    else {
      out_stream << ": ";
      for (it_patternsmatches = pattern_matches->begin(); it_patternsmatches != pattern_matches->end(); it_patternsmatches++){
        std::string leaf_name = it_patternsmatches->first;
        MatchList* match_list = it_patternsmatches->second;
        vsize_t n_matches = match_list->size();
        
        if (it_patternsmatches != pattern_matches->begin()){
          out_stream << ", ";
        }
        out_stream << leaf_name << " (" << n_matches << ")";
      }
      out_stream << std::endl;
    }
  }
  else {
    if (count > 0 or optionShowAll){
      out_stream << pathTest;
      if (count > 0){
        out_stream << " - ";
      }
      for (it_patternsmatches = pattern_matches->begin(); it_patternsmatches != pattern_matches->end(); it_patternsmatches++){
        std::string leaf_name = it_patternsmatches->first;
        MatchList* match_list = it_patternsmatches->second;
        vsize_t n_matches = match_list->size();
        
        if (it_patternsmatches != pattern_matches->begin()){
          out_stream << ", ";
        }
        out_stream << leaf_name << " (" << n_matches << ")";
      }
      out_stream << std::endl;
    }
  }
  
  // Parse matches and print the extracted nodes
  if (getids and not pattern_matches->empty()) {
    for (it_patternsmatches = pattern_matches->begin(); it_patternsmatches != pattern_matches->end(); it_patternsmatches++){
      std::string leaf_name = it_patternsmatches->first;
      MatchList* match_list = it_patternsmatches->second;
//       if (it_patternsmatches != pattern_matches->begin() and match_list->begin() != match_list->end()) out_stream << "lklk" << std::endl;
  //     std::cout << "\nExtracted nodes:\n";
      MatchList::iterator it_match_list;

      vsize_t i = 1;
      bool matches_all_empty = true;
      ostringstream matches_out_stream;
      for (it_match_list = match_list->begin(); it_match_list != match_list->end(); it_match_list++) {
        Match* match = *it_match_list;
        
        if (not match->empty()){
          matches_all_empty = false;
          if (it_match_list != match_list->begin()){
            matches_out_stream << std::endl;
          }
          if (leaf_name == ""){
            matches_out_stream << "Match " << std::dec << i << std::endl;
          }
          else {
            matches_out_stream << leaf_name << ", " << "match " << std::dec << i << std::endl;
          }

          Match::iterator it_match;
          for (it_match = match->begin(); it_match != match->end(); it_match++) {
            std::list < node_t * >*node_list = (*it_match).second;

            if (not node_list->empty()) {
              vsize_t k = 0;
              for (std::list < node_t * >::iterator itn = node_list->begin(); itn != node_list->end(); ++itn) {
                node_t *n = *itn;
                matches_out_stream << (*it_match).first;
                if (node_list->size() > 1) matches_out_stream << k;
                matches_out_stream << ": ";
                if (n->info->has_address) matches_out_stream << "0x" << std::hex << n->info->address << std::dec << ", ";
                matches_out_stream << n->info->inst_str;
                matches_out_stream << endl;
                k++;
              }
            }
          }
        }
        i++;
      }
      
      if (not matches_all_empty and it_patternsmatches != pattern_matches->end()){
        out_stream <<  std::endl;
      }
      out_stream << matches_out_stream.str();
    }
  }
  
  freePatternsMatches(pattern_matches, true);
  graph_free(test_graph, true);
  
  cout_mutex->lock();
  std::cout << out_stream.str();
  std::cerr << err_stream.str();
  cout_mutex->unlock();
}