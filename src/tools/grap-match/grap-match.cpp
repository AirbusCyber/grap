#include "grap-match.hpp"
#include <boost/concept_check.hpp>

char optionFuncs;
char optionLabels;

void printUsage() {
  printf("Use grap-match to look for a pattern file (.grapp) in a test file (.grapcfg).\n");
  printf("For standard usage please use the python wrapper (grap).\n");
  printf("Usage : ./grap-match [options] patternFile [-p patternFile] testFile\n");
  printf("Options are :\n");
  printf("        -h or --help: print this message\n");
  printf("        -v or --verbose\n");
  printf("        -d or --debug\n");
  printf("        -q or --quiet\n");
  printf("        -r or --recursive                 : analyzes .grapt files recursively (testFile must be a directory)\n");
  printf("        -m or --print-all-matches         : always print matched nodes (overrides getid fields)\n");
  printf("        -nm or --print-no-matches         : never print matched nodes (overrides getid fields)\n");
  printf("        -nt or --no-thread                : don't multithread (defaut: 4 threads)\n");
  printf("        -ncl or -ncs or --no-check-labels : do not check the symbols (labels) of sites\n");
  printf("        -st or --single-traversal         : use single traversal algorithm (default with one pattern)\n");
  printf("        -sa or --show-all                 : show all tested files (not default when quiet, default otherwise)\n");
  printf("        -t or --tree                      : use tree algorithm (default with multiple patterns)\n");
  printf("        -p or --pattern                   : include additional pattern file, can be used multiple times\n");
}

#ifndef _WIN32
#ifndef NOSECCOMP
void drop_initial_privileges(){
  scmp_filter_ctx ctx;
  
  // release: SCMP_ACT_KILL
  // use SCMP_ACT_TRAP or SCMP_ACT_TRACE(0) for debug
  ctx = seccomp_init(SCMP_ACT_KILL); 

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
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

  // libc requires an open in _int_free to /proc/sys/vm/overcommit_memory with flags==0x80000 (O_CLOEXEC)
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_NE, 0x80000));
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

  std::list<FILE*> filePatternList;
  std::list<std::string> pathPatternList;
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
  bool multipleTestFiles = false;
  bool optionRecursive = false;

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
      #ifdef DEBUG
      optionDebug = true;
      #else
      std::cerr << "WARNING: Debug option only available when compiled in debug mode, ignored." << std::endl;
      #endif
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
    else if (strcmp(argv[a], "-r") == 0 || strcmp(argv[a], "--recursive") == 0) {
      optionRecursive = true;
    }
    else if (strcmp(argv[a], "-p") == 0 || strcmp(argv[a], "--pattern") == 0) {
      if (a + 1 < argc){
        std::string s = std::string(argv[a+1]);
        
        FILE* fpPattern = fopen(s.c_str(), "rb");
        if (fpPattern == NULL) {
          std::cerr << "WARNING: Can't open pattern graph " << s << "." << std::endl;
        }
        else {
          pathPatternList.push_back(s);
          filePatternList.push_back(fpPattern);
        }
        
        a++;
      }
      else {
        std::cerr << "WARNING: -p or --pattern needs pattern path" << std::endl;
      }
    }
    else {
      if (!learnOk) {
        std::string s = std::string(argv[a]);
        
        FILE* fpPattern = fopen(s.c_str(), "rb");
        if (fpPattern == NULL) {
          std::cerr << "WARNING: Can't open pattern graph " << s << "." << std::endl;
        }
        else {
          pathPatternList.push_back(s); 
          filePatternList.push_back(fpPattern); 
        }
        
        learnOk = true;
      }
      else {
        std::string path = std::string(argv[a]);
        std::list<string> files;
        
        if (boost::filesystem::is_directory(path)){
          if (optionRecursive){
            files = list_files(path, true, true, ".grapcfg");
          }
          else {
            files = list_files(path, false, true, ".grapcfg");
          }
        }
        else {
          files = std::list<string>();
          files.push_back(path);
        }
        
        if (not files.empty()){
          std::list<string>::iterator it;
          for (it = files.begin(); it != files.end(); it++){
            string p = *it;
            FILE* fp = fopen(p.c_str(), "rb");

            if (fp == nullptr) {
              std::cerr << "WARNING: Can't open test graph " << p << std::endl;
              if (testsInfo.size() >= 1024){
                // TODO Reorganize (with seccomp) to open files later
                std::cerr << "HINT: You might need to increase the maximum number of file descriptors per process (ulimit -n)" << std::endl;
              }
            }
            else{
              testsInfo.push_back(std::pair<std::string, FILE*>(p, fp)); 
              scanOk = true;
              if (testsInfo.size() >= 2){
                multipleTestFiles = true;
              }
            }
          }
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

  if (not learnOk or not scanOk or pathPatternList.empty()) {
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

  GraphCppList patternList;
  std::list<FILE*>::iterator it;
  for (it = filePatternList.begin(); it != filePatternList.end(); it++){
    FILE* fp = *it;
    GraphList* pattern_graphs = getGraphListFromFile(fp);
    GraphCppList tmpPatternList = MakeGraphList(pattern_graphs);
    patternList.insert(patternList.end(), tmpPatternList.begin(), tmpPatternList.end());
    fclose(fp);
  }
  
  if (patternList.empty()){
    std::cerr <<  "ERROR: No pattern graph could be imported, exiting." << std::endl;
    return 1;
  }
  
  graph_t* pattern_graph = nullptr;
  ParcoursNode* tree = nullptr;
  Parcours *pattern_parcours = nullptr;
  vsize_t maxSiteSize;
  
  if (not use_tree){
    if (patternList.size() >= 2){
      std::cerr << "WARNING: Only the first pattern will be processed with the single traversal algorithm." << std::endl;
    }
    
    pattern_graph = patternList.front();
    
    if (pattern_graph == NULL){
      std::cerr << "ERROR: No pattern found, exiting." << std::endl;
      return 1;
    }
       
    if (pattern_graph->has_wildcards){
      std::cerr << "WARNING: Edge wildcards are not handled by the single traversal algorithm." << std::endl; 
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
    
    if (optionDebug){
      std::cout << "Pattern graph has " << (int) maxSiteSize <<   " nodes." << std::endl;
    }
  }
  else {
    tree = new ParcoursNode();

    vsize_t k;
    vsize_t n_patterns = 0;
    maxSiteSize = 0;
    GraphCppList::iterator it_graph;
    for (it_graph = patternList.begin(); it_graph != patternList.end(); it_graph++){
      graph_t* gr = *it_graph;
      bool added = tree->addGraphFromNode(gr, gr->root, gr->nodes.count, checkLabels);
      if (added){
        n_patterns++;
        if (gr->nodes.count > maxSiteSize){
          maxSiteSize = gr->nodes.count; 
        }
      }
      else {
        std::cerr << "WARNING: One duplicate or incomplete pattern was not added." << std::endl; 
      }
    }
    
    if (optionVerbose){
      std::cout << (int) n_patterns << " unique pattern(s) found." << std::endl << std::endl;
    }
    
    if (optionDebug){
      std::cout << "Grap tree:" << std::endl << tree->toDot() << std::endl; 
    }
  }
  
  std::list<std::pair<std::string, FILE*>>::iterator test_iterator;
  std::list<ArgsMatchPatternToTest>* args_queue = new std::list<ArgsMatchPatternToTest>();
  std::mutex* queue_mutex = new std::mutex();
  std::mutex* cout_mutex = new std::mutex();
  for (test_iterator = testsInfo.begin();  test_iterator != testsInfo.end(); test_iterator++){  
    std::pair<std::string, FILE*> testInfo = (std::pair<std::string, FILE*>) *test_iterator;
    args_queue->push_back(std::make_tuple(optionVerbose, optionQuiet, optionDebug, optionShowAll, checkLabels, multipleTestFiles, tree, pattern_parcours, testInfo, printNoMatches, printAllMatches, maxSiteSize));
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
    freeGraphList(patternList, true, true);
    tree->freeParcoursNode(); 
  }
  else{
    pattern_parcours->freeParcours(true);
    graph_free(pattern_graph, true);
  }
  
  for (test_iterator = testsInfo.begin();  test_iterator != testsInfo.end(); test_iterator++){
    fclose((*test_iterator).second);
  }
  
  return 0;
}

bool filter_path(boost::filesystem::path p, bool option_filter, string extension_filter){  
  if (not boost::filesystem::is_directory(p)){
    if (option_filter){
      if (p.extension() == extension_filter){
        return true;
      }
    }
    else{
      return true;
    }
  }

  return false;
}

std::list<string> list_files(string path, bool recursive, bool option_filter, string extension_filter){
  std::list<string> pathList = std::list<string>();
  
  try {
    if (recursive){
      boost::filesystem::recursive_directory_iterator end, dir(path);
      for (end; dir != end; dir++) {
        #ifndef _WIN32
        // Try to avoid being denied a dir open on linux
        // TODO: make it work better and avoid race condition (how to do that with boost ?)
        if (boost::filesystem::is_directory(dir->path())){
          DIR* dir_test = opendir(dir->path().string().c_str());
          if (dir_test != NULL) {
            closedir (dir_test);
          }
          else {
            dir.no_push(); 
          }
        }
        #endif
        
        if (filter_path(dir->path(), option_filter, extension_filter)){
          pathList.push_back(dir->path().string());
        }
      }
    }
    else {
      boost::filesystem::directory_iterator end, dir(path);
      for (end; dir != end; dir++) {
        if (filter_path(dir->path(), option_filter, extension_filter)){
          pathList.push_back(dir->path().string());
        }
      }
    }
  }
   catch(std::exception const& ex) {
    std::cerr << "WARNING: an error occurred while listing directory " << path << std::endl;
  } 
  
  return pathList;
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
      std::pair<std::string, FILE*> pair = std::get<8>(args);
      std::string test_path = pair.first;
      FILE* test_file = pair.second;
      
      if (use_tree){
        matchTreeToTest(std::get<0>(args), std::get<1>(args), std::get<2>(args), std::get<3>(args), std::get<4>(args), std::get<5>(args), std::get<6>(args), std::get<7>(args), test_path, test_file, std::get<9>(args), std::get<10>(args), std::get<11>(args), cout_mutex);
      }
      else{
        matchPatternToTest(std::get<0>(args), std::get<1>(args), std::get<2>(args), std::get<3>(args), std::get<4>(args), std::get<5>(args), std::get<7>(args), test_path, test_file, std::get<9>(args), std::get<10>(args), std::get<11>(args), cout_mutex);
      }
    }
    else{
      break; 
    }
  }
}

void matchPatternToTest(bool optionVerbose, bool optionQuiet, bool optionDebug, bool optionShowAll, bool checkLabels, bool multipleTestFiles, Parcours* pattern_parcours, string pathTest, FILE* fileTest, bool printNoMatches, bool printAllMatches, vsize_t maxSiteSize, std::mutex* cout_mutex){
  ostringstream out_stream;
  ostringstream err_stream;
  
  if (optionDebug){
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
  
  if (optionDebug){
    out_stream << "Done." << endl; 
  }
  
  // Find possible traversals of parcours in test graph
  bool getids = (not optionQuiet and not printNoMatches) or printAllMatches;
  Parcours::RetourParcours rt = pattern_parcours->parcourir(test_graph, maxSiteSize, checkLabels, true, getids, printAllMatches);
  vsize_t count = rt.first;

  if (not optionQuiet){
    out_stream << pathTest << " - " << (int) test_graph->nodes.size <<  " instructions" << std::endl;
    out_stream << (int) count << " matche(s) in " << pathTest << std::endl;
  }
  else{
    if (count > 0 or optionShowAll){
     out_stream << pathTest << " " << count << std::endl;
    }
  }

  // Parse matches and print the extracted nodes
  std::list < std::map < string, std::list < node_t * >*>*>* list_gotten = rt.second;
  if (not list_gotten->empty()) {
    std::list < std::map < string, std::list < node_t * >*>*>::iterator it;

    vsize_t i = 1;
    for (it = list_gotten->begin(); it != list_gotten->end(); it++) {
      out_stream << std::endl;
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

void matchTreeToTest(bool optionVerbose, bool optionQuiet, bool optionDebug, bool optionShowAll, bool checkLabels, bool multipleTestFiles, ParcoursNode* tree, Parcours* pattern_parcours, string pathTest, FILE* fileTest, bool printNoMatches, bool printAllMatches, vsize_t maxSiteSize, std::mutex* cout_mutex){
  ostringstream out_stream;
  ostringstream err_stream;
  
  if (optionDebug){
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
  
  if (optionDebug){
    out_stream << "Done." << endl; 
  }

  bool getids = (not optionQuiet and not printNoMatches) or printAllMatches;
  ParcoursNode::RetourParcourir rt = tree->parcourir(test_graph, maxSiteSize, checkLabels, getids, printAllMatches);
  vsize_t count = std::get<0>(rt);
  PatternsMatches* pattern_matches = std::get<1>(rt);
  PatternsMatches::iterator it_patternsmatches;
  
  if (not optionQuiet){
    out_stream << pathTest << " - " << (int) test_graph->nodes.size <<  " instructions" << std::endl;
    
    if (count == 0){
      out_stream << (int) count << " match";
      out_stream << std::endl;
    }
    else {
      out_stream << (int) count << " matches";
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
      out_stream << pathTest << " (" << (int) test_graph->nodes.size << ")";
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
            matches_out_stream << leaf_name << " - " << "match " << std::dec << i << std::endl;
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
  
  if (multipleTestFiles and not optionQuiet){
    out_stream << "---" << std::endl;
  }
  
  cout_mutex->lock();
  std::cout << out_stream.str();
  std::cerr << err_stream.str();
  cout_mutex->unlock();
}
