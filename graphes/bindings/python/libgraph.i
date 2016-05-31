/* File: libgraph.i */
%module libgraph

%{
#define SWIG_FILE_WITH_INIT
#include "graphIO.hpp"
#include "graph.hpp"
#include "node.hpp"
#include "node_list.hpp"
#include "nodeIO.hpp"
#include "graphParser.hpp"
#include "Expression.hpp"
#include "node_info.hpp"
#include "my_alloc.hpp"
#include "utils-gtsi.hpp"
#include "Traversal.hpp"
#include "ga_types.hpp"

%}
%include "std_pair.i"
%include "std_map.i"
%include "std_set.i"
%include "std_string.i"
%include "std_vector.i"
%include "std_list.i"


%include "graphIO.hpp"
%include "graph.hpp"
%include "node.hpp"
%include "node_list.hpp"
%include "nodeIO.hpp"
%include "graphParser.hpp"
%include "Expression.hpp"
%include "node_info.hpp"
%include "my_alloc.hpp"
%include "utils-gtsi.hpp"
%include "Traversal.hpp"
%include "ga_types.hpp"




%inline %{	
void graph_fprint(const char *filename, graph_t* graph) {

  FILE *f = fopen(filename, "w");
  graph_fprint(f, graph);
  fclose(f);
}

graph_t* getGraphFromFile(const char *filename) {

  graph_t* gr = NULL;
  FILE *f = fopen(filename, "r");

  if( f == NULL)
	  return NULL;
  
  gr = getGraphFromFile(f);
  fclose(f);

  return gr;
}

%}

%template (ListNode) std::list<node_t *>;
%template(MapStrNode) std::map<string,  std::list<node_t *>*>;
%template(SetGotten) std::set<std::map<string, std::list<node_t *> *> *>;
%template(PairRT) std::pair<vsize_t,
	 std::set<std::map<string, std::list<node_t *> *> *> *>;
