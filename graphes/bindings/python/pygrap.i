/* File: pygrap.i */
%module pygrap

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
%include "carrays.i"
%include "stdint.i"


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


%template(ListNode) std::list<node_t *>;
%template(Match) std::map<std::string, std::list <node_t *> *>;
%template(MatchList) std::list <Match*>;
%template(RetourParcours) std::pair <vsize_t, MatchList*>;
%template(PatternsMatches) std::map<std::string, MatchList*>;
%template(RetourParcourir) std::pair<vsize_t, PatternsMatches*>;
%template(GraphCppList) std::list<graph_t *>;
