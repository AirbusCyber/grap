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

%pythoncode %{
import sys
import os
import tempfile

def compute_tree(pattern_graphs):
    tree = ParcoursNode()

    n_patterns = 0
    max_site_size = 0
    for pattern_graph in pattern_graphs:
        added = tree.addGraphFromNode(pattern_graph, pattern_graph.root, pattern_graph.nodes.count, True)

        if added:
            n_patterns += 1
            if pattern_graph.nodes.count > max_site_size:
                max_site_size = pattern_graph.nodes.count
        else:
            sys.stderr.write("WARNING: one duplicate pattern was not added.\n")

    return tree, max_site_size, n_patterns


def match_tree(tree, max_site_size, test_graph):
    rt = tree.parcourir(test_graph, max_site_size, True, True, False)

    pattern_matches = rt[1]
    return pattern_matches


def match_graph(pattern_arg, test_arg):
    if isinstance(pattern_arg, basestring):
        f = None
        if not os.path.isfile(pattern_arg):
            f=tempfile.NamedTemporaryFile() 
            f.write(pattern_arg)
            f.flush()
            pattern_path = f.name
        else:
            pattern_path = pattern_arg
        pattern_graphs_ptr = getGraphListFromPath(pattern_path)
        pattern_graphs = MakeGraphList(pattern_graphs_ptr)

        if f is not None:
            f.close()
    elif type(pattern_arg) is list:
        pattern_graphs = pattern_arg
    else:
        pattern_graphs = MakeGraphList(pattern_arg)
    
    if pattern_graphs is None or len(pattern_graphs) == 0:
        print("Pattern graph could not be opened or is empty.")
        return None
        

    if isinstance(test_arg, basestring):
        test_graph = getGraphFromPath(test_arg)
    else:
        test_graph = test_arg

    if test_graph is None:
        print("Test graph could not be opened or is empty.")
        return None

    tree, max_site_size, n_patterns = compute_tree(pattern_graphs)
    matches = match_tree(tree, max_site_size, test_graph)

    if isinstance(test_arg, basestring):
        freeGraphList(pattern_graphs_ptr, True, True)
    elif type(pattern_arg) is list:
        pass
    else:
        freeGraphList(pattern_graphs_ptr, True, True)

    return matches
%}
