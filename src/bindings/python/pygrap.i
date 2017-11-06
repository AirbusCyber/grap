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

  FILE *f = fopen(filename, "wb");
  graph_fprint(f, graph);
  fclose(f);
}

graph_t* getGraphFromFile(const char *filename) {

  graph_t* gr = NULL;
  FILE *f = fopen(filename, "rb");

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

%pythoncode "dot_writer.py"
%pythoncode "../../tools/grap_disassembler/disassembler.py"

%pythoncode %{
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
import os
import tempfile

def get_disassembled_graph(bin_data=None, bin_path=None, raw=False, raw_64=False, verbose=False):
    if bin_data is not None or bin_path is not None:
        dot_file=tempfile.NamedTemporaryFile()

        if dot_file is not None:
            path=disassemble_file(bin_data=bin_data, bin_path=bin_path, dot_path=dot_file.name, raw=raw, raw_64=raw_64, verbose=verbose)
            
            graph = None
            if path == dot_file.name:
                graph=getGraphFromPath(path)
            dot_file.close()
            return graph
    return None
    

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
            sys.stderr.write("WARNING: One duplicate or incomplete pattern was not added.\n")

    return tree, max_site_size, n_patterns


def match_tree(tree, max_site_size, test_graph, print_all_matches=False):
    rt = tree.parcourir(test_graph, max_site_size, True, True, print_all_matches)

    pattern_matches = rt[1]
    return pattern_matches


def match_graph(pattern_arg, test_arg, print_all_matches=False):
    if type(pattern_arg) is list:
        pattern_arg_list = pattern_arg
    else:
        pattern_arg_list = [pattern_arg]
    
    pattern_graph_list = []
    for pattern in pattern_arg_list:
        if isinstance(pattern, basestring):
            f = None
            if not os.path.isfile(pattern):
                f=tempfile.NamedTemporaryFile() 
                f.write(pattern)
                f.flush()
                pattern_path = f.name
            else:
                pattern_path = pattern

            pattern_graphs_ptr = getGraphListFromPath(pattern_path)
            pattern_graphs = MakeGraphList(pattern_graphs_ptr)
        
            if pattern_graphs is None or len(pattern_graphs) == 0:
                print("Pattern graph could not be opened or is empty.")
            else:
                pattern_graph_list += pattern_graphs

            if f is not None:
                f.close()
        else:
            pattern_graph_list.append(pattern)
        
    if isinstance(test_arg, basestring):
        test_graph = getGraphFromPath(test_arg)
    else:
        test_graph = test_arg

    if test_graph is None:
        print("Test graph could not be opened or is empty.")
        return None

    tree, max_site_size, n_patterns = compute_tree(pattern_graph_list)
    matches = match_tree(tree, max_site_size, test_graph, print_all_matches)

    if isinstance(test_arg, basestring):
        freeGraphList(pattern_graphs_ptr, True, True)
    elif type(pattern_arg) is list:
        pass
    else:
        freeGraphList(pattern_graphs_ptr, True, True)

    return matches
%}

