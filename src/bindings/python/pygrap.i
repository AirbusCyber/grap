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
%pythoncode "ida_helper.py"
%pythoncode "../../tools/grap_disassembler/disassembler.py"

%pythoncode %{
#!/usr/bin/env python3
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
        if isinstance(pattern, str):
            f = None
            if not os.path.isfile(pattern):
                f=tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".grapp") 
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
        
    if isinstance(test_arg, str):
        test_graph = getGraphFromPath(test_arg)
    else:
        test_graph = test_arg

    if test_graph is None:
        print("Test graph could not be opened or is empty.")
        return None

    tree, max_site_size, n_patterns = compute_tree(pattern_graph_list)
    matches = match_tree(tree, max_site_size, test_graph, print_all_matches)

    if isinstance(test_arg, str):
        freeGraphList(pattern_graphs_ptr, True, True)
    elif type(pattern_arg) is list:
        pass
    else:
        freeGraphList(pattern_graphs_ptr, True, True)

    return matches


def matches_tostring(matches, getids=True):
    if matches is None:
        print("ERROR: matches is None")
        return ""

    s = ""
    count = len(matches)
    
    if count == 0:
        s += "Matched none."
    else:
        s += "Matched: "
        first = True
        for pattern_name in matches:
            match_list = matches[pattern_name]
            n_matches = match_list.size()
            if not first:
                s += ", "
            first = False

            s += pattern_name + " (" + str(n_matches) + ") "
        s += "\n"
          
        # Parse matches and print the extracted nodes
        if getids and len(matches) > 0:
            first = True
            for pattern_name in matches:
                match_list = matches[pattern_name]

                if not first and not match_list.empty():
                    s += "\n"
                first = False
  
                i = 1
                first2 = True
                for match in match_list:
                    if not first2 and not match.empty():
                        s += "\n"
                    first2 = False
                    
                    if not match.empty():
                        if pattern_name == "":
                            s += "Match " + str(i) + "\n"
                        else:
                            s += pattern_name + ", " + "match " + str(i) + "\n"

                        for it_match in match:
                            node_list = match[it_match]
  
                            if not node_list.empty():
                                k = 0
                                for n in node_list:
                                    s += it_match
                                    if node_list.size() > 1:
                                        s += str(k)
                                    
                                    s += ": "
                                    if n.info.has_address:
                                        s += hex(n.info.address) + ", "
                                    s += n.info.inst_str
                                    s += "\n"
                                    k += 1
                    i += 1
    return s


def parse_int_hex(s):
    if s.isdigit():
        return int(s)
    elif "0x" in s:
        try:
            return int(s, 16)
        except:
            return None
    return None


def parse_first_address(s):
    split = s.split("0x")
    if len(split) >= 2:
        rest = split[1]
        s = "0x"
        for c in rest:
            if c in "0123456789abcdef":
                s += c
        if len(s) >=3:
            n = int(s, 16)
            return n


def parse_first_indirect(s):
    if "+" in s or "-" in s or "[" not in s:
        return None

    for w in s.split(" "):
        if "[" in w and "]" in w:
            w_splitted = w.split("[")[1]
            if "]" in w_splitted:
                w_splitted2 = w_splitted.split("]")[0]
                int_p = parse_int_hex(w_splitted2)
                if int_p is not None:
                    return int_p
    return None
    

def parse_first_immediate(s):
    if "+" in s or "-" in s:
        return None 

    for w in s.split(" "):
        int_p = parse_int_hex(w)
        if int_p is not None:
            return int_p
    return None

%}

