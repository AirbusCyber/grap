#!/usr/bin/env python
import argparse
import sys
from pygrap import *


def parse_arguments():
    """
    Parse the arguments of the program.
    """
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()

    # Arguments
    group.add_argument("-v", "--verbosity", action="count", default=0,
                       help="increase output verbosity")
    group.add_argument("-q", "--quiet", action="store_true", default=False)
    parser.add_argument("-ncl", "--no-check-labels", dest="checklabels", action="store_false", default=True,
                        help="do not check the labels of sites")
    parser.add_argument("-st", "--single-traversal", dest="singletraversal", action="store_true", default=False,
                        help="use the single traversal algorithm (default: tree)")
    parser.add_argument("-m", "--print-all-matches", dest="allmatches", action="store_true", default=False,
                        help="always print matched nodes (overrides getid fields)")
    parser.add_argument("-nm", "--print-no-matches", dest="nomatches", action="store_true", default=False,
                        help="never print matched nodes (overrides getid fields)")
    parser.add_argument("patternFile", help="The pattern to search")
    parser.add_argument("testFile", nargs='+', help="The file in which we will lookfor the pattern")

    return parser.parse_args()


def main():
    """
    Main
    """
    args = parse_arguments()

    if args.verbosity >= 1:
        print("Parsing pattern file.")

    pattern_graphs_ptr = getGraphListFromPath(args.patternFile)
    pattern_graphs = MakeGraphList(pattern_graphs_ptr)

    if args.verbosity >= 1:
        print("Done.")
        
    if not args.singletraversal:
        tree, max_site_size, n_patterns = compute_tree(pattern_graphs, args)

    if args.verbosity >= 2:
        print "Grap tree:"
        print tree.toDot()

    first = True
    for test_path in args.testFile:
        if args.verbosity >= 1:
            print("Parsing test file.")

        test_graph = getGraphFromFile(test_path)
        n_test = test_graph.nodes.size

        if args.verbosity >= 1:
            print("Done.")

        if not first:
            if not args.quiet:
                print ""
        first = False

        if args.singletraversal:
            if len(pattern_graphs) >= 1:
                match_single_traversal(pattern_graphs[0], n_test, test_path, test_graph, args)
            else:
                sys.exit(1)
        else:
            match_tree(tree, max_site_size, test_path, test_graph, args)
            
        graph_free(test_graph, True)
    freeGraphList(pattern_graphs_ptr, True, True)

    # if not args.singletraversal:
    #     tree.freeParcoursNode()


def match_single_traversal(pattern_graph, n_test, test_path, test_graph, args):
    n_pattern = pattern_graph.nodes.size
  
    if not args.quiet:
        print("Pattern graph (%s) has %d nodes." % (args.patternFile, n_pattern))
  
    parcours = parcoursGen(pattern_graph, pattern_graph.root.list_id, n_pattern)
    if args.verbosity >= 2:
        print("Pattern Parcours is:\n" + parcours.toString() + "\n")
  
    rt = parcours.parcourir(test_graph, n_pattern, args.checklabels, True, not args.quiet, False)
    count = rt[0]

    if not args.quiet:
        print("\nTest graph (%s) has %d nodes." % (test_path, n_test))
        print("%d traversal(s) possible in %s." % (count, test_path))
    elif count >= 1:
        print("%s %d" % (test_path, count))

    list_gotten = rt.second

    if not list_gotten.empty():
        print("\nExtracted nodes:")

        # For each match
        for f_index, found_nodes in enumerate(list_gotten, start=1):
            print("Match %d" % f_index)

            for getid, node_list in found_nodes.iteritems():
                if not node_list.empty():
                    for n_index, node in enumerate(node_list):
                        s = str(getid)

                        if node_list.size() > 1:
                            s += str(n_index)

                        s += ": "

                        if node.info.has_address:
                            s += hex(node.info.address) + ", "

                        s += node.info.inst_str
                        print s

    parcours.freeParcours(True);
    del list_gotten


def compute_tree(pattern_graphs, args):
    tree = ParcoursNode()

    n_patterns = 0
    max_site_size = 0
    for pattern_graph in pattern_graphs:
        added = tree.addGraphFromNode(pattern_graph, pattern_graph.root, pattern_graph.nodes.count, args.checklabels)

        if added:
            n_patterns += 1
            if pattern_graph.nodes.count > max_site_size:
                max_site_size = pattern_graph.nodes.count
        else:
            print("WARNING: One duplicate pattern was not added.")

    if not args.quiet:
        print n_patterns, "unique patterns added to tree."
        print ""

    return tree, max_site_size, n_patterns


def match_tree(tree, max_site_size, test_path, test_graph, args):
    getids = (not args.quiet and not args.nomatches) or args.allmatches
    rt = tree.parcourir(test_graph, max_site_size, args.checklabels, getids, args.allmatches)
  
    count = rt[0]
    pattern_matches = rt[1]
    
    if not args.quiet:
        print "Test graph (" + test_path + ") has", test_graph.nodes.size, "nodes."
        print count, "traversal(s) possible in", test_path,
        
        if count == 0:
            print "."
        else:
            print ": ",
            first = True
            for pattern_name in pattern_matches:
                match_list = pattern_matches[pattern_name]
                n_matches = match_list.size()
                if not first:
                    print ", ",
                first = False
  
                print pattern_name, "(" + str(n_matches) + ")",
            print ""
    else:
        if count > 0:
            print test_path + " - ",
            
            first = True
            for pattern_name in pattern_matches:
                match_list = pattern_matches[pattern_name]
                n_matches = match_list.size()
                
                if not first:
                    print ", ",
                first = False
                
                print pattern_name, "(" + str(n_matches) + ")",
            
            print ""
      
    # Parse matches and print the extracted nodes
    if getids and len(pattern_matches) > 0:
        first = True
        for pattern_name in pattern_matches:
            match_list = pattern_matches[pattern_name]

            if not first and not match_list.empty():
                print ""
            first = False
  
            i = 1
            first2 = True
            for match in match_list:
                if not first2 and not match.empty():
                    print ""
                first2 = False
                
                if not match.empty():
                    if pattern_name == "":
                        print "Match", str(i)
                    else:
                        print pattern_name + ", " + "match " +str(i)

                    for it_match in match:
                        node_list = match[it_match]
  
                        if not node_list.empty():
                            k = 0
                            for n in node_list:
                                print it_match,
                                if node_list.size() > 1:
                                    print k,
                                
                                print ": ",
                                if n.info.has_address:
                                    print hex(n.info.address) + ", ",
                                print n.info.inst_str,
                                print ""
                                k += 1
                i += 1
    
    freePatternsMatches(pattern_matches, True)

if __name__ == '__main__':
    main()
    sys.exit(0)
