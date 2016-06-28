#!/usr/bin/env python
"""This file is a part of the IDAgrap project."""

import sys
import threading

from pygrap import freeMapGotten, getGraphFromFile, graph_free, parcoursLargeur

import idaapi
from idagrap.graph.Graph import CFG

sys.setrecursionlimit(400000000)

def PLUGIN_ENTRY():
    """Plugin entry point."""
    return IDAgrapPlugin()


class IDAgrapPlugin(idaapi.plugin_t):
    """Grap plugin."""

    flags = idaapi.PLUGIN_PROC
    comment = "IDA Grap"
    help = "IDA Grap"
    wanted_name = "IDAgrap"
    wanted_hotkey = "Shift+G"

    def init(self):
        """Initialization of the IDAgrap plugin."""
        return idaapi.PLUGIN_KEEP

    def term(self):
        """Exit of the IDAgrap plugin."""
        pass

    def run(self, arg):
        """Core of the IDAgrap plugin.

        Args:
            arg: Plugin argument.
        """
        thread = threading.Thread(target=self.main, args=(arg,))
        # Fixed the stack size to 10M
        threading.stack_size(0x100000 * 10)
        thread.start()

    def main(self, arg):
        """Main of the IDAgrap plugin.

        Args:
            arg: Plugin argument.
        """
        cfg = CFG()

        # Get the CFG of the binary
        cfg.extract()

        pattern_graph = getGraphFromFile("E:\pattern1.dot")
        n_pattern = pattern_graph.nodes.size

        parcours = parcoursLargeur(pattern_graph, pattern_graph.root.list_id,
                                   n_pattern)
        rt = parcours.parcourir(cfg.graph, n_pattern, True,
                                True, True)
        count = rt.first
        set_gotten = rt.second

        print "%d traversal(s) possible in %s." % (count, "cryptowall")
        print "Pattern graph (%s) has %d nodes." % ("pattern", n_pattern)

        if not set_gotten.empty():
            print("\nExtracted nodes:")

            for f_index, found_nodes in enumerate(set_gotten, start=1):
                print("Match %d" % f_index)

                for getid, node_list in found_nodes.iteritems():
                    if not node_list.empty():
                        for n_index, node in enumerate(node_list):

                            print "%s" % getid,

                            if node_list.size() > 1:
                                print "%d" % n_index,

                            print ": ",

                            if node.info.has_address:
                                print "0x%X, " % node.info.address,

                            print "%s" % node.info.inst_str

            freeMapGotten(found_nodes)
            parcours.freeParcours(True)
            graph_free(pattern_graph, True)
            graph_free(cfg.graph, True)
