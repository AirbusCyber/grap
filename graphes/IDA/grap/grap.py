#!/usr/bin/env python
"""This file is a part of the IDAgrap project."""

import sys
import threading

from pygrap import graph_free

import idaapi
from idagrap.analysis.Analysis import PatternsAnalysis
from idagrap.graph.Graph import CFG
from idagrap.patterns.Modules import MODULES
from idc import Wait

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
        # Wait for the end of autoanalysis
        Wait()

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

        print "[I] Creation of the Control Flow Graph (can take few seconds)"
        # Get the CFG of the binary
        cfg.extract()

        print "[I] Searching for patterns."
        # Group
        for grp_name, grp in MODULES.iteritems():
            print "Group: " + grp_name

            # Group->Type
            for tp_name, tp in grp.iteritems():
                print "\tType: " + tp_name

                for algo in tp:

                    # print algo
                    print "\t\tAlgorithm: %s" % algo.get_name()

                    # List of Patterns
                    for patterns in algo.get_patterns():

                        print "\t\t\tFunction: %s" % patterns.get_name()

                        # List of Pattern
                        for pattern in patterns.get_patterns():
                            print "\t\t\t\t[I] Searching for " + pattern.get_name()

                            pattern.parcourir(cfg.graph)
                            print "\t\t\t\t[I] %d %s pattern found" % (
                                len(pattern.get_matches()),
                                pattern.get_name()
                            )

                        #
                        # Analysing
                        #
                        print "\t\t\t\t[I] Linking the patterns matches which are in the same area"
                        ana = PatternsAnalysis(patterns)

                        print "\t\t\t\t[I] Filtering those patterns"
                        ana.filter_patterns()
                        ana.print_patterns()

        graph_free(cfg.graph, True)
