#!/usr/bin/env python
"""This file is a part of the IDAgrap project."""

import sys
import threading

from pygrap import graph_free

import idaapi
from idagrap.analysis.Analysis import PatternsAnalysis
from idagrap.graph.Graph import CFG
from idagrap.patterns.Modules import MODULES

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

        # Group
        for grp_name, grp in MODULES.iteritems():
            print "### Group: " + grp_name

            # Group->Type
            for tp_name, tp in grp.iteritems():
                print "#### Type: " + tp_name
                print tp

                # List of Patterns
                for patterns in tp.get_patterns():

                    # List of Pattern
                    for pattern in patterns.get_patterns():
                        print "##### Search : " + pattern.get_file()

                        pattern.parcourir(cfg.graph)

                    #
                    # Analysing
                    #
                    ana = PatternsAnalysis(patterns)

                    ana.search_patterns()
                    ana.print_patterns()

        graph_free(cfg.graph, True)
