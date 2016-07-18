#!/usr/bin/env python

import threading

from idagrap.analysis.Analysis import PatternsAnalysis
from idagrap.graph.Graph import CFG
from idagrap.patterns.Modules import MODULES


class CryptoIdentifier:
    """Cryptographic identifier.

    This class aims to organize the identification of cryptography.

    graph (CFG): Control flow graph.
    _analyzed_patterns: (PatternsAnalysis list): Hold the analyzed patterns.
    """

    def __init__(self):
        """Initialization"""

        self.graph = CFG()
        self._analyzed_patterns = []

    def analyzing(self):
        """Analyze the graph.

        Analyzing the graph for patterns.
        """
        thread = threading.Thread(target=self._analyzing)
        # Fixed the stack size to 10M
        threading.stack_size(0x100000 * 10)
        thread.start()
        thread.join()


    def _analyzing(self):

        cfg = self.graph

        #
        # Clear
        #
        # Clear the graph
        if cfg.graph:
            cfg.clear_graph()

        # Clear the list
        del self._analyzed_patterns[:]

        #
        # Control flow graph extraction
        #
        print "[I] Creation of the Control Flow Graph (can take few seconds)"
        # Get the CFG of the binary
        cfg.extract()

        #
        # Pattern searching
        #
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
                        # Analyzing
                        #
                        print "\t\t\t\t[I] Linking the patterns matches which are in the same area"
                        ana = PatternsAnalysis(patterns, algo)

                        print "\t\t\t\t[I] Filtering those patterns"
                        ana.filter_patterns()

                        # Add the analyzed patterns to the list
                        self._analyzed_patterns.append(ana)

    def get_analyzed_patterns(self):
        """Analyzed patterns getter."""
        return self._analyzed_patterns
