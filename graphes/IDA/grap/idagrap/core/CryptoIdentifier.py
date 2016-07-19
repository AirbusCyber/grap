#!/usr/bin/env python

import colorsys
import random
import threading

from idagrap.analysis.Analysis import PatternsAnalysis
from idagrap.graph.Graph import CFG
from idagrap.patterns.Modules import MODULES
from idc import CIC_ITEM, GetColor, SetColor


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


class CryptoColor:
    """CryptoColor class.

    This class handles the colors for the CryptoIdentifierWidget.

    Attributes:
        _patterns_colors (dict): This dictionary links a color
                                                    to an pattern_id.
                                Structure : {
                                              pattern_id : color,
                                              ...,
                                            }
        _matches_colors (dict): This dictionary contains the old and new color
                                for each instructions in the matches.
                                Structure : {
                                                match_id : {
                                                               ea : {
                                                                        "new": color,
                                                                        "old": color
                                                                    },
                                                               ea : {...},
                                                           },
                                                match_id : {...},
                                            }
        _HUE (float): Default hue value.
        _SATURATION (float): Default saturation value.
        _LIGHTNESS (float): Default lightness value.
    """

    def __init__(self):
        """Initialization."""
        self._patterns_colors = {}
        self._matches_colors = {}

        self._HUE = 0
        self._SATURATION = 0.10
        self._LIGHTNESS = 0.50

    def add_pattern(self, patternid):
        """Associate a color to a pattern id.

        Arguments:
            patternid (uuid4): Pattern id to add.
        """
        self._patterns_colors[patternid] = self.gen_color()

    def add_match(self, match):
        """Associate a color to a match id.

        Arguments:
            match (Match): Match to add.
        """
        match_id = match.get_match_id()
        pattern_id = match.get_pattern_id()
        insts = match.get_match()

        for getid, node_list in insts.iteritems():
            if not node_list.empty():

                # Add all match instructions.
                for node in node_list:

                    if match_id not in self._matches_colors:
                        self._matches_colors[match_id] = {}

                    self._matches_colors[match_id][node.info.address] = {
                        "new": self._patterns_colors[pattern_id],
                        "old": GetColor(node.info.address, CIC_ITEM)
                    }

    def xchg_colors(self):
        """Exchange old and new color for each instruction."""
        for insts in self._matches_colors.itervalues():
            for color in insts.itervalues():

                tmp = color['old']
                color['old'] = color['new']
                color['new'] = tmp

    def clear(self):
        """Clear the class."""
        # swap old and new color
        self.xchg_colors()
        self.highlight_matches()

        # Clear dictionary
        self._matches_colors.clear()
        self._patterns_colors.clear()

    def gen_color(self):
        """Generate a color.

        Returns:
            (int): The return value is an rgb color.
        """
        hue = random.random()
        sat = random.random()

        rgb = colorsys.hls_to_rgb(hue, self._LIGHTNESS, sat)

        return self.rgb_to_int(rgb)

    def rgb_to_int(self, rgb):
        """Convert a rgb tuple to an int.

        Arguments:
            rgb (tuple): Rgb color.

        Returns:
            (int): The return value is an rgb color.
        """
        r = int(rgb[0] * 256) << 16
        g = int(rgb[1] * 256) << 8
        b = int(rgb[2] * 256)

        return (r | g | b)

    def get_patterns_colors(self):
        """patterns_colors getter.

        Returns:
            The return value is `_patterns_colors` attribute.
        """
        return self._patterns_colors

    def get_matches_colors(self):
        """matches_colors getter.

        Returns:
            The return value is `_matches_colors` attribute.
        """
        return self._matches_colors

    def highlight_matches(self):
        """Highlight all the matches."""
        for insts in self._matches_colors.itervalues():
            for ea, color in insts.iteritems():
                SetColor(ea, CIC_ITEM, color['new'])
