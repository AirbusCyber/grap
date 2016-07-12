#!/usr/bin/env python

from idc import GetFunctionName


class PatternsAnalysis:
    """PatternsAnalysis class.

    This Allows the analysis of patterns. The different analyses are:
        - Searching of different patterns in the same area.
        - Exporting the matches that respect our rules.

    Attributes:
        _patterns (Patterns): Patterns to analyze.
        _found_patterns (Match list): List of found patterns that respect our
                                      rules.
                                     Structure : [
                                                     [
                                                         "pattern_id": {
                                                             "match_id": Match,
                                                         },
                                                         "...": {...}
                                                     ],
                                                     [...]
                                     ]
    Arguments:
        patterns (Patterns): Patterns to analyze.
    """

    def __init__(self, patterns):
        """Initialization of the class."""
        # Init
        self._patterns = patterns
        self._found_patterns = []

        self.search_relationships()

    def search_relationships(self):
        """Searching relationships between patterns.

        The goal of the method is to link pattern matches that are in the same
        area (function). It fills the `_links` attribute of each `Match`.
        """
        patterns = self._patterns.get_patterns()

        # For all patterns
        for p1 in patterns:
            for p2 in patterns:
                # For all matches
                for m1 in p1.get_matches():

                    # Get the first node_t
                    n1 = m1.get_match().values()[0][0]

                    for m2 in p2.get_matches():
                        # Get the first node_t
                        n2 = m2.get_match().values()[0][0]

                        # If they are in the same area (function)
                        if GetFunctionName(n1.info.address) == GetFunctionName(n2.info.address):
                            m1.add_link(m2)

    def filter_patterns(self):
        """Search good patterns.

        This method filter patterns matches that respect our rules. It fills
        the `_found_patterns` attributes of this class.
        """
        patterns = self._patterns
        pattern_list = self._patterns.get_patterns()

        for pattern in pattern_list:

            for match in pattern.get_matches():

                # If the rate of the match is superior at the patterns
                # threshold.
                if patterns.sup_threshold(match.get_rate(patterns)):

                    if match.get_links() not in self._found_patterns:
                        links = match.get_links()

                        ok = True

                        # Check the Min and Max rules.
                        for pattern_id, match_dict in links.iteritems():
                            p = patterns.get_pattern(pattern_id)

                            if len(match_dict) < p.get_min_pattern():
                                ok = False
                                break

                            if len(match_dict) > p.get_max_pattern():
                                ok = False
                                break
                        if ok:
                            self._found_patterns.append(links)

    def print_patterns(self):
        """Print the patterns.

        Print the matches in the `_found_patterns` attribute.
        """
        patterns = self._patterns
        found_patterns = self._found_patterns

        print "%d %s PATTERN FOUND:" % (len(found_patterns),
                                        patterns.get_name())

        for index, match_dict_list in enumerate(found_patterns):
            print "\n~~ Match %d ~~" % index

            for pattern_id, match_dicts in match_dict_list.iteritems():

                print "\nPattern : %s" % patterns.get_pattern_name(pattern_id)

                # Print Pattern matches
                for match in match_dicts.itervalues():
                    print "------------------------"
                    match.print_parcours()
