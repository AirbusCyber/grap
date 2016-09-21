#!/usr/bin/env python

from uuid import uuid4

from pygrap import freeMapGotten, getGraphFromFile, graph_free, parcoursLargeur

from idagrap.config.General import MAX_THRESHOLD


class Match:
    """Match class.

    This class is a representation of a match.

    Attributes:
        _links (Match dict): dictionary of Match in the same function ares.
                            Structure {"pattern_id": {
                                                        "match_id": Match,
                                                     },
                                      }.
        _match (std::map< std::string,std::list< node_t * > * > * list): List of match instructions.
        _pattern_id (UUID): Id of the match Pattern.
        _match_id (UUID): Id of this Match.

    Arguments:
        match (std::map< std::string,std::list< node_t * > * > * list): List of matched instructions.
        pattern_id (UUID): Id of the match Pattern.
    """

    def __init__(self, match, pattern_id):
        """Initialization of the class."""
        self._links = {}
        self._match = match
        self._pattern_id = pattern_id
        self._match_id = uuid4()

    def get_match(self):
        """Match getter.

        Returns:
            The return value is the `_match` attribute.
        """
        return self._match

    def get_links(self):
        """Links getter.

        Returns:
            The return value is the `_links` attribute.
        """
        return self._links

    def add_link(self, match):
        """Add links between two `Match`.

        Add the `match` argument to the `_links` attribute.

        Arguments:
            match (Match): Match to add.
        """
        pattern_id = match.get_pattern_id()
        match_id = match.get_match_id()

        if pattern_id in self._links:
            if match_id not in self._links[pattern_id]:
                self._links[pattern_id][match_id] = match
        else:
            self._links[pattern_id] = {match_id: match}

    def get_match_id(self):
        """Match ID getter.

        Returns:
            The return value is the `_match_id` attribute.
        """
        return self._match_id

    def get_pattern_id(self):
        """Pattern ID getter.

        Returns:
            The return value is the `_pattern_id` attribute.
        """
        return self._pattern_id

    def print_parcours(self):
        """Print the "parcours"."""
        for getid, node_list in self._match.iteritems():
            if not node_list.empty():
                for n_index, node in enumerate(node_list):

                    print "%s" % getid,

                    if node_list.size() > 1:
                        print "%d" % n_index,

                    print ": ",

                    if node.info.has_address:
                        print "0x%X, " % node.info.address,

                    print "%s" % node.info.inst_str

    def get_start_address(self):
        """Get the start address of this Match.

        Returns:
            (ea_t): The return value is the start address of this Match.
        """
        node = self._match.values()[0][0]

        return node.info.address

    def get_num_insts(self):
        """Get the number of instructions of this Match.

        Returns:
            (int): The return value is the number of instructions in the Match.
        """
        size = 0
        for node_list in self._match.values():
            size += len(node_list)

        return size

    def get_rate(self, patterns):
        """Calculate the rate.

        Arguments:
            patterns (Patterns): Patterns of the matches.
        """
        return (len(self._links) / patterns.get_size())


class Pattern:
    r"""Pattern class.

    This class is a representation of a pattern.

    Attributes:
        _file (str): File path (eg. "C:\test.dot").
        _name (str): Name of the pattern (eg. "First loop")
        _description (str): Description of the Pattern (eg.
                            "First Initialization loop of RC4 set_key.").
        _matches (Match list): Matches of the pattern in a graph.
        _id (UUID): Pattern id.
        _min_pattern (int): Minimum of patterns authorized in the same area.
        _max_pattern (int): Maximum of patterns authorized in the same area.
    Args:
        f (str): File path (default value: "").
        name (str): Name of the pattern (default value: "")
        description (str): Description of the Pattern (default value: "").
        _min_pattern (int): Minimum of patterns authorized in the same area.
                            (default value: 1)
        _max_pattern (int): Maximum of patterns authorized in the same area.
                            (default value: 1)

    """

    _file = ""
    _name = ""

    def __init__(self, f="", name="", description="",
                 min_pattern=1, max_pattern=1):
        """Initialization of the class."""
        self._file = f
        self._name = name
        self._description = description
        self._matches = []
        self._id = uuid4()
        self._min_pattern = min_pattern
        self._max_pattern = max_pattern

    def __str__(self):
        """String representation of the class."""
        res = "(\n"
        res += "Name: " + self._name + "\n"
        res += "Description: " + self._description + "\n"
        res += "File: " + self._file + "\n"
        res += "Min pattern per area : " + self._min_pattern.__str__() + "\n"
        res += "Max pattern per area : " + self._max_pattern.__str__() + "\n"
        res += ")\n"
        return res

    def __del__(self):
        """Exit function."""
        # free matches
        for found_nodes in self._matches:
            if found_nodes:
                freeMapGotten(found_nodes)

    def get_file(self):
        """File getter.

        Returns:
            The return value is the `_file` attribute.
        """
        return self._file

    def get_name(self):
        """Name getter.

        Returns:
            The return value is the `_name` attribute.
        """
        return self._name

    def get_description(self):
        """Description getter.

        Returns:
            The return value is the `_description` attribute.
        """
        return self._description

    def get_id(self):
        """Id getter.

        Returns:
            The return value is the `_id` attribute.
        """
        return self._id

    def get_matches(self):
        """Matches getter.

        Returns:
            The return value is the `_matches` attribute.
        """
        return self._matches

    def get_min_pattern(self):
        """Min Pattern getter.

        Returns:
            The return value is the `_min_pattern` attribute.
        """
        return self._min_pattern

    def get_max_pattern(self):
        """Max Pattern getter.

        Returns:
            The return value is the `_max_pattern` attribute.
        """
        return self._max_pattern

    def parcourir(self, graph, checklabels=True, countallmatches=True, getid=True, printallmatches=False):
        """Search a pattern.

        This method allows the search of an pattern in a graph.

        Arguments:
            graph (graph_t*): Graph in which we will look for the pattern.
            checklabels (bool): Check or not the labels of the pattern
                                                (default value: True).
            countallmatches (bool): Count or not all the matches
                                                (default value: True).
            getid (bool): Get or not the ID (default value: True).
        """
        pattern_graph = getGraphFromFile(self._file)
        pattern_size = pattern_graph.nodes.size

        parcours = parcoursLargeur(pattern_graph,
                                   pattern_graph.root.list_id,
                                   pattern_size)

        rt = parcours.parcourir(graph, pattern_size,
                                checklabels, countallmatches, getid, printallmatches)

        set_gotten = rt.second

        # Check if the list is empty
        if len(self._matches) != 0:
            del self._matches[:]

        # Fill the matches list
        if not set_gotten.empty():
            for found_nodes in set_gotten:
                self._matches.append(Match(found_nodes, self.get_id()))

        # Free object
        parcours.freeParcours(True)
        graph_free(pattern_graph, True)

    def print_parcours(self):
        """Print the matches."""
        if self._matches:
            count = len(self._matches)

            print "%d traversal(s) possible." % (count)
            print "Pattern graph (%s)" % (self._name)

            if count > 0:
                print("\nExtracted nodes:")

                for f_index, found_nodes in enumerate(self._matches, start=1):
                    print("Match %d, UUID : %s\n" %
                          (f_index, found_nodes.get_match_id()))

                    found_nodes.print_parcours()

                    print ""
        else:
            print "[E] Matches haven't been initialized"


class Patterns():
    """Patterns class.

    This class is a representation of multiple patterns.

    Attributes:
        _patterns (Pattern list): List of patterns.
        _threshold (float): Threshold of the module. Its value can vary between
                            0 and 1 (see MIN_THRESHOLD and MAX_THRESHOLD).
                            The threshold value is compared to the
                            number_of_function_patterns divided by the
                            number_of_detected_function_patterns 
                            (default value: MAX_THRESHOLD).
        _size (int): Size of `_patterns`.
        _name (str): Name of the Patterns (eg. "RC4 Set_Key")
        _description (str): Description of the Patterns (eg.
                            "Initialization function of the RC4 algorithm.")

    Args:
        patterns (Pattern list): List of patterns (default value: None).
        threshold (float): Threshold of the module (default value: 1.0).
        name (str): Name of the Patterns (default value: "")
        description (str): Description of the Patterns (default value: "").
    """

    _patterns = []
    _threshold = MAX_THRESHOLD
    _size = 0
    _name = ""
    _description = ""

    def __init__(self, patterns=None, threshold=MAX_THRESHOLD, name="", description=""):
        """Initialization of the class."""
        if not patterns:
            patterns = []

        self._patterns = patterns
        self._threshold = threshold
        self._size = len(patterns)
        self._name = name
        self._description = description

    def __str__(self):
        """String representation of the class."""
        res = "[\n"
        res += "Name: " + self._name + "\n"
        res += "Description: " + self._description + "\n"

        for pattern in self._patterns:
            res += pattern.__str__()

        res += "Threshold: " + self._threshold.__str__() + "\n"
        res += "Size: " + self._size.__str__() + "\n"
        res += "]\n"

        return res

    def get_patterns(self):
        """Patterns getter.

        Returns:
            The return value is the `_pattern` attribute.
        """
        return self._patterns

    def get_threshold(self):
        """Threshold getter.

        Returns:
            The return value is the `_threshold` attribute.
        """
        return self._threshold

    def get_size(self):
        """Size getter.

        Returns:
            The return value is the `_size` attribute.
        """
        return self._size

    def get_name(self):
        """Name getter.

        Returns:
            The return value is the `_name` attribute.
        """
        return self._name

    def get_pattern_name(self, pattern_id):
        """Get the pattern name linked to the id.

        Arguments:
            pattern_id (UUID): Pattern id to search.

        Returns:
            (str): The return value is the name of the pattern.
                     If it fails, the return value will be "None"
        """
        for pattern in self._patterns:
            if pattern_id == pattern.get_id():
                return pattern.get_name()
        return "None"

    def get_pattern(self, pattern_id):
        """Get the pattern linked to the id.

        Arguments:
            pattern_id (UUID): Pattern id to search.

        Returns:
            (Pattern): The return value is the pattern.
                     If it fails, the return value will be NoneType.
        """
        for pattern in self._patterns:
            if pattern_id == pattern.get_id():
                return pattern
        return None
    def get_description(self):
        """Description getter.

        Returns:
            The return value is the `_description` attribute.
        """
        return self._description

    def sup_threshold(self, value):
        """Check if the value is superior at the threshold.

        Arguments:
            value (float): Value to be checked.

        Returns:
            (bool): True if the value is superior at the threshold,
                     otherwise False.
        """
        if value >= self._threshold:
            return True
        return False
