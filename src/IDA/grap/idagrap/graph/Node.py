#!/usr/bin/env python

from pygrap import NodeInfo, node_t

from idaapi import isCode
from idagrap.error.Exceptions import CodeException
from idc import BeginEA, GetDisasm, GetFlags


class Node(node_t):
    """Representation of a pygrap node, with useful methods.

    Args:
        ea (ea_t): Effective Address of the node.

    Attributs:
        node (node_t): Pygrap structure for a node.

    Raises:
        CodeException: If the ``ea`` is not a code instruction.
    """

    def __init__(self, ea):
        """Initialization function."""
        # Init the node structure
        node_t.__init__(self)

        # Check if it's a code instruction
        if not isCode(GetFlags(ea)):
            raise CodeException

        #
        # fill node_t struct
        #

        # NodeInfo
        self.info = NodeInfo()
        self.info.inst_str = GetDisasm(ea)

        # Parse opcode and arguments
        split_space = self.info.inst_str.split(" ")
        if len(split_space) >= 1:
            self.info.opcode = split_space[0]
            
        if len(split_space) >= 2:
            rest = " ".join([s for s in split_space[1:]])
            split_comma = rest.split(",")
            
            self.info.nargs = min(len(split_comma), 3)
            
            if len(split_comma) >= 1:
                self.info.arg1 = split_comma[0].strip()
            if len(split_comma) >= 2:
                self.info.arg2 = split_comma[1].strip()
            if len(split_comma) >= 3:
                self.info.arg3 = split_comma[2].strip()

        if ea == BeginEA():
            self.info.is_root = True
        else:
            self.info.is_root = False

        self.info.address = ea
        self.info.has_address = True

        # node_t
        self.node_id = self._genid()

    def getid(self):
        """Get the node id.

        Returns:
            vsize_t: The id of the node.
        """
        return self.node_id

    def _genid(self):
        """Generate a unique ID for the node.

        Returns:
            vsize_t: The id for the node
        """
        return self.info.address
