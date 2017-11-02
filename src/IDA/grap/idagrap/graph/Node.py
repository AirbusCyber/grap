#!/usr/bin/env python

from pygrap import NodeInfo, node_t

try:
    from idaapi import is_code, get_flags, print_insn_mnem, generate_disasm_line, create_insn
    from idc import print_operand, get_bytes
except:
    from idaapi import isCode
    from idc import GetDisasm, GetFlags, GetMnem, GetOpnd, GetManyBytes, MakeCode
from idagrap.error.Exceptions import CodeException
import capstone


class Node(node_t):
    """Representation of a pygrap node, with useful methods.

    Args:
        ea (ea_t): Effective Address of the node.

    Attributs:
        node (node_t): Pygrap structure for a node.

    Raises:
        CodeException: If the ``ea`` is not a code instruction.
    """

    def __init__(self, ea, info, cs):
        """Initialization function."""
        # Init the node structure
        node_t.__init__(self)

        # Check if it's a code instruction
        try:
            is_c = is_code(get_flags(ea))
        except:
            is_c = isCode(GetFlags(ea))
        if not is_c:
            raise CodeException

        #
        # fill node_t struct
        #

        # NodeInfo
        self.info = NodeInfo()
        inst_elements = []
        
        try:
            size = create_insn(ea)
            bytes = get_bytes(ea, size)
        except:
            size = MakeCode(ea)
            bytes = GetManyBytes(ea, size)
        
        

        #s = hex(ea) + "\n"
        #f = open("E:\\hex.txt", "a")
        #f.write(s)
        #f.close()


        (address, size, mnemonic, op_str) = cs.disasm_lite(bytes, ea, count=1).next()
        self.info.opcode = mnemonic.encode("ascii", "ignore")

        op_str_ascci = op_str.encode("ascii", "ignore")
        splitted = op_str_ascci.split(", ")
        if len(splitted) >= 1:
            self.info.arg1 = splitted[0]
            if len(splitted) >= 2:
                self.info.arg2 = splitted[1]
                if len(splitted) >= 3:
                    self.info.arg3 = splitted[2]
        
        # No node will be root but this is acceptable for CFGs
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
