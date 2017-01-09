#/usr/bin/env python

from pygrap import (graph_alloc, graph_free, graph_t, node_alloc,
                    node_copy, node_link, node_list_add, node_list_find,
                    update_children_fathers_number)

from idaapi import get_root_filename, is_noret
from idagrap.config.Instruction import *
from idagrap.error.Exceptions import CodeException
from idagrap.graph.Node import *
from idautils import DecodeInstruction, Functions
from idc import BeginEA


class CFG:
    """Control Flow Graph Class.

    This class allows the conversion between the binary file and the pygrap
     graph.

    Attributes:
        graph (graph_t): The control flow graph of the binary
    """

    def __init__(self, graph=None):
        """Initialization of CFG.

        Args:
            graph (graph_t) = The graph graph.
        """
        # Set attributes
        if not graph:
            graph = graph_alloc(0)

        self.graph = graph

    def extract(self):
        """Extract the control flow graph from the binary."""
        # Get the Entry Point
        entry = BeginEA()

        self.dis(ea=entry, is_child1=None, ifrom=None)

        # Scan all the functions
        for ea in Functions():
            self.dis(ea=ea, is_child1=None, ifrom=None)

        update_children_fathers_number(self.graph)

        # Information
        print "%s graph has %d nodes" % (get_root_filename(),
                                         self.graph.nodes.size)

    def clear_graph(self):
        """Clear the graph."""
        # Remove the old graph.
        if self.graph:
            graph_free(self.graph, True)

        # Allocate a new graph
        self.graph = graph_alloc(0)

    def dis(self, ea, is_child1, ifrom=None):
        """Disassemble the current address and fill the nodes list.

        Args:
            ea (ea_t): Effective address.
            ifrom (node_t*): Predecessor node.
            is_child1 (bool)
        """

        node_list = self.graph.nodes

        try:
            n = Node(ea)
        except CodeException:
            return
        except:
            return

        # If the node exists
        if node_list_find(node_list, n.getid()):
            if ifrom and is_child1 is not None:
                # Link the father and the child
                node_link(node_list_find(node_list, ifrom.getid()),
                          node_list_find(node_list, n.getid()),
                          is_child1)
            return

        # Get the instruction
        try:
            inst = DecodeInstruction(ea)
        except:
            return

        if not inst:
            return

        # Add the node
        node_list_add(node_list, node_copy(node_alloc(), n))

        if ifrom and is_child1 is not None:
            node_link(node_list_find(node_list, ifrom.getid()),
                      node_list_find(node_list, n.getid()),
                      is_child1)

        # No child
        if inst.itype in RETS:
            pass

        # 1 remote child
        elif inst.itype in JMPS:
            try:
                self.dis(inst.Operands[0].addr, True, n)
            except:
                pass

        # 2 children (next, then remote) - except call
        elif inst.itype in CJMPS:

            # Next
            self.dis(inst.ea + inst.size, True, n)

            # Remote
            self.dis(inst.Operands[0].addr, False, n)

        # 2 children (next, then remote) - call
        elif inst.itype in CALLS:

            # Next
            # Catch the end of a noret function
            if not is_noret(inst.ea):
                self.dis(inst.ea + inst.size, True, n)

            # Remote
            if inst.Operands[0].type in OP_MEM:
                self.dis(inst.Operands[0].addr, False, n)

        # 1 child (next) - basic instruction
        else:
            self.dis(inst.ea + inst.size, True, n)

        return
