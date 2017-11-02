#/usr/bin/env python

from pygrap import (graph_alloc, graph_free, graph_t, node_alloc,
                    node_copy, node_link, node_list_add, node_list_find,
                    update_children_fathers_number)

from idaapi import get_root_filename, is_noret, get_inf_structure
try:
    from idaapi import get_entry_ordinal, get_entry
except:
    from idc import BeginEA

from idagrap.config.Instruction import *
from idagrap.error.Exceptions import CodeException
from idagrap.graph.Node import *
from idautils import DecodeInstruction, Functions
import capstone

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
        self.info = None
        self.capstone = None

    def extract(self):
        """Extract the control flow graph from the binary."""
        # Initialize binary info
        self.info = get_inf_structure()
        
        # Initialize Capstone
        if self.info.is_64bit():
            mode = capstone.CS_MODE_64
        else:
            mode = capstone.CS_MODE_32
        self.capstone = capstone.Cs(capstone.CS_ARCH_X86, mode)
        
        # Get the Entry Point
        entry = None
        try:
            start_ea = self.info.start_ea
            if start_ea != 0xffffffff:
                entry = start_ea
        except:
            try:
                entry = BeginEA()
            except:
                pass
                
        if entry is None:
            print "WARNING: Could not determine entrypoint"
        else:
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

    def dis(self, ea, is_child1 = False, ifrom=None):
        """Disassemble the current address and fill the nodes list.

        Args:
            ea (ea_t): Effective address.
            ifrom (node_t*): Predecessor node.
            is_child1 (bool)
        """

        node_list = self.graph.nodes
        args_queue = []
        args_queue.append((ea, is_child1, ifrom))

        while args_queue != []:
            ea, is_child1, ifrom = args_queue.pop(0)
            
            try:
                n = Node(ea, self.info, self.capstone)
            except CodeException as e:
                continue
            except Exception as e:
                print "WARNING:", e
                continue

            # If the node exists
            if node_list_find(node_list, n.getid()):
                if ifrom and is_child1 is not None:
                    # Link the father and the child
                    node_link(node_list_find(node_list, ifrom.getid()),
                              node_list_find(node_list, n.getid()), False,
                              is_child1)
                continue

            # Get the instruction
            try:
                inst = DecodeInstruction(ea)
            except Exception as e:
                print "WARNING:", e
                continue

            if not inst:
                continue

            # Add the node
            node_list_add(node_list, node_copy(node_alloc(), n))

            if ifrom and is_child1 is not None:
                node_link(node_list_find(node_list, ifrom.getid()),
                          node_list_find(node_list, n.getid()), False,
                          is_child1)

            # No child
            if inst.itype in RETS:
                pass

            # 1 remote child
            elif inst.itype in JMPS:
                try:
                    op = inst.ops[0]
                except:
                    op = inst.Operands[0]
            
                try:
                    args_queue.insert(0, (op.addr, False, n))
                except Exception as e:
                    print "WARNING:", e
                    pass

            # 2 children (next, then remote) - except call
            elif inst.itype in CJMPS:
                try:
                    op = inst.ops[0]
                except:
                    op = inst.Operands[0]
                
                # Next
                args_queue.insert(0, (inst.ea + inst.size, True, n))

                # Remote
                args_queue.insert(0, (op.addr, False, n))

            # 2 children (next, then remote) - call
            elif inst.itype in CALLS:
                try:        
                    op = inst.ops[0]
                except:
                    op = inst.Operands[0]
                
                # Next
                # Catch the end of a noret function
                if not is_noret(inst.ea):
                    args_queue.insert(0, (inst.ea + inst.size, True, n))

                # Remote
                if op.type in OP_MEM:
                    args_queue.insert(0, (op.addr, False, n))

            # 1 child (next) - basic instruction
            else:
                args_queue.insert(0, (inst.ea + inst.size, True, n))

        return
