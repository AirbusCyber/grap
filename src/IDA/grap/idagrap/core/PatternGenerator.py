#!/usr/bin/env python

import colorsys
import random
import threading
from collections import deque, OrderedDict
from ColorCore import ColorCore

from idagrap.analysis.Analysis import PatternsAnalysis
from idagrap.graph.Graph import CFG
from idagrap.patterns.Modules import MODULES
from idagrap.modules.Pattern import Pattern, Patterns, Match
try:
    from idc import CIC_ITEM, set_color, DEFCOLOR
except:
    from idc import CIC_ITEM, GetColor, SetColor, DEFCOLOR
from pygrap import (NodeInfo, node_t, node_list_find)
from idagrap.patterns.test.misc.ModulesTestMisc import get_test_misc


class PatternGenerator:
    """Cryptographic identifier.

    This class aims to organize the identification of cryptography.

    graph (CFG): Control flow graph.
    _analyzed_patterns: (PatternsAnalysis list): Hold the analyzed patterns.
    """

    def __init__(self):
        """Initialization"""

        self.graph = CFG()
        self.rootNode = None
        self.targetNodes = []

        self.coloredNodes = set()
        self.defaultColor = DEFCOLOR
        self.rootColor = 0xcc2efa
        self.targetColor = 0x31b404
        self.nodeColor = 0xffcc99

        self.generic_arguments_option = False
        self.lighten_memory_ops_option = False
        self.std_jmp_option = False
        self.factorize_option = False

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

        #
        # Control flow graph extraction
        #
        print "[I] Creation of the Control Flow Graph (can take few seconds)"
        # Get the CFG of the binary
        cfg.extract()

    def resetPattern(self):
        self.rootNode = None
        self.targetNodes = []

        self.resetColored()

    def colorNode(self, node, color):
        try:
            set_color(node, CIC_ITEM, ColorCore.rgb_to_bgr(color))
        except:
            SetColor(node, CIC_ITEM, ColorCore.rgb_to_bgr(color)) 

    def resetColored(self):
        if self.coloredNodes:
            for node in self.coloredNodes:
                self.colorNode(node, self.defaultColor)

            self.coloredNodes = set()

        # Color target nodes again
        for targetNode in self.targetNodes:
            self.coloredNodes.add(targetNode.node_id)
            self.colorNode(targetNode.node_id, self.targetColor)

        # Color root node again
        if self.rootNode:
            self.coloredNodes.add(self.rootNode.node_id)
            self.colorNode(self.rootNode.node_id, self.rootColor)

    def setRootNode(self, rootNodeAddress):
        rootNode = node_list_find(self.graph.graph.nodes, rootNodeAddress)
        if not rootNode:
            raise Exception("Invalid root node")

        if rootNode in self.targetNodes:
            raise Exception("Node already used")

        self.rootNode = rootNode
        self.resetColored()

        print "Set root node to {}".format(hex(rootNode.node_id))

    def addTargetNode(self, targetNodeAddress):
        targetNode = node_list_find(self.graph.graph.nodes, targetNodeAddress)
        if not targetNode:
            raise Exception("Invalid target node")

        if targetNode in self.targetNodes:
            raise Exception("Node already used")

        self.targetNodes.append(targetNode)
        self.coloredNodes.add(targetNodeAddress)
        self.colorNode(targetNodeAddress, self.targetColor)

        print "Add target node {}".format(hex(targetNode.node_id))

    def removeTargetNode(self, targetNodeAddress):
        self.targetNodes = [node for node in self.targetNodes if node.node_id != targetNodeAddress]

        self.resetColored()

    def generate(self):
        if self.rootNode is None:
            raise Exception("Impossible to generate pattern without a root node")

        if len(self.targetNodes) == 0:
            raise Exception("Impossible to generate pattern without some target nodes")

        queue = deque()
        targetNodes = set([i.node_id for i in self.targetNodes])
        foundNodes = []
        coloring = set()
        previous = {}

        queue.append(self.rootNode)
        coloring.add(self.rootNode.node_id)

        while queue and (len(foundNodes) != len(targetNodes)):
            node = queue.pop()

            for child in self._getChildren(node):
                if child.node_id not in coloring:
                    if child.node_id in targetNodes:
                        foundNodes.append(child.node_id)

                    coloring.add(child.node_id)
                    queue.appendleft(child)
                    previous[child.node_id] = node.node_id

        if len(foundNodes) != len(targetNodes):
            raise Exception("Can not reach all target nodes from the root.")

        # Generate the nodes and edges of the pattern
        patternNodes = OrderedDict()
        patternEdges = []

        for finalNode in reversed(self.targetNodes):
            node_id = finalNode.node_id

            while node_id != self.rootNode.node_id:
                if node_id not in patternNodes:
                    self.coloredNodes.add(node_id)
                    if node_id != self.rootNode.node_id and node_id not in targetNodes:
                        self.colorNode(node_id, self.nodeColor)

                    patternNodes[node_id] = PatternGeneratorNode.fromNodeId(self.graph.graph.nodes, node_id)
                    previous_id = previous[node_id]
                    patternEdges.append((previous_id, node_id))
                    node_id = previous_id
                else:
                    break

        patternNodes[self.rootNode.node_id] = PatternGeneratorNode.fromNodeId(self.graph.graph.nodes,
                                                                              self.rootNode.node_id)

        for patternEdge in patternEdges:
            childNumber = self._getChildNumber(patternEdge[0], patternEdge[1])
            if childNumber == 1:
                patternNodes[patternEdge[0]].child1 = patternEdge[1]
            elif childNumber == 2:
                patternNodes[patternEdge[0]].child2 = patternEdge[1]

        # Transformations

        for _, patternNode in patternNodes.items():
            if self.generic_arguments_option:
                patternNode.arg1 = None
                patternNode.arg2 = None
                patternNode.arg3 = None

            if self.lighten_memory_ops_option:
                if patternNode.opcode in ["lea", "push", "pop"] or patternNode.opcode.startswith("mov"):
                    patternNode.opcode = None

        if self.factorize_option:
            for patternNodeId, patternNode in reversed(patternNodes.items()):
                if patternNodeId not in patternNodes:
                    continue

                while True:
                    if patternNode.child2 is not None or patternNode.child1 is None:
                        break

                    child = patternNodes[patternNode.child1]
                    if (patternNode.opcode is not None or child.opcode is not None) and (patternNode.opcode != child.opcode or patternNode.arg1 != child.arg1 or patternNode.arg2 != child.arg2 or patternNode.arg3 != child.arg3):
                        break

                    del patternNodes[patternNode.child1]

                    if child.child1 is not None:
                        patternNode.child1 = patternNodes[child.child1].node_id
                    else:
                        patternNode.child1 = None

                    patternNode.repeat = '*'

        # End of transformations

        patternStr = "digraph G {\n"

        for patternNodeId, patternNode in reversed(patternNodes.items()):
            patternStr += "    {} [cond={}".format(patternNodeId, self._getConditionString(patternNode))
            if patternNode.repeat is not None:
                patternStr += ', repeat=' + str(patternNode.repeat) + ', lazyrepeat=true'
            patternStr += "]\n"

        patternStr += "\n"

        for patternNodeId, patternNode in reversed(patternNodes.items()):
            if patternNode.child1 is not None:
                patternStr += "    {} -> {} [childnumber={}]\n".format(patternNode.node_id,
                                                                       patternNode.child1, 1)
            if patternNode.child2 is not None:
                patternStr += "    {} -> {} [childnumber={}]\n".format(patternNode.node_id,
                                                                       patternNode.child2, 2)

        patternStr += "}\n"

        return patternStr

    def _getConditionString(self, node):
        if self.std_jmp_option:
            if node.children_nb > 1:
                return "\"nchildren == " + str(node.children_nb) + "\""

        if node.opcode is None:
            return "true"

        s = "opcode is '"
        s += node.opcode
        s += "'"

        for argNb in range(1, 4):
            arg = None

            if argNb == 1:
                arg = node.arg1
            elif argNb == 2:
                arg = node.arg2
            elif argNb == 3:
                arg = node.arg3

            if arg is not None:
                s += " and arg" + str(argNb) + " is '" + str(arg) + "'"

        return "\"" + s + "\""

    def _getChildren(self, node):
        children = []

        if node.has_child1:
            children.append(node.child1)

        if node.has_child2:
            children.append(node.child2)

        return children

    def _getChildNumber(self, parentId, childId):
        parentNode = node_list_find(self.graph.graph.nodes, parentId)

        if parentNode.has_child1 and parentNode.child1.node_id == childId:
            return 1
        elif parentNode.has_child2 and parentNode.child2.node_id == childId:
            return 2
        else:
            return None


class PatternGeneratorNode:
    def __init__(self, node_id, opcode, arg1, arg2, arg3, child1, child2, children_nb, repeat=None):
        self.node_id = node_id

        self.opcode = opcode
        self.arg1 = arg1 if arg1 != '' else None
        self.arg2 = arg2 if arg2 != '' else None
        self.arg3 = arg3 if arg3 != '' else None

        self.child1 = child1
        self.child2 = child2
        self.children_nb = children_nb

        self.repeat = repeat

    @staticmethod
    def fromNodeId(graph, nodeId):
        node = node_list_find(graph, nodeId)

        return PatternGeneratorNode(nodeId, node.info.opcode, node.info.arg1, node.info.arg2, node.info.arg3,
                                    None, None, node.children_nb)
