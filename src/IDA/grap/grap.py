#!/usr/bin/env python
"""This file is a part of the IDAgrap project."""

import sys
import threading

from pygrap import graph_free

import idaapi
from idagrap.analysis.Analysis import PatternsAnalysis
from idagrap.graph.Graph import CFG
from idagrap.patterns.Modules import MODULES
from idagrap.ui.helpers import QtShim
from idagrap.ui.IDAgrapForm import IDAgrapForm
try:
    from idc import auto_wait
except:
    from idc import Wait

# Initialization of useful objects for PySide/PyQt
QtGui = QtShim.get_QtGui()
QtCore = QtShim.get_QtCore()
QtWidgets = QtShim.get_QtWidgets()

# Recursion limit
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
        # Wait for the end of autoanalysis
        try:
            auto_wait()
        except:
            Wait()

        # Create form
        form = IDAgrapForm()

        # Show the form
        form.Show()

        return
