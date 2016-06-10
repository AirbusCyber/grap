#!/usr/bin/env python
"""This file is a part of the IDAgrap project."""

import idaapi
import threading


def PLUGIN_ENTRY():
    """ Plugin entry point."""
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
        thread = threading.Thread(target=self.main, args=(arg,))
        # Fixed the stack size to 10M
        threading.stack_size(0x100000*10)
        thread.start()

    def main(self, arg):
        """Main of the IDAgrap plugin.

        Args:
            arg: Plugin argument.
        """
        pass
