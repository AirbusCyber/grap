#!/usr/bin/env python
# Inspired by IDAscope.


import idagrap.ui.helpers.QtShim as QtShim
import idc
import idaapi
from idagrap.config.General import config
from idagrap.patterns.Modules import MODULES

QMainWindow = QtShim.get_QMainWindow()


class  AboutWidget(QMainWindow):
    def __init__(self, parent):
        """Initialization."""
        # Initialization
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        #print "[|] loading AboutWidget"

        # Enable access to shared IDAscope modules
        self.parent = parent
        self.name = "About"
        self.icon = self.cc.QIcon(config['icons_path'] + "icons8-info.png")
        self.color = False

        # This widget relies on the crypto identifier
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()


    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """

        # Text pattern
        self._createTextWidget()

        # Layout and fill the widget
        generation_layout = self.cc.QVBoxLayout()
        generation_layout.addWidget(self.text_widget)

        self.central_widget.setLayout(generation_layout)

    def _createTextWidget(self):
        self.text_widget = self.cc.QTextEdit()
        self.text_widget.setReadOnly(True)
        self.text_widget.setFontFamily("Monospace")
        
        
        html_text = open(config['about_path'], "r").read()
        if html_text is not None:
            self.text_widget.setHtml(html_text.replace("TODO_GRAPVERSION", config["version"]))
        else:
            self.text_widget.setText("Error: about.html not found")
