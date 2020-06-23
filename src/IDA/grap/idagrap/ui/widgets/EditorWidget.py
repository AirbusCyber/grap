#!/usr/bin/env python
# Inspired by IDAscope.


import idagrap.ui.helpers.QtShim as QtShim
import idc
import idaapi
from idagrap.config.General import config
from idagrap.patterns.Modules import MODULES
import idagrap.ui.helpers.QtGrapSyntax as syntax
from PyQt5.QtWidgets import QMessageBox

QMainWindow = QtShim.get_QMainWindow()

class  EditorWidget(QMainWindow):
    def __init__(self, parent, file_path=None):
        """Initialization."""
        # Initialization
        self.file_path = file_path
        self.saved_text = None
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        # print("[|] loading EditorWidget")

        # Enable access to shared IDAscope modules
        self.parent = parent
        self.name = "Pattern Editor"
        #self.icon = self.cc.QIcon(config['icons_path'] + "icons8-align-text-left-50.png")
        self.icon = self.cc.QIcon(config['icons_path'] + "icons8-edit-property-52.png")
        self.color = False

        # This widget relies on the crypto identifier
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()

        self.textPath.setText(self.file_path)
        self.load_file()
        
    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """

        # Toolbar
        self._createToolbar()

        # Text pattern
        self._createTextWidget()

        # Layout and fill the widget
        generation_layout = self.cc.QVBoxLayout()
        generation_layout.addWidget(self.text_widget)

        self.central_widget.setLayout(generation_layout)

    def _createToolbar(self):
        """
        Creates the toolbar, containing buttons to control the widget.
        """
        self.toolbar = self.addToolBar('Pattern Editor Toolbar')
        self.toolbar.setMovable(False)

        #self._createOpenAction()
        #self.toolbar.addAction(self.openAction)

        self._createSaveAction()
        self.toolbar.addAction(self.saveAction)

        self._createTextPath()
        self.toolbar.addWidget(self.textPath)

        self._createCloseAction()
        self.toolbar.addAction(self.closeAction)

    def _createCloseAction(self):
        """
        Create an action for the close button of the toolbar and connect it.
        """
        # Action
        self.closeAction = self.cc.QAction(
            self.cc.QIcon(config['icons_path'] + "icons8-delete.png"),
            "Quit editor",
            self
        )

        self.closeAction.triggered.connect(self._onCloseClicked)

    def _onCloseClicked(self):
        text = self.text_widget.toPlainText()
        if text != self.saved_text:
            msg_box = QMessageBox(self)
            r = msg_box.question(self, 'Warning', ('The pattern has not been saved to file, close the editor anyway?'), QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel)
            if r != QMessageBox.Yes:
                return

        index = self.parent.tabs.indexOf(self)
        self.parent.tabs.removeTab(index)

    def _createSaveAction(self):
        """
        Create an action for the save button of the toolbar and connect it.
        """
        # Action
        self.saveAction = self.cc.QAction(
            self.cc.QIcon(config['icons_path'] + "icons8-save-as-50.png"),
            "Save file",
            self
        )

        self.saveAction.triggered.connect(self._onSaveClicked)

    def _onSaveClicked(self):
        text = self.text_widget.toPlainText()

        try:
            f = open(self.file_path, "w")
            f.write(text)
            f.close()
            self.saved_text = text
        except Exception as e:
            print("WARNING:", e)

    def _createTextPath(self):
        self.textPath = self.cc.QLineEdit()
        self.textPath.setReadOnly(True)
        self.textPath.setFrame(False)

    def _createTextWidget(self):
        self.text_widget = self.cc.QTextEdit()
        self.text_widget.setReadOnly(False)
        self.text_widget.setFontFamily("Monospace")
        self.highlight = syntax.PythonHighlighter(self.text_widget.document())


    def load_file(self):
        if self.file_path:
            try:
                f = open(self.file_path, "r")
                text = f.read()
                f.close()
                self.text_widget.setText(text)
                self.saved_text = text
            except Exception as e:
                print("WARNING:", e)

