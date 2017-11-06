#!/usr/bin/env python
# Inspired by IDAscope.


from pygrap import graph_free

import idagrap.ui.helpers.QtShim as QtShim
import idc
import idaapi
from idagrap.config.General import config
from idagrap.patterns.Modules import MODULES

QMainWindow = QtShim.get_QMainWindow()


class PatternGenerationWidget(QMainWindow):
    def __init__(self, parent):
        """Initialization."""
        # Initialization
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print "[|] loading PatternGenerationWidget"

        # Enable access to shared IDAscope modules
        self.parent = parent
        self.name = "Pattern Generation"
        self.icon = self.cc.QIcon(config['icons_path'] + "icons8-plus.png")
        self.color = False

        # This widget relies on the crypto identifier
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()

        self.actionsDefined = False

        self.real_time_option = False

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # Toolbar
        self._createToolbar()

        # Text pattern
        self._createTextWidget()

        # Options widgets
        self._createOptionsWidgets()

        # Layout and fill the widget
        generation_layout = self.cc.QVBoxLayout()

        for options_widget in self.options_widgets:
            generation_layout.addWidget(options_widget)

        generation_layout.addWidget(self.text_widget)

        self.central_widget.setLayout(generation_layout)

    def _createToolbar(self):
        """
        Creates the toolbar, containing buttons to control the widget.
        """
        self.toolbar = self.addToolBar('Pattern Generation Toolbar')

        self._createLoadGraphAction()
        self.toolbar.addAction(self.loadGraphAction)

        self._createGenerateAction()
        self.toolbar.addAction(self.generateAction)

        self._createResetAction()
        self.toolbar.addAction(self.resetAction)
        
        self._createSaveAction()
        self.toolbar.addAction(self.saveAction)

    def _createTextWidget(self):
        self.text_widget = self.cc.QTextEdit()
        self.text_widget.setReadOnly(True)
        self.text_widget.setFontFamily("Monospace")

    def _createOptionsWidgets(self):
        self.options_widgets = []

        generic_arguments_check = self.cc.QCheckBox("Generic arguments")
        generic_arguments_check.stateChanged.connect(self._generic_arguments_option_trigger)
        self.options_widgets.append(generic_arguments_check)

        lighten_memory_ops_check = self.cc.QCheckBox("Lighten memory handling operations")
        lighten_memory_ops_check.stateChanged.connect(self._lighten_memory_ops_option_trigger)
        self.options_widgets.append(lighten_memory_ops_check)

        std_jmp_check = self.cc.QCheckBox("Standardize jump operations")
        std_jmp_check.stateChanged.connect(self._std_jmp_check_option_trigger)
        self.options_widgets.append(std_jmp_check)

        factorize_check = self.cc.QCheckBox("Factorize")
        factorize_check.stateChanged.connect(self._factorize_check_option_trigger)
        self.options_widgets.append(factorize_check)

        real_time_check = self.cc.QCheckBox("Real time")
        real_time_check.stateChanged.connect(self._real_time_check_option_trigger)
        self.options_widgets.append(real_time_check)

    def _generic_arguments_option_trigger(self, state):
        self.cc.PatternGenerator.generic_arguments_option = (state == 2)
        self.text_widget.setText(self.cc.PatternGenerator.generate())

    def _lighten_memory_ops_option_trigger(self, state):
        self.cc.PatternGenerator.lighten_memory_ops_option = (state == 2)
        self.text_widget.setText(self.cc.PatternGenerator.generate())

    def _std_jmp_check_option_trigger(self, state):
        self.cc.PatternGenerator.std_jmp_option = (state == 2)
        self.text_widget.setText(self.cc.PatternGenerator.generate())

    def _factorize_check_option_trigger(self, state):
        self.cc.PatternGenerator.factorize_option = (state == 2)
        self.text_widget.setText(self.cc.PatternGenerator.generate())

    def _real_time_check_option_trigger(self, state):
        self.real_time_option = (state == 2)
        self.text_widget.setText(self.cc.PatternGenerator.generate())

    def _createLoadGraphAction(self):
        """
        Create an action for the load graph button of the toolbar and connect it.
        """
        # Action
        self.loadGraphAction = self.cc.QAction(
            self.cc.QIcon(config['icons_path'] + "scan_graph.png"),
            "Load the control flow graph (might take some time)",
            self
        )

        self.loadGraphAction.triggered.connect(self._onLoadGraphButtonClickedThread)

    def _createGenerateAction(self):
        # Action
        self.generateAction = self.cc.QAction(
            self.cc.QIcon(config['icons_path'] + "generate.png"),
            "Generate a pattern",
            self
        )

        self.generateAction.triggered.connect(self._onGenerateButtonClicked)

    def _createResetAction(self):
        # Action
        self.resetAction = self.cc.QAction(
            self.cc.QIcon(config['icons_path'] + "icons8-delete.png"),
            "Reset the pattern",
            self
        )

        self.resetAction.triggered.connect(self._onResetButtonClicked)
        
    def _createSaveAction(self):
        # Action
        self.saveAction = self.cc.QAction(
            self.cc.QIcon(config['icons_path'] + "icons8-add-file.png"),
            "Save the pattern to disk",
            self
        )

        self.saveAction.triggered.connect(self._onSaveButtonClicked)

    def _createContextActions(self):
        actions = [
            ("grap:pg:set_root", self.cc.QIcon(), "[grap] Set root node", self._onSetRootNode),
            ("grap:pg:add_target", self.cc.QIcon(), "[grap] Add target node", self._onAddTargetNode),
            ("grap:pg:remove_target", self.cc.QIcon(), "[grap] Remove target node", self._onRemoveTargetNode)
        ]

        for actionId, icon, text, method in (a for a in actions):
            # Describe the action
            action_desc = idaapi.action_desc_t(
                actionId,  # The action name. This acts like an ID and must be unique
                text,  # The action text.
                PatternGenerationHandler(method))  # The action handler.

            # Register the action
            idaapi.register_action(action_desc)

        self.actionsDefined = True

    def _updateContextMenus(self):
        self.hooks = PatternGenerationHooks(self.cc)
        self.hooks.hook()

    def _onSetRootNode(self):
        #try:
        self.cc.PatternGenerator.setRootNode(idc.get_screen_ea())
        #except:
        #    self.cc.PatternGenerator.setRootNode(idc.ScreenEA())

        if self.real_time_option:
            self.text_widget.setText(self.cc.PatternGenerator.generate())

    def _onAddTargetNode(self):
        try:
            self.cc.PatternGenerator.addTargetNode(idc.get_screen_ea())
        except:
            self.cc.PatternGenerator.addTargetNode(idc.ScreenEA())

        if self.real_time_option:
            self.text_widget.setText(self.cc.PatternGenerator.generate())

    def _onRemoveTargetNode(self):
        try:
            self.cc.PatternGenerator.removeTargetNode(idc.get_screen_ea())
        except:
            self.cc.PatternGenerator.removeTargetNode(idc.ScreenEA())

        if self.real_time_option:
            self.text_widget.setText(self.cc.PatternGenerator.generate())

    def _onLoadGraphButtonClickedThread(self):
        self._onLoadGraphButtonClicked()

    def _onLoadGraphButtonClicked(self):
        # Analyzing
        self.cc.PatternGenerator.analyzing()

        # Update the UI
        if not self.actionsDefined:
            self._createContextActions()
            self._updateContextMenus()

    def _onGenerateButtonClicked(self):
        print "[I] Generation of pattern"
        self.text_widget.setText(self.cc.PatternGenerator.generate())
        print "[I] Generation done"

    def _onResetButtonClicked(self):
        print "[I] Reset pattern"
        self.cc.PatternGenerator.resetPattern()
        self.text_widget.clear()
        
    def _onSaveButtonClicked(self):
        print "[I] Saving pattern"
        options = self.cc.QFileDialog.Options()
        #options |= self.cc.QFileDialog.DontUseNativeDialog
        filename, _ = self.cc.QFileDialog.getSaveFileName(self, "Choose name of save file (.dot and .grapp will be parsed as patterns)", "C:\\Program Files\\IDA 7.0\\plugins\\idagrap\\patterns\\test\\misc\\files\\generated.grapp", "Grap pattern (*.grapp)", options=options)
        #filename = "C:\\Program Files\\IDA 7.0\\plugins\\idagrap\\patterns\\test\\misc\\files\\generated.grapp"
        if filename:            
            #import subprocess            
            #import base64
            #import sys
            
            #print sys.executable
            #save_to_disk = "python C:\\Program Files\\IDA 7.0\\plugins\\idagrap\\utils\\save_to_disk.py"
            #path = base64.b64encode(filename)
            #text = base64.b64encode(self.text_widget.toPlainText())
            #params = base64.encode(filename) + " " + base64.encode(self.text_widget.getText())
            #subprocess.call([save_to_disk])
            #subprocess.call(['runas', '/user:Administrator', sys.executable, save_to_disk, path, text])
            #shell.ShellExecuteEx(lpVerb='runas', lpFile="C:\\Program Files\\IDA 7.0\\plugins\\idagrap\\utils\\save_to_disk.py", lpParameters=params)
            try:
                f = open(filename, "wb")
                f.write(self.text_widget.toPlainText())
                f.close()
                print "[I] Saved pattern to", filename
            except Exception as e:
                print "WARNING:", e


class PatternGenerationHandler(idaapi.action_handler_t):
    def __init__(self, callback):
        idaapi.action_handler_t.__init__(self)
        self.callback = callback

    def activate(self, ctx):
        self.callback()

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class PatternGenerationHooks(idaapi.UI_Hooks):
    def __init__(self, cc):
        idaapi.UI_Hooks.__init__(self)
        self.cc = cc

    def populating_widget_popup(self, form, popup):
        pass

    def finish_populating_widget_popup(self, form, popup):
        try:
            b = idaapi.get_widget_type(form) == idaapi.BWN_DISASM
        except:
            b = idaapi.get_tform_type(form) == idaapi.BWN_DISASM
    
        if b:
            # Add separator
            idaapi.attach_action_to_popup(form, popup, None, None)

            # Add actions
            try:
                currentAddress = idc.get_screen_ea()
            except:
                currentAddress = idc.ScreenEA()

            if currentAddress in [node.node_id for node in self.cc.PatternGenerator.targetNodes]:
                idaapi.attach_action_to_popup(form, popup, "grap:pg:remove_target", None)
            elif self.cc.PatternGenerator.rootNode is None or currentAddress != self.cc.PatternGenerator.rootNode.node_id:
                idaapi.attach_action_to_popup(form, popup, "grap:pg:set_root", None)
                idaapi.attach_action_to_popup(form, popup, "grap:pg:add_target", None)

    def populating_tform_popup(self, form, popup):
        self.populating_widget_popup(form, popup)

    def finish_populating_tform_popup(self, form, popup):
        self.finish_populating_widget_popup(form, popup)