#!/usr/bin/env python
# Inspired by IDAscope.


from pygrap import graph_free

import idagrap.ui.helpers.QtShim as QtShim
import idc
import idaapi
from idagrap.config.General import config
from idagrap.patterns.Modules import MODULES
import idagrap.ui.helpers.QtGrapSyntax as syntax
import os

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

        self.real_time_option = True

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # Toolbar
        self._createToolbar()
        
        # Quick pattern text
        self._createQuickPatternTextWidget()

        # Text pattern
        self._createTextWidget()

        # Options widgets
        self._createOptionsWidgets()

        # Layout and fill the widget
        generation_layout = self.cc.QVBoxLayout()

        for options_widget in self.options_widgets:
            generation_layout.addWidget(options_widget)

        hbox = self.cc.QHBoxLayout()
        hbox.addWidget(self.text_qp_widget)
        hbox.addWidget(self.toolbar_qp)
        generation_layout.addLayout(hbox)
        
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
        
    def _createQuickPatternTextWidget(self):
        self.text_qp_widget = self.cc.QLineEdit()
        self.text_qp_widget.setReadOnly(False)
        
        self.toolbar_qp = self.addToolBar('Pattern Generation Toolbar')
        self._createGenerateQuickPatternAction()
        self.toolbar_qp.addAction(self.generateQuickPatternAction)
        self.text_qp_widget.returnPressed.connect(self._onGenerateQuickPatternButtonClicked)

    def _createTextWidget(self):
        self.text_widget = self.cc.QTextEdit()
        self.text_widget.setReadOnly(False)
        self.text_widget.setFontFamily("Monospace")
        self.highlight = syntax.PythonHighlighter(self.text_widget.document())

    def _createOptionsWidgets(self):
        self.options_widgets = []

        self.real_time_check = self.cc.QCheckBox("Automatically update the pattern")
        self.real_time_check.setChecked(True)
        self.real_time_check.stateChanged.connect(self._real_time_check_option_trigger)
        self.options_widgets.append(self.real_time_check)
        
        self.generic_arguments_check = self.cc.QCheckBox("Generic arguments")
        self.generic_arguments_check.stateChanged.connect(self._generic_arguments_option_trigger)
        self.options_widgets.append(self.generic_arguments_check)

        self.lighten_memory_ops_check = self.cc.QCheckBox("Lighten memory handling operations")
        self.lighten_memory_ops_check.stateChanged.connect(self._lighten_memory_ops_option_trigger)
        self.options_widgets.append(self.lighten_memory_ops_check)

        self.std_jmp_check = self.cc.QCheckBox("Standardize jump operations")
        self.std_jmp_check.stateChanged.connect(self._std_jmp_check_option_trigger)
        self.options_widgets.append(self.std_jmp_check)

        self.factorize_check = self.cc.QCheckBox("Factorize")
        self.factorize_check.stateChanged.connect(self._factorize_check_option_trigger)
        self.options_widgets.append(self.factorize_check)

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
        if self.real_time_option:
            self.text_widget.setText(self.cc.PatternGenerator.generate())
        self.generateAction.setEnabled(not self.real_time_option)

    def _createLoadGraphAction(self):
        """
        Create an action for the load graph button of the toolbar and connect it.
        """
        # Action
        self.loadGraphAction = self.cc.QAction(
            self.cc.QIcon(config['icons_path'] + "icons8-fingerprint-scan.png"),
            "Load the Control Flow Graph (might take some time)",
            self
        )

        self.loadGraphAction.triggered.connect(self._onLoadGraphButtonClickedThread)

    def _createGenerateAction(self):
        # Action
        self.generateAction = self.cc.QAction(
            self.cc.QIcon(config['icons_path'] + "icons8-workflow.png"),
            "Generate a pattern (enabled only if you disable the \"Auto update\" option)",
            self
        )
        self.generateAction.setEnabled(False)

        self.generateAction.triggered.connect(self._onGenerateButtonClicked)
        
    def _createGenerateQuickPatternAction(self):
        # Action
        self.generateQuickPatternAction = self.cc.QAction(
            self.cc.QIcon(config['icons_path'] + "icons8-workflow.png"),
            "Generate a pattern from this short pattern field (for instance: xor->add->xor)",
            self
        )

        self.generateQuickPatternAction.triggered.connect(self._onGenerateQuickPatternButtonClicked)

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
        try:
            self.cc.PatternGenerator.setRootNode(idc.get_screen_ea())
        except:
            self.cc.PatternGenerator.setRootNode(idc.ScreenEA())

        if self.real_time_option:
            self.text_widget.setText(self.cc.PatternGenerator.generate(auto=True))
            self._enable_options()

    def _onAddTargetNode(self):
        try:
            self.cc.PatternGenerator.addTargetNode(idc.get_screen_ea())
        except:
            self.cc.PatternGenerator.addTargetNode(idc.ScreenEA())

        if self.real_time_option:
            self.text_widget.setText(self.cc.PatternGenerator.generate(auto=True))
            self._enable_options()

    def _onRemoveTargetNode(self):
        try:
            self.cc.PatternGenerator.removeTargetNode(idc.get_screen_ea())
        except:
            self.cc.PatternGenerator.removeTargetNode(idc.ScreenEA())

        if self.real_time_option:
            self.text_widget.setText(self.cc.PatternGenerator.generate(auto=True))
            self._enable_options()

    def _onLoadGraphButtonClickedThread(self):
        self._onLoadGraphButtonClicked()

    def _onLoadGraphButtonClicked(self):
        # Analyzing
        self.cc.PatternGenerator.analyzing()

        # Update the UI
        if not self.actionsDefined:
            self._createContextActions()
            self._updateContextMenus()
            
        # UI information
        print "[I] CFG loaded. You can now define your pattern's root node and target nodes (right click on an instruction in IDA View)."

    def _onGenerateQuickPatternButtonClicked(self):
        print "[I] Generation of quick pattern"
        self.text_widget.setText(self.cc.PatternGenerator.generate_quick_pattern(self.text_qp_widget.text()))
        self._disable_options()
        
    def _onGenerateButtonClicked(self):
        print "[I] Generation of pattern"
        self.text_widget.setText(self.cc.PatternGenerator.generate())
        self._enable_options()

    def _onResetButtonClicked(self):
        print "[I] Reset pattern"
        self.cc.PatternGenerator.resetPattern()
        self.text_widget.clear()
        self._enable_options()
        
    def _onSaveButtonClicked(self):
        pattern_text = self.text_widget.toPlainText()
        
        if len(pattern_text.strip()) == 0:
            print "WARNING: Pattern is empty."
            return
    
        print "[I] Saving pattern"
        options = self.cc.QFileDialog.Options()
        #options |= self.cc.QFileDialog.DontUseNativeDialog
        
        if "user_patterns_path" in config:
            default_path = config["user_patterns_path"]
        else:
            default_path = config["patterns_path"] + os.path.sep + "test"+ os.path.sep + "misc" + os.path.sep + "files"
        default_filename = default_path + os.path.sep + "generated.grapp"
            
        filename, _ = self.cc.QFileDialog.getSaveFileName(self, "Save pattern file (.grapp files in %APPDATA%\IDAgrap\patterns will be parsed as patterns)", default_filename, "Grap pattern (*.grapp)", options=options)
        if filename:            
            try:
                f = open(filename, "wb")
                f.write(pattern_text)
                f.close()
            except Exception as e:
                print "WARNING:", e
                
    def _disable_options(self):    
        self.generic_arguments_check.setEnabled(False)
        self.lighten_memory_ops_check.setEnabled(False)
        self.std_jmp_check.setEnabled(False)
        self.factorize_check.setEnabled(False)

    def _enable_options(self):    
        self.generic_arguments_check.setEnabled(True)
        self.lighten_memory_ops_check.setEnabled(True)
        self.std_jmp_check.setEnabled(True)
        self.factorize_check.setEnabled(True)


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