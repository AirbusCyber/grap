#!/usr/bin/env python
# Inspired by IDAscope

import idc
from idaapi import PluginForm
from idagrap.config.General import config

from .helpers.ClassCollection import ClassCollection
from .widgets.CryptoIdentificationWidget import CryptoIdentificationWidget
from .widgets.PatternGenerationWidget import PatternGenerationWidget
from .widgets.AboutWidget import AboutWidget


class IDAgrapForm(PluginForm):
    """IDAgrapForm class.

    This class is the core of the IDAgrap UI.

    Attributes:
        idagrap_widgets (QMainWindow list): List of widgets to add.
        cc (ClassCollection): Collection of many classes.
        icon (QIcon): Icon of the plugin-in.
        parent (QWidget): QWidget to be used by PySide/PyQt5.
        tabs (QTabWidget): Stack of tabbed widgets.
    """

    def __init__(self):
        """Initialization."""
        super(IDAgrapForm, self).__init__()

        self.idagrap_widgets = []
        self.cc = ClassCollection()
        self.icon = self.cc.QIcon(config['icons_path'] + "circle.png")

    def print_banner(self):
        """Print the banner."""
        banner = "{:#^72}\n".format('')
        banner += " ________  ______   ________   _______    ______    ________   ______    \n"
        banner += "/_______/\\/_____/\\ /_______/\\ /______/\\  /_____/\\  /_______/\\ /_____/\\   \n"
        banner += "\\__.::._\\/\\:::_ \\ \\\\::: _  \\ \\\\::::__\\/__\\:::_ \\ \\ \\::: _  \\ \\\\:::_ \\ \\  \n"
        banner += "   \\::\\ \\  \\:\\ \\ \\ \\\\::(_)  \\ \\\\:\\ /____/\\\\:(_) ) )_\\::(_)  \\ \\\\:(_) \\ \\ \n"
        banner += "   _\\::\\ \\__\\:\\ \\ \\ \\\\:: __  \\ \\\\:\\\\_  _\\/ \\: __ `\\ \\\\:: __  \\ \\\\: ___\\/ \n"
        banner += "  /__\\::\\__/\\\\:\\/.:| |\\:.\\ \\  \\ \\\\:\\_\\ \\ \\  \\ \\ `\\ \\ \\\\:.\\ \\  \\ \\\\ \\ \\   \n"
        banner += "  \\________\\/ \\____/_/ \\__\\/\\__\\/ \\_____\\/   \\_\\/ \\_\\/ \\__\\/\\__\\/ \\_\\/   \n\n"
        banner += "{:~^72}\n".format('')
        banner += "{:^72}\n".format('Airbus Defence & Space')
        banner += "{:#^72}\n".format('')

        print banner

    def setupWidgets(self):
        """
        Setup IDAgrap widgets.
        """

        print "[/] setting up widgets..."

        # Initialization of the widgets
        self.idagrap_widgets.append(CryptoIdentificationWidget(self))
        self.idagrap_widgets.append(PatternGenerationWidget(self))
        self.idagrap_widgets.append(AboutWidget(self))
        self.setupIDAgrapForm()

        print "[\\] end widgets"

    def setupIDAgrapForm(self):
        """
        Orchestrate the already initialized widgets in tabs on the main
        window.
        """
        self.tabs = self.cc.QTabWidget()
        self.tabs.setTabsClosable(False)

        # Add all the widgets
        for widget in self.idagrap_widgets:
            self.tabs.addTab(widget, widget.icon, widget.name)

        # Lines up widgets
        layout = self.cc.QVBoxLayout()
        layout.addWidget(self.tabs)

        # Set layout in QWidget
        self.parent.setLayout(layout)

    def OnCreate(self, form):
        """OnCreate of IDAgrap.

        This event is called when the plugin form is created.

        Arguments:
            form (TForm*): Plug-in form.
        """
        self.print_banner()

        # compatibility with IDA < 6.9
        # Convert TForm* for PyQt or PySide
        try:
            self.parent = self.FormToPySideWidget(form)
        except Exception:
            self.parent = self.FormToPyQtWidget(form)

        self.parent.setWindowIcon(self.icon)
        self.setupWidgets()

    def Show(self):
        """
        Creates the form and brings it to the front.
        """
        
        try:
            input_md5 = idc.retrieve_input_file_md5()
        except:
            input_md5 = idc.GetInputMD5()
        
        if input_md5 is None:
            return
        else:
            name = "{} {}".format(config['name'], config['version'])
			
            try:
                options = PluginForm.WCLS_CLOSE_LATER |\
                        PluginForm.WCLS_SAVE |\
                        PluginForm.WOPN_RESTORE
            except:
                options = PluginForm.FORM_CLOSE_LATER |\
                          PluginForm.FORM_SAVE |\
                          PluginForm.FORM_RESTORE

            return PluginForm.Show(self, name, options=options)
