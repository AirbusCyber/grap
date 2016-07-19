#!/usr/bin/python

# Inspired by https://bitbucket.org/daniel_plohmann/simplifire.idascope/raw/438a8f8a83b8ef7599b72c78cd2d843aa23c407c/idascope/core/helpers/ClassCollection.py
########################################################################
# Copyright (c) 2016
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  This file is part of IDAscope
#
#  IDAscope is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################


# helpers
import QtShim as QtShim
from idagrap.core.CryptoIdentifier import CryptoIdentifier


class ClassCollection():
    """Collection of classes.

    This class is a collection of many classes. The goal of this
    ClassCollection is to simplify the access to Qt and personal classes.
    """

    def __init__(self):
        """Initialization."""
        # python imports
        # PySide / PyQt imports
        self.QtShim = QtShim
        self.QtGui = self.QtShim.get_QtGui()
        self.QtCore = self.QtShim.get_QtCore()
        self.QIcon = self.QtShim.get_QIcon()
        self.QWidget = self.QtShim.get_QWidget()
        self.QVBoxLayout = self.QtShim.get_QVBoxLayout()
        self.QHBoxLayout = self.QtShim.get_QHBoxLayout()
        self.QSplitter = self.QtShim.get_QSplitter()
        self.QStyleFactory = self.QtShim.get_QStyleFactory()
        self.QLabel = self.QtShim.get_QLabel()
        self.QTableWidget = self.QtShim.get_QTableWidget()
        self.QAbstractItemView = self.QtShim.get_QAbstractItemView()
        self.QTableWidgetItem = self.QtShim.get_QTableWidgetItem()
        self.QPushButton = self.QtShim.get_QPushButton()
        self.QScrollArea = self.QtShim.get_QScrollArea()
        self.QSizePolicy = self.QtShim.get_QSizePolicy()
        self.QLineEdit = self.QtShim.get_QLineEdit()
        self.QTextEdit = self.QtShim.get_QTextEdit()
        self.QMainWindow = self.QtShim.get_QMainWindow()
        self.QSlider = self.QtShim.get_QSlider()
        self.QCompleter = self.QtShim.get_QCompleter()
        self.QTextBrowser = self.QtShim.get_QTextBrowser()
        self.QStringListModel = self.QtShim.get_QStringListModel()
        self.QDialog = self.QtShim.get_QDialog()
        self.QGroupBox = self.QtShim.get_QGroupBox()
        self.QRadioButton = self.QtShim.get_QRadioButton()
        self.QComboBox = self.QtShim.get_QComboBox()
        self.QCheckBox = self.QtShim.get_QCheckBox()
        self.QAction = self.QtShim.get_QAction()
        self.QColor = self.QtShim.get_QColor()
        self.QBrush = self.QtShim.get_QBrush()
        self.QTreeWidget = self.QtShim.get_QTreeWidget()
        self.QTreeWidgetItem = self.QtShim.get_QTreeWidgetItem()
        self.QStyle = self.QtShim.get_QStyle()
        self.QPainter = self.QtShim.get_QPainter()
        self.QApplication = self.QtShim.get_QApplication()
        self.QStyleOptionSlider = self.QtShim.get_QStyleOptionSlider()
        self.QTabWidget = self.QtShim.get_QTabWidget()
        self.DescendingOrder = self.QtShim.get_DescendingOrder()

        # IDAgrap
        self.CryptoIdentifier = CryptoIdentifier()
