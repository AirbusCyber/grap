# Source : https://bitbucket.org/daniel_plohmann/simplifire.idascope/raw/438a8f8a83b8ef7599b72c78cd2d843aa23c407c/idascope/core/helpers/QtShim.py
# Provides a common interface between PyQt5 and PySide.


def get_QtCore():
    """QtCore getter."""

    try:
        # IDA 6.8 and below
        import PySide.QtCore as QtCore
        return QtCore
    except ImportError:
        # IDA 6.9
        import PyQt5.QtCore as QtCore
        return QtCore


def get_QtGui():
    """QtGui getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui
    except ImportError:
        import PyQt5.QtGui as QtGui
        return QtGui


def get_QtWidgets():
    """QtWidgets getter."""

    try:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets
    except ImportError:
        return None


def get_QTreeWidget():
    """QTreeWidget getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QTreeWidget
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidget


def get_QTreeWidgetItem():
    """QTreeWidgetItem getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QTreeWidgetItem
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidgetItem


def get_QTableWidgetItem():
    """QTableWidgetItem getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidgetItem
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidgetItem


def get_QIcon():
    """QIcon getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QIcon
    except ImportError:
        import PyQt5.QtGui as QtGui
        return QtGui.QIcon


def get_QWidget():
    """QWidget getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QWidget
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QWidget


def get_QVBoxLayout():
    """QVBoxLayout getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QVBoxLayout
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QVBoxLayout


def get_QHBoxLayout():
    """QHBoxLayout getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QHBoxLayout
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QHBoxLayout


def get_QSplitter():
    """QSplitter getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QSplitter
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSplitter


def get_QStyleFactory():
    """QStyleFactory getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QStyleFactory
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleFactory


def get_QStyleOptionSlider():
    """QStyleOptionSlider getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QStyleOptionSlider
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleOptionSlider


def get_QApplication():
    """QApplication getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QApplication
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QApplication


def get_QPainter():
    """QPainter getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QPainter
    except ImportError:
        import PyQt5.QtGui as QtGui
        return QtGui.QPainter


def get_DescendingOrder():
    """DescendingOrder getter."""

    try:
        import PySide.QtCore as QtCore
        return QtCore.Qt.SortOrder.DescendingOrder
    except ImportError:
        import PyQt5.QtCore as QtCore
        return QtCore.Qt.DescendingOrder


def get_QTabWidget():
    """QTabWidget getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QTabWidget
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTabWidget


def get_QStyle():
    """QStyle getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QStyle
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyle


def get_QLabel():
    """QLabel getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QLabel
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QLabel


def get_QTableWidget():
    """QTableWidget getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidget
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidget


def get_QTableWidgetItem():
    """QTableWidgetItem getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidgetItem
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidgetItem


def get_QPushButton():
    """QPushButton getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QPushButton
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QPushButton


def get_QAbstractItemView():
    """QAbstractItemView getter."""

    try:
        import PySide.QtGui as QtGui

        return QtGui.QAbstractItemView
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QAbstractItemView


def get_QScrollArea():
    """QScrollArea getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QScrollArea
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QScrollArea


def get_QSizePolicy():
    """QSizePolicy getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QSizePolicy
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSizePolicy


def get_QLineEdit():
    """QLineEdit getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QLineEdit
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QLineEdit


def get_QCompleter():
    """QCompleter getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QCompleter
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCompleter


def get_QTextBrowser():
    """QTextBrowser getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QTextBrowser
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTextBrowser


def get_QSlider():
    """QSlider getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QSlider
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSlider


def get_QMainWindow():
    """QMainWindow getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QMainWindow
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QMainWindow


def get_QTextEdit():
    """QTextEdit getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QTextEdit
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTextEdit


def get_QDialog():
    """QDialog getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QDialog
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QDialog


def get_QGroupBox():
    """QGroupBox getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QGroupBox
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QGroupBox


def get_QRadioButton():
    """QRadioButton getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QRadioButton
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QRadioButton


def get_QComboBox():
    """QComboBox getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QComboBox
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QComboBox


def get_QCheckBox():
    """QCheckBox getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QCheckBox
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCheckBox


def get_QAction():
    """QAction getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QAction
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QAction


def get_QBrush():
    """QBrush getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QBrush
    except ImportError:
        import PyQt5.QtGui as QtGui
        return QtGui.QBrush


def get_QColor():
    """QColor getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QColor
    except ImportError:
        import PyQt5.QtGui as QtGui
        return QtGui.QColor


def get_QStringListModel():
    """QStringListModel getter."""

    try:
        import PySide.QtGui as QtGui
        return QtGui.QStringListModel
    except ImportError:
        import PyQt5.QtCore as QtCore
        return QtCore.QStringListModel


def get_Signal():
    """Signal getter."""

    try:
        import PySide.QtCore as QtCore
        return QtCore.Signal
    except ImportError:
        import PyQt5.QtCore as QtCore
        return QtCore.pyqtSignal

        
def get_QFileDialog():
    """QFileDialog getter."""

    try:
        import PySide.QtCore as QtCore
        return QtCore.QFileDialog
    except ImportError:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QFileDialog
