from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, \
    QGridLayout, QComboBox, QPlainTextEdit, \
    QLineEdit, QTextEdit, QTreeWidget, QTreeWidgetItem, QMessageBox
from PySide2.QtCore import Qt
from PySide2.QtGui import QTextOption
import angr
import claripy

from ..widgets import QAddressInput, QStateComboBox
from ...utils.namegen import NameGenerator


class NewSymbol(QDialog):
    def __init__(self, instance, parent=None):
        super(NewSymbol, self).__init__(parent)
        # initialization
        self.instance = instance
        self.setWindowTitle('New Symbol')
        self.main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self.main_layout)
        self.symbol = None  # output
    #
    # Private methods
    #

    def _init_widgets(self):
        layout = QGridLayout()
        row = 0

        # name
        name_label = QLabel(self)
        name_label.setText("Name")
        name_box = QLineEdit(self)
        layout.addWidget(name_label, row, 0)
        layout.addWidget(name_box, row, 1)
        row += 1

        # length
        length_label = QLabel(self)
        length_label.setText("Length")
        length_box = QLineEdit(self)
        layout.addWidget(length_label, row, 0)
        layout.addWidget(length_box, row, 1)
        row += 1

        # # value
        # value_label = QLabel(self)
        # value_label.setText("Value")
        # value_box = QLineEdit(self)
        # layout.addWidget(value_label, row, 0)
        # layout.addWidget(value_box, row, 1)
        # row += 1

        # buttons

        ok_button = QPushButton(self)
        ok_button.setText('OK')

        def do_ok():
            name = name_box.text()
            try:
                length = int(length_box.text())
            except ValueError:
                QMessageBox.critical(self,"","Invalid Length")
                return
            self.symbol = claripy.BVS(name, length)
            self.close()

        ok_button.clicked.connect(do_ok)

        cancel_button = QPushButton(self)
        cancel_button.setText('Cancel')
        def do_cancel():
            self.close()
        cancel_button.clicked.connect(do_cancel)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        self.main_layout.addLayout(layout)
        self.main_layout.addLayout(buttons_layout)
