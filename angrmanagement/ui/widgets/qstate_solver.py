import logging

from PySide2.QtWidgets import QFrame, QLabel, QVBoxLayout, QHBoxLayout, QScrollArea, QSizePolicy, \
    QTableWidget, QTableWidgetItem, QLineEdit, QComboBox, QPushButton, QMessageBox
from PySide2.QtCore import Qt, QSize


class QStateSolver(QFrame):
    COLUMNS = ["Name","Cast to", "Value"]

    def __init__(self, state, parent, workspace):
        super(QStateSolver,self).__init__(parent)

        self._state = state
        self.workspace = workspace

        self.table = None  # type: QTableWidget or None
        self._state.am_subscribe(self._watch_state)

    def reload(self):
        self.table.clearContents()
        self.table.setRowCount(0)

    def solver(self, bv, cast_to):
        return self._state.solver.eval(bv,cast_to=cast_to)

    def _init_widgets(self):
        if self._state.am_none():
            return

        layout = QVBoxLayout()

        input_layout = QHBoxLayout()
        symbol_name = QLineEdit(self)
        symbol_type = QComboBox(self)
        symbol_type.addItem("As Bytes", bytes)
        symbol_type.addItem("As Int", int)
        symbol_butt = QPushButton(self, text="Go")

        input_layout.addWidget(symbol_name)
        input_layout.addWidget(symbol_type)
        input_layout.addWidget(symbol_butt)

        def symbol_solve():
            name = symbol_name.text()
            tmp = [symbol for symbol in self.workspace.instance.symbols if symbol.args[0].split('_')[0] == name]
            if len(tmp) != 1:
                QMessageBox.critical(self, "Symbol Not found", "Invalid Symbol Name")
                return
            typ_name = symbol_type.currentText()
            typ = symbol_type.currentData()
            res = self.solver(tmp[0], typ)
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row,0,QTableWidgetItem(name))
            self.table.setItem(row,1,QTableWidgetItem(typ_name))
            self.table.setItem(row,2,QTableWidgetItem(str(res)))

        symbol_butt.clicked.connect(symbol_solve)

        table = QTableWidget(self)
        table.setColumnCount(len(self.COLUMNS))
        table.setHorizontalHeaderLabels(self.COLUMNS)

        self.table = table
        layout.addLayout(input_layout)
        layout.addWidget(table)

        layout.setSpacing(0)
        layout.addStretch(0)
        layout.setContentsMargins(2, 2, 2, 2)

        self.setLayout(layout)

    def _watch_state(self, **kwargs):
        if self.table is None:
            self._init_widgets()
        self.reload()