import logging

from PySide2.QtWidgets import QFrame, QLabel, QVBoxLayout, QHBoxLayout, QScrollArea, QSizePolicy, \
    QTableWidget, QTableWidgetItem
from PySide2.QtCore import Qt, QSize

from ...ui.dialogs.new_state import SrcAddrAnnotation

l = logging.getLogger('ui.widgets.qconstraint_viewer')


class QConstraintViewer(QFrame):

    COLUMNS = [ "Constraint", "Src Address", "Cardinality", "Depth", "# Variables" ]

    def __init__(self, state, parent, workspace):
        super(QConstraintViewer, self).__init__(parent)

        self._state = state
        self.workspace = workspace

        self.table = None
       
        self._state.am_subscribe(self._watch_state)

       
    #
    # Public methods
    #

    def reload(self):
        self.table.setRowCount(0)
        for constraint in self._state.solver.constraints:
            count = self.table.rowCount()
            self.table.insertRow(count)
            self.table.setItem(count, 0, QTableWidgetItem(constraint.shallow_repr()))

            src_addr = next(a for a in constraint.annotations if type(a) == SrcAddrAnnotation).addr
            self.table.setItem(count, 1, QTableWidgetItem(hex(src_addr)))

            self.table.setItem(count, 2, QTableWidgetItem(str(constraint.cardinality)))
            self.table.setItem(count, 3, QTableWidgetItem(str(constraint.depth)))
            self.table.setItem(count, 4, QTableWidgetItem(str(len(list(constraint.recursive_leaf_asts)))))

    #
    # Private methods
    #

    def _init_widgets(self):
        if self._state.am_none():
            return

        layout = QVBoxLayout()
        area = QScrollArea()
        area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setWidgetResizable(True)

        table = QTableWidget(0, 0)
        table.setColumnCount(len(self.COLUMNS))
        table.setHorizontalHeaderLabels(self.COLUMNS)

        self.table = table
        layout.addWidget(table)

        # common ones
        layout.setSpacing(0)
        layout.addStretch(0)
        layout.setContentsMargins(2, 2, 2, 2)

        # the container
        container = QFrame()
        container.setAutoFillBackground(True)
        palette = container.palette()
        palette.setColor(container.backgroundRole(), Qt.white)
        container.setPalette(palette)
        container.setLayout(layout)

        area.setWidget(container)

        base_layout = QVBoxLayout()
        base_layout.addWidget(area)
        self.setLayout(base_layout)


    def _watch_state(self, **kwargs):
        if self.table is None:
            self._init_widgets()
        self.reload()
