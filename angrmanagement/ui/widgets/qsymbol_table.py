import re

from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QMenu
from PySide2.QtGui import QColor
from PySide2.QtCore import Qt

import angr
import claripy

from ..dialogs.new_symbol import NewSymbol


class QSymbolTableItem(QTableWidgetItem):
    def __init__(self, bv, *args, **kwargs):
        super(QSymbolTableItem, self).__init__(*args, **kwargs)
        self.bv = bv  # type: claripy.BVS

    def widgets(self):

        widgets = [
            QTableWidgetItem(self.bv.args[0]),
            QTableWidgetItem(str(self.bv.length)),
        ]
        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)
            w.setForeground(QColor(0, 0, 0))

        return widgets


class QSymbolTable(QTableWidget):
    def __init__(self, instance, parent, selection_callback=None):
        super(QSymbolTable, self).__init__(parent)

        self._selected = selection_callback

        header_labels = ['Name', 'Length']

        self.setColumnCount(len(header_labels))
        self.setHorizontalHeaderLabels(header_labels)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)

        self.items = []
        self.instance = instance
        self.symbols = instance.symbols

        self.itemDoubleClicked.connect(self._on_symbol_selected)
        self.cellDoubleClicked.connect(self._on_symbol_selected)
        self.symbols.am_subscribe(self._watch_symbols)

    def current_symbols_record(self):
        selected_index = self.currentRow()
        if 0 <= selected_index < len(self.symbols):
            return self.symbols[selected_index]
        else:
            return None

    def reload(self):
        current_row = self.currentRow()
        self.clearContents()

        self.items = [QSymbolTableItem(f) for f in self.symbols]
        items_count = len(self.items)
        self.setRowCount(items_count)

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        #if 0 <= current_row < len(self.items):
        #    self.setCurrentItem(current_row, 0)

    def _on_symbol_selected(self, *args):
        if self._selected is not None:
            self._selected(self.current_symbols_record())

    def contextMenuEvent(self, event):
        sr = self.current_symbols_record()

        menu = QMenu("", self)

        menu.addAction('New Symbol...', self._action_new_symbol)
        menu.addSeparator()

        a = menu.addAction('Delete Symbol', self._action_delete)
        if sr is None:
            a.setDisabled(True)

        menu.exec_(event.globalPos())

    def _action_new_symbol(self):
        dialog = NewSymbol(self.instance, parent=self)
        dialog.exec_()
        if dialog.symbol is not None:
            self.symbols.append(dialog.symbol)
            self.symbols.am_event()
        pass

    def _action_delete(self):
        self.symbols.pop(self.currentRow())
        self.symbols.am_event()

    def _watch_symbols(self, **kwargs):
        self.reload()

