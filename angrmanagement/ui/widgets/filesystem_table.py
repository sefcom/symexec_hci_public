import re

from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QMenu, QFileDialog
from PySide2.QtGui import QColor
from PySide2.QtCore import Qt

import angr
import claripy


class QFileSystemTable(QTableWidget):
    def __init__(self, items, parent):
        super(QFileSystemTable, self).__init__(parent)

        header_labels = ['Mount Point', 'Host Path']

        self.setColumnCount(len(header_labels))
        self.setHorizontalHeaderLabels(header_labels)
        self.setSelectionBehavior(QAbstractItemView.SelectItems)

        self.setRowCount(len(items))
        for idx, item in enumerate(items):
            for i, it in enumerate(item):
                self.setItem(idx, i, QTableWidgetItem(it))

    def contextMenuEvent(self, event):
        sr = self.currentRow()

        menu = QMenu("", self)

        menu.addAction('Add a Row', self._action_new_symbol)
        menu.addSeparator()

        a = menu.addAction('Delete this Row', self._action_delete)
        if sr is None:
            a.setDisabled(True)
        # b = menu.addAction('Select a File', self._action_select_file)
        # if sr is None:
        #     b.setDisabled(True)
        c = menu.addAction('Select a directory', self._action_select_dir)
        if sr is None:
            c.setDisabled(True)


        menu.exec_(event.globalPos())

    def _action_new_symbol(self):
        row = self.rowCount()
        self.insertRow(row)
        self.setItem(row, 0, QTableWidgetItem("Edit Me"))
        self.setItem(row, 1, QTableWidgetItem(""))

    def _action_select_file(self):
        file_path, succ = QFileDialog.getOpenFileName(self, "Open a real file", "","All executables (*)",)
        if succ:
            self.setItem(self.currentRow(),1,QTableWidgetItem(file_path))

    def _action_select_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select a directory")
        if dir_path:
            self.setItem(self.currentRow(),1,QTableWidgetItem(dir_path))

    def _action_delete(self):
        self.removeRow(self.currentRow())

    def get_result(self):
        ret = []
        for i in range(self.rowCount()):
            ret.append([self.item(i,0).text(), self.item(i,1).text()])
        return ret

