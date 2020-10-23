from PySide2.QtWidgets import QMainWindow, QHBoxLayout, QDockWidget
from PySide2.QtCore import Qt,QSize

from ..widgets.qsymbol_table import QSymbolTable
from .view import BaseView

class SymbolsView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(SymbolsView, self).__init__('symbols', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Symbols'
        self._symbols_table = None  # type: QSymbolTable or None
        self.workspace = workspace

        self._init_widgets()

    def reload(self):
        self._symbols_table.state_manager = self.workspace.instance.states

    def sizeHint(self):
        return QSize(400, 800)

    def _init_widgets(self):
        self._symbols_table = QSymbolTable(self.workspace.instance, self)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self._symbols_table)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)
