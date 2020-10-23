import logging

from collections import defaultdict
from bisect import bisect_right
from typing import Optional, Tuple, Callable, Iterator, List, Any, Union

from PySide2.QtCore import Qt
from PySide2.QtGui import QColor
from PySide2.QtWidgets import QTableWidget, QDockWidget, QTableWidgetItem, QVBoxLayout, QWidget

from ..base_plugin import BasePlugin
from ...ui.widgets.qoperand import QOperand
from ...ui.widgets.qsimulation_manager_viewer import QSimulationManagerViewer, StateTreeItem

l = logging.getLogger('plugins.state_disasm_viewer')
l.setLevel("DEBUG")


class StateDisasmViewer(BasePlugin):

    def __init__(self, *args, **kwargs):
        super(StateDisasmViewer, self).__init__(*args, **kwargs)
        self.layout = None

        self.state_history = []

        self.disasm_view = self.workspace.view_manager.first_view_in_category("disassembly")
        self.symexec_view = self.workspace.view_manager.first_view_in_category("symexec")
        self.simgrs = self.workspace.instance.simgrs
        self.simgr_viewer = None

        self._init_widgets()

    def color_block(self, addr) -> Optional[QColor]:
        addr_count = self.state_history.count(addr)
        return QColor(max(0xff - (addr_count*0x10), 0x10),
                      0xff,
                      max(0xff - (addr_count*0x10), 0x10))

    def _on_state_selection(self):
        state = self.simgr_viewer.current_state()
        if state:
            self.state_history = list(state.history.bbl_addrs)
        else:
            self.state_history = []
        self.disasm_view.redraw_current_graph()

    def _init_states_viewer(self):
        curr_simgr = self.symexec_view.current_simgr
        viewer = QSimulationManagerViewer(curr_simgr)
        viewer.currentItemChanged.connect(self._on_state_selection)
        self.simgr_viewer = viewer

        def _jump_to_state_address(item, column):
            if not isinstance(item, StateTreeItem):
                return
            self.workspace.jump_to(item.state.addr)

        viewer.itemDoubleClicked.connect(_jump_to_state_address)

        layout = self.layout
        layout.addWidget(viewer)

    def _init_widgets(self):
        layout = QVBoxLayout()
        w = QWidget()
        w.setLayout(layout)
        dock = QDockWidget("States")
        dock.setWidget(w)
        self.disasm_view.main_window.addDockWidget(Qt.RightDockWidgetArea, dock)
        self.layout = layout
        self._init_states_viewer()
