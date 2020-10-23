from collections import defaultdict
from typing import List, Optional, Type, Union, Callable, TYPE_CHECKING

from PySide2.QtGui import QMouseEvent, QCursor, QContextMenuEvent
from PySide2.QtWidgets import QTreeWidget, QTreeWidgetItem, QMenu, QMessageBox, QHBoxLayout, QLabel, QLineEdit, QDialog, \
    QInputDialog, QAbstractItemView
from PySide2.QtCore import Qt

from angr import SimState


class SimgrViewerAbstractTreeItem(QTreeWidgetItem):

    def handle_context_menu_event(self, event: QContextMenuEvent):
        """Handles right-click actions on the specific QTreeWidgetItem that was clicked in the view"""
        raise NotImplemented()


class StashTreeItem(SimgrViewerAbstractTreeItem):

    def __init__(self, stash_name, simgr_viewer):
        self.simgr_viewer = simgr_viewer
        self.stash_name = stash_name
        super().__init__(simgr_viewer)
        self.setFlags(self.flags() & ~Qt.ItemIsSelectable)
        self.refresh()

    def __iter__(self):
        for i in range(self.childCount()):
            yield self.child(i)

    @property
    def states(self):
        return self.simgr_viewer.simgr.stashes[self.stash_name]

    def refresh(self):
        self.takeChildren()
        for state in self.simgr_viewer.simgr.stashes[self.stash_name]:
            if self.stash_name == "errored" and getattr(state, "state", None):
                state = state.state
            self.addChild(StateTreeItem(state, self.simgr_viewer))
        self.setText(0, "%s (%d)" % (self.stash_name, len(self.states)))

    def handle_context_menu_event(self, event):
        menu = QMenu()
        menu.addAction("Copy states", self.copy_states)
        menu.addAction("Cut states", self.cut_states)
        if self.simgr_viewer.state_clipboard:
            plural = ""
            if len(self.simgr_viewer.state_clipboard) > 1:
                plural += "s"
            menu.addAction("Paste state" + plural, self.paste_states)
        menu.addAction("Delete stash", self.delete_stash)
        menu.exec_(QCursor.pos())

    def copy_states(self):
        self.simgr_viewer.state_clipboard = [s.state for s in self]
        self.refresh()

    def cut_states(self):
        self.simgr_viewer.state_clipboard = [s.state for s in self]
        self.simgr_viewer.simgr.drop(stash=self.stash_name, filter_func=lambda state: state in self.states)
        self.refresh()

    def delete_stash(self, *args, **kwargs):
        self.simgr_viewer.simgr._stashes.pop(self.stash_name)
        self.simgr_viewer.refresh()

    def paste_states(self, *args, **kwargs):
        self.simgr_viewer.paste_from_clipboard(self.stash_name)
        self.refresh()


class StateTreeItem(SimgrViewerAbstractTreeItem):

    def __init__(self, state, simgr_viewer):
        self.state = state
        self.simgr_viewer: QSimulationManagerViewer = simgr_viewer
        super().__init__([str(state)])
        self.setData(0, 1, state)

    @property
    def stash_name(self):
        return self.parent().stash_name

    def handle_context_menu_event(self, event):
        menu = QMenu()
        self.add_menu_action(menu, "Copy state", self.copy_states)
        self.add_menu_action(menu, "Cut state", self.cut_states)
        self.add_menu_action(menu, "Delete state", self.delete_states)
        if self.simgr_viewer.state_clipboard:
            self.add_menu_action(menu, "Paste state", self.paste_states)
        menu.exec_(QCursor.pos())

    def add_menu_action(self, menu, string, action):
        plural = ""
        if len(self.simgr_viewer.selectedItems()) > 1:
            plural = "s"
        menu.addAction(string + plural, action)

    def copy_states(self, *args, **kwargs):
        self.simgr_viewer.copy_selected_to_clipboard()

    def cut_states(self, *args, **kwargs):
        self.simgr_viewer.cut_selected_to_clipboard()

    def delete_states(self, *args, **kwargs):
        self.simgr_viewer.delete_selected_states()

    def paste_states(self, *args, **kwargs):
        self.simgr_viewer.paste_from_clipboard(self.stash_name)


class QSimulationManagerViewer(QTreeWidget):

    state_clipboard: List[SimState]

    def __init__(self, simgr, parent=None):
        super(QSimulationManagerViewer, self).__init__(parent)

        self.setColumnCount(1)
        self.setHeaderHidden(True)

        self.simgr = simgr
        self.state_clipboard = []

        self._init_widgets()

        self.simgr.am_subscribe(self.refresh)
        self.setSelectionMode(QAbstractItemView.MultiSelection)

    def _stash_to_selected_states(self):
        stash_to_states = defaultdict(list)
        for state_tree_item in self.selectedItems():
            stash_to_states[state_tree_item.stash_name].append(state_tree_item.state)
        return stash_to_states

    def copy_selected_to_clipboard(self):
        self.state_clipboard = [item.state.copy() for item in self.selectedItems()]

    def cut_selected_to_clipboard(self):
        self.copy_selected_to_clipboard()
        self.delete_selected_states()

    def delete_selected_states(self):
        stash_to_states = self._stash_to_selected_states()
        for stash_name, states in stash_to_states.items():
            self.simgr.drop(stash=stash_name, filter_func=lambda state: state in states)
            self.get_stash_tree_item(stash_name).refresh()

    def paste_from_clipboard(self, stash_name):
        self.simgr.populate(stash_name, self.state_clipboard)
        self.get_stash_tree_item(stash_name).refresh()

    def contextMenuEvent(self, event: QContextMenuEvent):
        item = self.itemAt(event.pos())
        if item is not None:
            item.handle_context_menu_event(event)
        else:
            menu = QMenu()
            menu.addAction("Create new stash", self._create_new_stash)
            menu.exec_(QCursor.pos())

    def _create_new_stash(self, *args, **kwargs):

        stash_name, accepted = QInputDialog.getText(self, "Stash name", "Blah")

        if not accepted or stash_name.strip() == "":
            # The user didn't provide a stash name
            return

        if stash_name in self.simgr.stashes:
            QMessageBox.critical(None, 'Duplicate stash name',
                                 f"A stash with the name {stash_name} already exists in the current simulation manager.")
            return
        self.simgr._stashes[stash_name] = list()
        self.refresh()

    def refresh(self, **kwargs):
        self._init_widgets()

    def current_state(self):
        item = self.currentItem()
        if item is None:
            return None
        return item.data(0, 1)

    def select_state(self, state):
        if state is None:
            self.setCurrentItem(None)
        else:
            for i in range(self.topLevelItemCount()):
                item = self.topLevelItem(i)
                for j in range(item.childCount()):
                    subitem = item.child(j)
                    if subitem.data(0, 1) == state:
                        self.setCurrentItem(subitem)
                        break
                else:
                    continue
                break

    def get_stash_tree_item(self, stash_name):
        return self.stash_tree_items[stash_name]

    def _init_widgets(self):
        self.clear()

        if self.simgr.am_none():
            return

        self.stash_tree_items = {}
        for stash_name, stash in self.simgr.stashes.items():
            # if not stash and stash_name not in ('active', 'deadended', 'avoided'):
            #     continue
            item = StashTreeItem(stash_name, simgr_viewer=self)
            self.stash_tree_items[stash_name] = item
            self.addTopLevelItem(item)