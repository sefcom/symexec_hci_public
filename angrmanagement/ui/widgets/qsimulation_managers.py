from typing import List

from PySide2.QtWidgets import QFrame, QLabel, QComboBox, QHBoxLayout, QVBoxLayout, QLineEdit, QPushButton, QGroupBox, \
    QCheckBox, QTabWidget, QListWidget, QListWidgetItem, QSpinBox, QMessageBox
from PySide2.QtCore import QSize, Qt, Signal

from angr import SimState
from ...data.jobs import SimgrStepJob, SimgrExploreJob
from ...data.instance import Instance
from ..widgets.qsimulation_manager_viewer import QSimulationManagerViewer, StateTreeItem, StashTreeItem
from ..dialogs.strategy import AddStrategy
from ..dialogs.strategy import ShowStrategy
from ...logic import GlobalInfo
from ...logic.threads import gui_thread_schedule

import angr


class QSimulationManagers(QFrame):

    def __init__(self, instance, simgr, state, parent=None):
        """
        :param Instance instance:       The data source for this project
        :param object parent:           The parent widget.
        """
        super(QSimulationManagers, self).__init__(parent)

        self.instance = instance
        self.simgrs = instance.simgrs
        self.simgr = simgr
        self.state = state
        self.step_count = 0

        self._simgrs_list = None  # type: QComboBox
        self._avoids_list = None  # type: QListWidget
        self._finds_list = None  # type: QListWidget
        self._simgr_viewer = None  # type: QSimulationManagerViewer
        self._oneactive_checkbox = None  # type: QCheckBox
        self._max_active = None # type: QSpinBox
        self._max_steps = None # type: QSpinBox

        self._init_widgets()

        self.simgr.am_subscribe(self._watch_simgr)
        self.simgrs.am_subscribe(self._watch_simgrs)
        self.state.am_subscribe(self._watch_state)

    @property
    def find_addrs(self):
        return [int(item.text(), 16) for item in self._get_checked_items(self._finds_list)]

    @property
    def avoid_addrs(self):
        return [int(item.text(), 16) for item in self._get_checked_items(self._avoids_list)]

    #
    # Public methods
    #

    def refresh(self):
        self._simgrs_list.clear()
        for i, simgr in enumerate(self.simgrs):
            self._simgrs_list.addItem(simgr.am_name)
            if simgr is self.simgr.am_obj:
                self._simgrs_list.setCurrentIndex(i)

    def add_avoid_address(self, addr):
        for i in range(self._avoids_list.count()):
            item = self._avoids_list.item(i)  # type: QListWidgetItem
            if int(item.text(), 16) == addr:
                # deduplicate
                return

        item = QListWidgetItem("%#x" % addr)
        item.setData(Qt.CheckStateRole, Qt.Checked)

        self._avoids_list.addItem(item)

    def add_find_address(self, addr):
        for i in range(self._finds_list.count()):
            item = self._finds_list.item(i)  # type: QListWidgetItem
            if int(item.text(), 16) == addr:
                # deduplicate
                return

        item = QListWidgetItem("%#x" % addr)
        item.setData(Qt.CheckStateRole, Qt.Checked)

        self._finds_list.addItem(item)

    def remove_find_address(self, addr):
        self._remove_addr(self._finds_list, addr)

    def remove_avoid_address(self, addr):
        self._remove_addr(self._avoids_list, addr)

    def select_states(self, states: List[SimState]):
        # TODO: hci: feature #3: Support more than just the active stash
        stash_tree_item = self._simgr_viewer.get_stash_tree_item("active")
        for state_tree_item in stash_tree_item:
            # TODO: hci: refactor: Use a set for the inner loop to avoid n^2 loop
            for state in states:
                if state_tree_item.state == state:
                    state_tree_item.setSelected(True)
        stash_tree_item.setExpanded(True)

    def select_states_that_passed_through(self, addr):
        # TODO: hci: refactor (big): looping over all active states and all bbl addrs could be pretty slow, we'll see.
        #  Note: This is only called when a user clicks on a red bubble in the disassembly view, so the expensive
        #  cost of calculating this is infrequent. Might affect user experience though if there are many states with
        #  deep execution
        stash_tree_item = self._simgr_viewer.get_stash_tree_item("active")
        for state_tree_item in stash_tree_item:
            state = state_tree_item.state
            for bbl_addr in state.history.bbl_addrs:
                if bbl_addr == addr:
                    state_tree_item.setSelected(True)
        stash_tree_item.setExpanded(True)

    #
    # Initialization
    #

    def _init_widgets(self):
        tab = QTabWidget()

        self._init_simgrs_tab(tab)
        self._init_settings_tab(tab)
        self._init_avoids_tab(tab)
        self._init_finds_tab(tab)

        layout = QVBoxLayout()
        layout.addWidget(tab)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _init_simgrs_tab(self, tab):
        # simgrs list

        simgrs_label = QLabel(self)
        simgrs_label.setText('Simulation Manager')

        simgrs_list = QComboBox(self)
        self._simgrs_list = simgrs_list
        simgrs_list.currentIndexChanged.connect(self._on_simgr_selection)

        pg_layout = QHBoxLayout()
        pg_layout.addWidget(simgrs_label)
        pg_layout.addWidget(simgrs_list)

        # simulation manager information
        viewer = QSimulationManagerViewer(self.simgr)
        self._simgr_viewer = viewer
        viewer.itemClicked.connect(self._on_item_clicked)

        #
        # Max settings
        #

        lbl_max_active = QLabel()
        lbl_max_active.setText("Max active")

        max_active = QSpinBox()
        max_active.setMinimum(0)
        max_active.setMaximum(1000)
        max_active.setSpecialValueText('-')
        self._max_active = max_active

        lbl_max_steps = QLabel()
        lbl_max_steps.setText("Max steps")

        max_steps = QSpinBox()
        max_steps.setMinimum(0)
        max_steps.setMaximum(1000)
        max_steps.setSpecialValueText('-')
        self._max_steps = max_steps

        max_settings_layout = QVBoxLayout()
        layout = QHBoxLayout()
        layout.addWidget(lbl_max_active)
        layout.addWidget(max_active)
        max_settings_layout.addLayout(layout)

        layout = QHBoxLayout()
        layout.addWidget(lbl_max_steps)
        layout.addWidget(max_steps)
        max_settings_layout.addLayout(layout)

        #
        # Buttons
        #

        # step button
        self.explore_buttons = []
        step_button = QPushButton()
        step_button.setText('&Step actives')
        step_button.released.connect(self._on_step_clicked)
        self.explore_buttons.append(step_button)

        # step until branch
        step_until_branch_button = QPushButton('Step actives until &branch')
        step_until_branch_button.released.connect(self._on_step_until_branch_clicked)
        self.explore_buttons.append(step_until_branch_button)

        # explore button
        explore_button = QPushButton('&Explore')
        explore_button.released.connect(self._on_explore_clicked)
        self.explore_buttons.append(explore_button)

        # buttons layout
        buttons_layout = QVBoxLayout()
        layout = QHBoxLayout()
        layout.addWidget(explore_button)
        buttons_layout.addLayout(layout)

        layout = QHBoxLayout()
        layout.addWidget(step_button)
        layout.addWidget(step_until_branch_button)
        buttons_layout.addLayout(layout)

        simgrs_layout = QVBoxLayout()
        simgrs_layout.addLayout(pg_layout)
        simgrs_layout.addWidget(viewer)
        simgrs_layout.addLayout(max_settings_layout)
        simgrs_layout.addLayout(buttons_layout)

        frame = QFrame()
        frame.setLayout(simgrs_layout)

        tab.addTab(frame, 'General')

    def _popup_add_strategy(self):
        dialog = AddStrategy(self.simgr, self.instance)
        dialog.show()

    def _init_settings_tab(self, tab):
        oneactive_checkbox = QCheckBox("Keep at most one active path")
        oneactive_checkbox.setChecked(False)
        self._oneactive_checkbox = oneactive_checkbox

        addstrategy_button = QPushButton("Add Strategy...")
        addstrategy_button.released.connect(self._popup_add_strategy)

        settings_layout = QVBoxLayout()
        settings_layout.addWidget(oneactive_checkbox)
        settings_layout.addStretch(0)
        settings_layout.addWidget(addstrategy_button)

        frame = QFrame()
        frame.setLayout(settings_layout)

        tab.addTab(frame, 'Settings')

    def _init_avoids_tab(self, tab):
        avoids_list = QListWidget()
        self._avoids_list = avoids_list

        layout = QVBoxLayout()
        layout.addWidget(avoids_list)

        frame = QFrame()
        frame.setLayout(layout)

        tab.addTab(frame, 'Avoids')

        self._avoids_list.itemChanged.connect(self._on_explore_addr_changed)

    def _init_finds_tab(self, tab):
        finds_list = QListWidget()
        self._finds_list = finds_list

        layout = QVBoxLayout()
        layout.addWidget(finds_list)

        frame = QFrame()
        frame.setLayout(layout)

        tab.addTab(frame, 'Finds')

        self._finds_list.itemChanged.connect(self._on_explore_addr_changed)

    #
    # Event handlers
    #

    def _on_step_clicked(self):
        if self._check_for_simgr():
            self._disable_explore_buttons()
            self.instance.add_job(SimgrStepJob.create(
                self.simgr.am_obj, until_branch=False,
                pre_step_callback=self.instance.workspace.plugins.pre_step_callback,
                post_step_callback=self.instance.workspace.plugins.post_step_callback))

    def _on_step_until_branch_clicked(self):
        if self._check_for_simgr():
            self._disable_explore_buttons()
            self.instance.add_job(SimgrStepJob.create(
                self.simgr.am_obj, until_branch=True,
                pre_step_callback=self.instance.workspace.plugins.pre_step_callback,
                post_step_callback=self.instance.workspace.plugins.post_step_callback))

    def _on_explore_clicked(self):
        if self._check_for_simgr():
            self.step_count = 0

            pre_step_callback = self.instance.workspace.plugins.pre_step_callback
            plugins_post_step_callback = self.instance.workspace.plugins.post_step_callback

            def post_step_callback(simgr):
                """Called after each step during explore. Runs in the worker thread."""
                plugins_post_step_callback(simgr)
                gui_thread_schedule(lambda: self.simgr.am_event(src="post_step"))
                self.step_count += 1
                if self._oneactive_checkbox.isChecked():
                    self._filter_actives(simgr, events=False)
                return simgr

            def until_callback(simgr):
                """Stops exploration on condition. Runs in the worker thread."""
                ma = self._max_active.value()
                ms = self._max_steps.value()
                return ma != 0 and len(simgr.active) >= ma or \
                    ms != 0 and self.step_count >= ms

            self._disable_explore_buttons()
            self.instance.add_job(
                SimgrExploreJob.create(self.simgr, avoid=self.avoid_addrs, find=self.find_addrs,
                                       pre_step_callback=pre_step_callback, post_step_callback=post_step_callback,
                                       until_callback=until_callback))

    def _on_simgr_selection(self):
        i = self._simgrs_list.currentIndex()
        if i != -1:
            simgr = self.simgrs[i]
        else:
            simgr = None

        if simgr != self.simgr.am_obj:
            self.simgr.am_obj = simgr
            self.simgr.am_event(src='clicked')

        if not self.simgr.am_none():
            # TODO: need better place to add explore strategy
            self.simgr.use_technique(
                angr.exploration_techniques.strategy_switcher.StrategySwitcher(self.instance.project, self.simgr))
            console = self.instance.workspace.view_manager.first_view_in_category('console')
            console.push_namespace({
                "sm": self.simgr.am_obj,
                "simgr": self.simgr.am_obj
            })
            console.print_text(f"\nsm = simgr = {self.simgr.am_obj}\n")

    def _on_item_clicked(self, item, column):
        """Callback for when an item is clicked in the list of states/stashes"""
        if isinstance(item, StateTreeItem) and item.state != self.state:
            self.state.am_obj = item.state
            self.state.am_event(src='clicked')
            console = self.instance.workspace.view_manager.first_view_in_category('console')
            console.push_namespace({
                'state': item.state, 's': item.state
            })
            console.print_text(f"\nstate = s = {item.state}\n")
        elif isinstance(item, StashTreeItem):
            console = self.instance.workspace.view_manager.first_view_in_category('console')
            console.push_namespace({
                'states': item.states,
            })
            console.print_text(f"\nstates = simgr.{item.stash_name}\n")

    def _watch_simgr(self, **kwargs):
        if kwargs.get("src") == "job_done" and kwargs.get("job") in ("step", "explore"):
            # Re-enable the simgr buttons once the exploring/stepping job finishes
            self._enable_explore_buttons()
        if kwargs.get('src') in ('clicked', 'filter_actives'):
            return
        elif kwargs.get('src') == 'job_done' and kwargs.get('job') == 'step':
            self._filter_actives(self.simgr)
        else:
            idx = self._simgrs_list.findText(self.simgr.am_obj.am_name)
            self._simgrs_list.setCurrentIndex(idx)

    def _watch_state(self, **kwargs):
        if kwargs.get('src') == 'clicked':
            return

        self._simgr_viewer.select_state(self.state.am_obj)

    def _watch_simgrs(self, **kwargs):
        self.refresh()

    def _on_explore_addr_changed(self, item: QListWidgetItem):
        """Refresh the disassembly view when an address in the 'avoids' or 'finds' tab is toggled. Ensures that
        annotations next to instructions are updated."""
        self.instance.workspace.view_manager.first_view_in_category("disassembly").refresh()

    #
    # Private methods
    #

    def _filter_actives(self, simgr, events=True):
        if not self._oneactive_checkbox.isChecked():
            return False
        if len(simgr.active) < 2:
            return False

        stashed = simgr.active[1:]
        simgr.stashes['stashed'].extend(stashed)
        simgr.stashes['active'] = simgr.active[:1]
        if events:
           simgr.am_event(src='filter_actives', filtered=stashed)
        return True

    def _check_for_simgr(self):
        if self.simgr.am_none():
            QMessageBox.critical(GlobalInfo.main_window, "No simulation manager",
                                 "Must first create a simulation manager or select an existing one from the "
                                 "symexec view.")
            return False
        return True

    def _disable_explore_buttons(self):
        for button in self.explore_buttons:
            button.setDisabled(True)

    def _enable_explore_buttons(self):
        for button in self.explore_buttons:
            button.setEnabled(True)

    def _get_checked_items(self, qlist: QListWidget):
        items = []
        for i in range(qlist.count()):
            item = qlist.item(i)
            if item.checkState() == Qt.Checked:
                items.append(item)
        return items

    def _remove_addr(self, qlist: QListWidget, addr):
        for i in range(qlist.count()):
            qitem = qlist.item(i)
            if int(qitem.text(), 16) == addr:
                qlist.takeItem(i)
                return