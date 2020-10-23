from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, \
    QGridLayout, QComboBox, QRadioButton, QGroupBox, QScrollArea, QWidget, \
    QLineEdit, QTextEdit, QTreeWidget, QTreeWidgetItem, QPlainTextEdit, QMessageBox
from PySide2.QtCore import Qt
from PySide2.QtGui import QTextOption

from ..widgets import QAddressInput, QStateComboBox
from .py_highlight import PythonHighlighter

import angr
from angr.exploration_techniques import *
import inspect

from IPython import embed

class AddStrategy(QDialog):

    # TODO: hardcoding this because veritesting ignores termination otherwise
    VERITESTING_CONSTRUCTOR = "(boundaries=None, loop_unrolling_limit=10, enable_function_inlining=False, terminator=lambda sm: any(s.addr == 0x0 for s in sm.active), deviation_filter=None)\n# set find address for terminator above and for the simgr."
    def __init__(self, simgr, instance):
        super(AddStrategy, self).__init__()

        # initialization

        self.simgr = simgr
        self.instance = instance
        self.strategies = {}
        if self.simgr.am_none():
            QMessageBox.about(self, 'Error', f"No simulation manager selected.")
            return
        self._ok_button = None
        self._constructor_box = None
        self.main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self.main_layout)

    #
    # Private methods
    #
    #

    def update_constructor(self, strategy):
        params = str(inspect.signature(self.strategies[strategy]))
        # veritesting uses dynamic args so hardcoding its constructor
        if strategy == "Veritesting":
            params = self.VERITESTING_CONSTRUCTOR
        params = params.replace(",", ",\n")
        self._constructor_box.setPlainText(strategy + params)

    def selected(self):
        btn = self.sender()
        if btn.isChecked():
            self.update_constructor(btn.strategy)


    def _init_widgets(self):
        layout = QGridLayout()
        row = 0

        header_label = QLabel(self)
        header_label.setText("Exploration strategy:")

        layout.addWidget(header_label, row, 0)
        row += 1

        options_container = QGroupBox(self)
        options = QVBoxLayout()

        for strategy, cls in sorted(angr.exploration_techniques.__dict__.items()):
            if hasattr(cls, "mro") and angr.exploration_techniques.ExplorationTechnique in type.mro(cls):

                child = QRadioButton()
                child.setText(strategy)
                child.strategy = strategy
                child.toggled.connect(self.selected)
                options.addWidget(child)
                self.strategies[strategy] = cls

        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        widget = QWidget()
        scroll_area.setWidget(widget)
        layout_scroll = QVBoxLayout(widget)
        layout_scroll.addWidget(options_container)
        options_container.setLayout(options)
        layout.addWidget(scroll_area, row, 0)
        row += 1


        constructor_box = QPlainTextEdit(self)

        highlight = PythonHighlighter(constructor_box.document())
        constructor_box.setWordWrapMode(QTextOption.WordWrap)
        self._constructor_box = constructor_box

        layout.addWidget(constructor_box, row, 0)
        row += 1

        # buttons

        ok_button = QPushButton(self)
        ok_button.setText('OK')
        def do_ok():
            constructor_txt = constructor_box.toPlainText()
            try:
                strategy = eval(constructor_txt)
                strategy.project = self.instance.project
                self.simgr.strategies[strategy.__class__.__name__] = strategy
                self.close()
            except NameError as e:
                # error
                QMessageBox.about(self, 'Error', f"{str(e)}, \nMake sure to fill in all positional arguments.")

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


class ShowStrategy(QDialog):
    def __init__(self, instance, addr=None):
        super(ShowStrategy, self).__init__()

        # initialization

        self.instance = instance
        self.workspace = instance.workspace
        self.symexec_view = self.workspace.view_manager.first_view_in_category("symexec")
        self.simgr = self.symexec_view.current_simgr

        if self.simgr.am_none():
            QMessageBox.about(self, 'Error', f"No simulation manager selected.")
            return

        self.strategies = self.simgr.strategies

        self.state = None  # output

        self._addr = addr

        self._selected = None

        self._ok_button = None

        self.setWindowTitle('Change function exploration strategy')

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def selected(self):
        btn = self.sender()
        if btn.isChecked():
            self._selected = btn.strategy

    def _init_widgets(self):
        if len(self.strategies) == 0:

            QMessageBox.about(self, 'Error', "No strategies available\nCreate a strategy in Symbolic Execution -> Settings -> Add Strategy")
            return


        layout = QGridLayout()
        row = 0

        addr = self.instance.project.entry if self._addr is None else self._addr
        function = self.instance.project.kb.functions.floor_func(addr)
        fn_name = function.name
        fn_addr = function.addr

        header_label = QLabel(self)
        header_label.setText(f"Exploration strategy for function {fn_name} @ address {hex(fn_addr)}:")

        layout.addWidget(header_label, row, 0)
        row += 1

        options_container = QGroupBox(self)
        options = QVBoxLayout()

        for strategy, cls in self.strategies.items():
            child = QRadioButton()
            child.setText(strategy)
            child.strategy = strategy
            child.toggled.connect(self.selected)
            options.addWidget(child)



        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        widget = QWidget()
        scroll_area.setWidget(widget)
        layout_scroll = QVBoxLayout(widget)
        layout_scroll.addWidget(options_container)
        options_container.setLayout(options)
        layout.addWidget(scroll_area, row, 0)
        row += 1

        # buttons

        ok_button = QPushButton(self)
        ok_button.setText('OK')
        def do_ok(): # TODO: parse call insn for this function and set end of explore at that addr
            if self._selected is not None:
                self.simgr.fn_strategy[fn_addr] = self._selected # TODO: select from options
                self.close()

        ok_button.clicked.connect(do_ok)

        # TODO: add validation for OK button enable/disable
        def validation_update():
            ok_button.setDisabled(bool(validation_failures))

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
