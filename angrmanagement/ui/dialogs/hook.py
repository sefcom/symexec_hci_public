from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, \
    QGridLayout, QComboBox, QRadioButton, QGroupBox, QScrollArea, QWidget, \
    QLineEdit, QTextEdit, QTreeWidget, QTreeWidgetItem, QPlainTextEdit
from PySide2.QtCore import Qt
from PySide2.QtGui import QSyntaxHighlighter, QTextOption

from ..widgets import QAddressInput, QStateComboBox
from .py_highlight import PythonHighlighter


class ShowHook(QDialog):

    def __init__(self, instance, addr=None, create_simgr=True, parent=None):
        super(ShowHook, self).__init__(parent)

        # initialization

        self.instance = instance

        if "hooks" not in dir(self.instance.project):
            self.instance.project.hooks = {}

        self.hooks = self.instance.project.hooks

        self.state = None  # output

        self._addr = addr

        self.templates = {}

        self._add_templates(hex(addr))

        self._function_box = None
        self._ok_button = None

        self.setWindowTitle('Change hook')

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _add_templates(self, addr):
        self.templates['base'] = f"""
@p.hook(addr={addr}, length=0)
def hook(state):
    ...
    """

        self.templates['assertion'] = f"""
@p.hook(addr={addr}, length=0)
def assertion(state):
    state.add_constraints(
        ...
    )"""

        self.templates['disable unicorn'] = f"""
@p.hook(addr={addr}, length=0)
def disable_unicorn(state):
    state.options.discard("UNICORN")
    state.options.discard("UNICORN_HANDLE_TRANSMIT_SYSCALL")
    state.options.discard("UNICORN_SYM_REGS_SUPPORT")
    state.options.discard("UNICORN_TRACK_BBL_ADDRS")
    state.options.discard("UNICORN_TRACK_STACK_POINTERS")
    """

        self.templates['enable unicorn'] = f"""
@p.hook(addr={addr}, length=0)
def enable_unicorn(state):
    state.options.add("UNICORN")
    state.options.add("UNICORN_HANDLE_TRANSMIT_SYSCALL")
    state.options.add("UNICORN_SYM_REGS_SUPPORT")
    state.options.add("UNICORN_TRACK_BBL_ADDRS")
    state.options.add("UNICORN_TRACK_STACK_POINTERS")
    """

    def update_function(self, template):
        self._function_box.setPlainText(template)

    def selected(self):
        btn = self.sender()
        if btn.isChecked():
            self.update_function(btn.template)

    def _init_widgets(self):

        layout = QGridLayout()

        row = 0

        # validation_failures = set()

        addr = hex(self._addr)

        address_label = QLabel(self)
        address_label.setText(f"Hook at address {addr}:")

        layout.addWidget(address_label, row, 0)
        row += 1

        options_container = QGroupBox(self)
        options = QVBoxLayout()



        for name, template in sorted(self.templates.items()):
                child = QRadioButton()
                child.setText(name)
                child.template = template
                child.toggled.connect(self.selected)
                options.addWidget(child)

        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        widget = QWidget()
        scroll_area.setWidget(widget)
        layout_scroll = QVBoxLayout(widget)

        header_label = QLabel(self)
        header_label.setText("Presets:")

        layout_scroll.addWidget(header_label)
        layout_scroll.addWidget(options_container)
        options_container.setLayout(options)
        layout.addWidget(scroll_area, row, 0)
        row += 1


        function_box = QPlainTextEdit(self)

        if addr in self.hooks.keys():
            function_box.insertPlainText(self.hooks[addr])

        highlight = PythonHighlighter(function_box.document())
        function_box.setWordWrapMode(QTextOption.WordWrap)
        self._function_box = function_box

        layout.addWidget(function_box, row, 0)
        row += 1

        # def add_indent():
        #     txt = function_box.toPlainText()
        #     if txt.endswith('\n'):
        #         embed()
        #         indent = txt.search()
        #     if txt.endswith(':\n'):
        #         function_box.insertPlainText('    ')

        # function_box.textChanged.connect(add_indent)
        # TODO: add python autoindent

        # buttons

        ok_button = QPushButton(self)
        ok_button.setText('OK')

        def do_ok():
            hook_code_string = function_box.toPlainText()
            self.instance.apply_hook(self._addr, hook_code_string)
            self.hooks[hex(self._addr)] = hook_code_string
            disasm_view = self.instance.workspace.view_manager.first_view_in_category("disassembly")
            # So the hook icon shows up in the disasm view
            disasm_view.refresh()
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
