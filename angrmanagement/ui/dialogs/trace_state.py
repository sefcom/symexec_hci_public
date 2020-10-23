from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, \
    QGridLayout, QComboBox, QPlainTextEdit, \
    QLineEdit, QTextEdit, QTreeWidget, QTreeWidgetItem, QMessageBox
from PySide2.QtCore import Qt
from PySide2.QtGui import QTextOption, QIntValidator
from traceback import print_exc
import angr
import claripy
import shlex

from ..widgets import QAddressInput, QStateComboBox

class TraceState(QDialog):
    def __init__(self, instance, base_state_combo, address_box, parent=None):
        super(TraceState, self).__init__(parent)

        # initialization

        self.instance = instance

        self._base_state_combo = base_state_combo  # type: QStateComboBox
        self._address_box = address_box # type: QLineEdit
        self._init_widgets()


    #
    # Private methods
    #

    def _init_widgets(self):
        try:
            from tracer import QEMURunner
        except:
            QMessageBox.about(self, 'Error', f"Unable to import QEMURunner, install angr tracer")
            self.close()

        self.setWindowTitle('New trace state')
        container = QVBoxLayout()
        layout = QGridLayout()
        row = 0

        args_label = QLabel(self)
        args_label.setText("Command-line arguments:")
        layout.addWidget(args_label, row, 0)
        row += 1

        args = QLineEdit(self)
        bin_name = str(self.instance.project).split(" ")[1][:-1]
        args.setText(bin_name)
        layout.addWidget(args, row, 0)
        row += 1

        input_label = QLabel(self)
        input_label.setText("Input:")
        layout.addWidget(input_label, row, 0)
        row += 1

        input_box = QPlainTextEdit()
        input_box.setWordWrapMode(QTextOption.WordWrap)
        layout.addWidget(input_box, row, 0)
        row += 1

        addr_label = QLabel(self)
        addr_label.setText("Stop address:")
        layout.addWidget(addr_label, row, 0)
        row += 1

        addr_box = QLineEdit(self)
        layout.addWidget(addr_box, row, 0)
        row += 1

        def parse_address():
            txt = addr_box.text()
            try:
                return self.instance.project.kb.labels.lookup(txt)
            except KeyError:
                pass

            try:
                return int(txt, 16)
            except ValueError:
                return None

        ok_button = QPushButton(self)
        ok_button.setText('OK')
        def do_ok():
            argv = shlex.split(args.text())
            inp = bytes(input_box.toPlainText().encode('latin-1'))
            addr = parse_address()

            try:
                p = self.instance.project
                r = QEMURunner(binary=bin_name,
                               argv=argv,
                               input=inp,
                               project=p)

                s = p.factory.entry_state(
                        mode='tracing',
                        stdin=angr.SimFileStream)
                s.preconstrainer.preconstrain_file(inp, s.posix.stdin, True)

                sm = p.factory.simgr(
                    s,
                    save_unsat=True,
                    hierarchy=False,
                    save_unconstrained=r.crash_mode)

                t = sm.use_technique(
                    angr.exploration_techniques.Tracer(
                        trace=r.trace,
                        resiliency=True,
                        keep_predecessors=1,
                        crash_addr=r.crash_addr))
                sm.use_technique(angr.exploration_techniques.Oppologist())
                sm.explore(find=addr)

                # add state to global state store
                state = sm.traced[0] if len(sm.traced) > 0 else sm.found[0]
                name = f"{hex(state.addr)} trace"
                state.gui_data.base_name = name
                state.gui_data.is_base = True
                state.gui_data.name = name
                state.gui_data.is_original = True
                self.instance.states.append(state)
                self._base_state_combo.refresh()
                for i in range(self._base_state_combo.count()):
                    if self._base_state_combo.itemText(i) == name:
                        self._base_state_combo.setCurrentIndex(i)
                self._address_box.setText(hex(state.addr))

                self.close()
            except Exception as e:
                QMessageBox.about(self, 'Error', f"{repr(e)}")

        ok_button.clicked.connect(do_ok)

        cancel_button = QPushButton(self)
        cancel_button.setText('Cancel')
        def do_cancel():
            self.close()
        cancel_button.clicked.connect(do_cancel)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        container.addLayout(layout)
        container.addLayout(buttons_layout)

        self.setLayout(container)
        self.exec_()
