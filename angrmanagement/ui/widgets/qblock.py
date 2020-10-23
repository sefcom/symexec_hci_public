import logging

from PySide2.QtGui import QColor, QPen, QPainterPath, QBrush, QFont, QCursor
from PySide2.QtCore import QRectF, QMarginsF
from PySide2.QtWidgets import QHBoxLayout, QLabel, QWidget, QGraphicsProxyWidget, QGraphicsItem, QGraphicsWidget, \
    QGraphicsSimpleTextItem, QGraphicsItemGroup, QGraphicsLinearLayout, QGraphicsSceneMouseEvent, QMenu

from angr.analyses.disassembly import Instruction
from angr.sim_variable import SimRegisterVariable
from .qsimulation_managers import QSimulationManagers
from ...logic import GlobalInfo

from ...utils import get_block_objects, get_out_branches_for_insn
from ...utils.block_objects import FunctionHeader, Variables, PhiVariable, Label
from ...config import Conf
from .qinstruction import QInstruction
from .qfunction_header import QFunctionHeader
from .qblock_label import QBlockLabel
from .qphivariable import QPhiVariable
from .qvariable import QVariable
from .qgraph_object import QCachedGraphicsItem

_l = logging.getLogger(__name__)


class QInstructionAnnotation(QGraphicsSimpleTextItem):
    """Abstract"""

    background_color = None
    foreground_color = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setBrush(QBrush(QColor(*self.foreground_color)))

    def paint(self, painter, *args, **kwargs):
        margin = QMarginsF(3, 0, 3, 0)
        box = self.boundingRect().marginsAdded(margin)
        path = QPainterPath()
        path.addRoundedRect(box, 5, 5)
        painter.fillPath(path, QColor(*self.background_color))
        super().paint(painter, *args, **kwargs)


class QStatsAnnotation(QInstructionAnnotation):
    """Abstract"""
    # TODO: hci: feature #1: When hold shift, can select multiple bubbles. When no hold shift, *replace* the current
    #  selection with new selection

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setAcceptHoverEvents(True)
        self.disasm_view = GlobalInfo.main_window.workspace.view_manager.first_view_in_category("disassembly")
        self.symexec_view = GlobalInfo.main_window.workspace.view_manager.first_view_in_category("symexec")
        self.hovered = False

    def mousePressEvent(self, event):
        raise NotImplementedError

    def hoverEnterEvent(self, event):
        self.hovered = True
        self.disasm_view.redraw_current_graph()

    def hoverLeaveEvent(self, event):
        self.hovered = False
        self.disasm_view.redraw_current_graph()

    def paint(self, painter, *args, **kwargs):
        if self.hovered:
            margin = QMarginsF(13, 10, 13, 10)
        else:
            margin = QMarginsF(3, 0, 3, 0)
        box = self.boundingRect().marginsAdded(margin)
        path = QPainterPath()
        if self.hovered:
            path.addRoundedRect(box, 20, 20)
        else:
            path.addRoundedRect(box, 5, 5)
        painter.fillPath(path, QColor(*self.background_color))
        super().paint(painter, *args, **kwargs)


class QActiveCount(QStatsAnnotation):

    background_color = (0, 255, 0, 30)
    foreground_color = (0, 60, 0)

    def __init__(self, states):
        super().__init__(str(len(states)))
        self.states = states

    def mousePressEvent(self, event):
        self.symexec_view.select_states(self.states)
        self.disasm_view.workspace.raise_view(self.symexec_view)


class QPassthroughCount(QStatsAnnotation):

    background_color = (255, 0, 0, 30)
    foreground_color = (60, 0, 0)

    def __init__(self, addr, count):
        super().__init__(str(count))
        self.addr = addr

    def mousePressEvent(self, event):
        self.symexec_view.select_states_that_passed_through(self.addr)
        self.disasm_view.workspace.raise_view(self.symexec_view)


class QHookAnnotation(QInstructionAnnotation):

    background_color = (230, 230, 230)
    foreground_color = (50, 50, 50)

    def __init__(self, disasm_view, addr, *args, **kwargs):
        super().__init__("hook", *args, **kwargs)
        self.disasm_view = disasm_view
        self.addr = addr

    def contextMenuEvent(self, event):
        menu = QMenu()
        menu.addAction("Modify", self.modify)
        menu.addAction("Delete", self.delete)
        menu.exec_(QCursor.pos())

    def modify(self):
        self.disasm_view.popup_modify_hook_dialog(addr=self.addr)

    def delete(self):
        GlobalInfo.main_window.workspace.instance.delete_hook(self.addr)
        self.disasm_view.refresh()


class QExploreAnnotation(QInstructionAnnotation):
    """Abstract"""

    background_color = None
    foreground_color = (230, 230, 230)
    text = None

    def __init__(self, disasm_view, qsimgrs: QSimulationManagers, addr, *args, **kwargs):
        super().__init__(self.text, *args, **kwargs)
        self.disasm_view = disasm_view
        self.qsimgrs = qsimgrs
        self.addr = addr

    def contextMenuEvent(self, event):
        menu = QMenu()
        menu.addAction("Delete", self.delete)
        menu.exec_(QCursor.pos())

    def delete(self):
        raise NotImplementedError


class QFindAddrAnnotation(QExploreAnnotation):

    background_color = (200, 230, 100)
    foreground_color = (30, 80, 30)
    text = "find"

    def delete(self):
        self.qsimgrs.remove_find_address(self.addr)
        self.disasm_view.refresh()


class QAvoidAddrAnnotation(QExploreAnnotation):

    background_color = (230, 200, 100)
    foreground_color = (80, 30, 30)
    text = "avoid"

    def delete(self):
        self.qsimgrs.remove_avoid_address(self.addr)
        self.disasm_view.refresh()


class QBlockAnnotations(QGraphicsItem):
    """Container for all instruction annotations in a QBlock"""

    PADDING = 10

    def __init__(self, addr_to_annotations: dict, *, parent):
        super().__init__(parent=parent)
        self.addr_to_annotations = addr_to_annotations
        max_width = 0
        for addr, annotations in self.addr_to_annotations.items():
            width = sum(a.boundingRect().width() + self.PADDING for a in annotations)
            max_width = max(max_width, width)
            for annotation in annotations:
                annotation.setParentItem(self)
        self.width = max_width
        self._init_widgets()

    def get(self, addr):
        return self.addr_to_annotations.get(addr)

    def width(self):
        return self.boundingRect().width()

    def paint(self, painter, *args, **kwargs):
        pass

    def boundingRect(self):
        return self.childrenBoundingRect()

    def _init_widgets(self):
        # Set the x positions of all the annotations. The y positions will be set later while laying out the
        # instructions
        for addr, annotations in self.addr_to_annotations.items():
            x = self.width
            for annotation in annotations:
                annotation.setX(x - annotation.boundingRect().width())
                x -= annotation.boundingRect().width() + self.PADDING


class QBlock(QCachedGraphicsItem):
    TOP_PADDING = 5
    BOTTOM_PADDING = 5
    LEFT_PADDING = 10
    RIGHT_PADDING = 10
    SPACING = 0

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, addr, cfg_nodes, out_branches, scene,
                 parent=None, container=None):
        super().__init__(parent=parent, container=container)
        # initialization
        self.workspace = workspace
        self.func_addr = func_addr
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.infodock = infodock
        self.variable_manager = infodock.variable_manager
        self.addr = addr
        self.cfg_nodes = cfg_nodes
        self.out_branches = out_branches
        self._scene = scene
        self.margins = QMarginsF(self.LEFT_PADDING, self.TOP_PADDING, self.RIGHT_PADDING, self.BOTTOM_PADDING)

        self._config = Conf

        self.objects = [ ]  # instructions and labels
        self._block_item = None  # type: QPainterPath
        self._block_item_obj = None  # type: QGraphicsPathItem
        self.qblock_annotations = None
        self.addr_to_insns = { }
        self.addr_to_labels = { }

        self._init_widgets()

        self._objects_are_hidden = False

        self._create_block_item()

        self.setAcceptHoverEvents(True)

    #
    # Properties
    #

    @property
    def mode(self):
        raise NotImplementedError

    @property
    def width(self):
        return self.boundingRect().width()

    @property
    def height(self):
        return self.boundingRect().height()

    #
    # Public methods
    #

    def clear_cache(self):
        super().clear_cache()
        for obj in self.objects:
            obj.clear_cache()

    def refresh(self):
        for obj in self.objects:
            obj.refresh()
        self.layout_widgets()
        self.recalculate_size()
        self._create_block_item()
        self.update()

    def reload(self):
        self._init_widgets()
        self.refresh()

    def size(self):
        return self.width, self.height

    def instruction_position(self, insn_addr):
        if insn_addr in self.addr_to_insns:
            insn = self.addr_to_insns[insn_addr]
            pos = insn.pos()
            return pos.x(), pos.y()

        return None

    #
    # Initialization
    #

    def _create_block_item(self):
        """
        Create the block background and border.
        """
        if self._block_item_obj is not None and self._scene is not None:
            self._scene.removeItem(self._block_item_obj)
            self._block_item = None
            self._block_item_obj = None

        self._block_item = QPainterPath()
        self._block_item.addRect(self.block_object_group.childrenBoundingRect().marginsAdded(self.margins))

    def _init_widgets(self):

        # TODO: hci: refactor: no need for self.objects anymore b/c of self.block_object_group. Using a
        #  QGraphicsItemGroup is a more natural way to group/work with multiple GraphicItems

        if self._scene is not None:
            for obj in self.objects:
                self._scene.removeItem(obj)

        self.objects.clear()
        block_objects = get_block_objects(self.disasm, self.cfg_nodes, self.func_addr)
        self.block_object_group = QGraphicsItemGroup(parent=self)
        self.block_object_group.setHandlesChildEvents(False)

        for obj in block_objects:
            if isinstance(obj, Instruction):
                out_branch = get_out_branches_for_insn(self.out_branches, obj.addr)
                insn = QInstruction(self.workspace, self.func_addr, self.disasm_view, self.disasm,
                                    self.infodock, obj, out_branch, self._config, parent=self,
                                    container=self._container)
                self.objects.append(insn)
                self.block_object_group.addToGroup(insn)
                self.addr_to_insns[obj.addr] = insn
            elif isinstance(obj, Label):
                # label
                label = QBlockLabel(obj.addr, obj.text, self._config, self.disasm_view, self.workspace, self.infodock,
                                    parent=self, container=self._container)
                self.objects.append(label)
                self.block_object_group.addToGroup(label)
                self.addr_to_labels[obj.addr] = label
            elif isinstance(obj, PhiVariable):
                if not isinstance(obj.variable, SimRegisterVariable):
                    phivariable = QPhiVariable(self.workspace, self.disasm_view, obj, self._config, parent=self,
                                               container=self._container)
                    self.objects.append(phivariable)
                    self.block_object_group.addToGroup(phivariable)
            elif isinstance(obj, Variables):
                for var in obj.variables:
                    variable = QVariable(self.workspace, self.disasm_view, var, self._config, parent=self,
                                         container=self._container)
                    self.objects.append(variable)
                    self.block_object_group.addToGroup(variable)
            elif isinstance(obj, FunctionHeader):
                header = QFunctionHeader(self.func_addr, obj.name, obj.prototype, obj.args, self._config,
                                         self.disasm_view, self.workspace, self.infodock, parent=self,
                                         container=self._container)
                self.objects.append(header)
                self.block_object_group.addToGroup(header)
        self.layout_widgets()

    def layout_widgets(self):
        raise NotImplementedError()


class QGraphBlock(QBlock):
    MINIMUM_DETAIL_LEVEL = 0.4

    @property
    def mode(self):
        return 'graph'

    def layout_widgets(self):
        x, y = self.LEFT_PADDING * self.currentDevicePixelRatioF(), self.TOP_PADDING * self.currentDevicePixelRatioF()

        if self.qblock_annotations and self.qblock_annotations.scene():
            self.qblock_annotations.scene().removeItem(self.qblock_annotations)

        self.qblock_annotations = self.disasm_view.fetch_qblock_annotations(self)

        for obj in self.objects:
            obj.setPos(x + self.qblock_annotations.width + self.LEFT_PADDING, y)
            if isinstance(obj, QInstruction) and self.qblock_annotations.get(obj.addr):
                qinsn_annotations = self.qblock_annotations.get(obj.addr)
                for qinsn_annotation in qinsn_annotations:
                    qinsn_annotation.setY(obj.y())
            y += obj.boundingRect().height()

    def hoverEnterEvent(self, event):
        self.infodock.hover_block(self.addr)
        event.accept()

    def hoverLeaveEvent(self, event):
        self.infodock.unhover_block(self.addr)
        event.accept()

    def mousePressEvent(self, event):
        if self.workspace.plugins.handle_click_block(self, event):
            # stop handling this event if the event has been handled by a plugin
            event.accept()
            return

        # the block is selected
        self.on_selected()

        super().mousePressEvent(event)

    def _calc_backcolor(self, should_omit_text):
        color = self.workspace.plugins.color_block(self.addr)
        if color is not None:
            return color

        if should_omit_text:
            return QColor(0xda, 0xda, 0xda)

        return self._config.disasm_view_node_background_color

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        should_omit_text = lod < QGraphBlock.MINIMUM_DETAIL_LEVEL

        # background of the node
        painter.setBrush(self._calc_backcolor(should_omit_text))
        if self.infodock.is_block_selected(self.addr):
            painter.setPen(QPen(self._config.disasm_view_selected_node_border_color, 2.5))
        else:
            painter.setPen(QPen(self._config.disasm_view_node_border_color, 1.5))
        self._block_item_obj = painter.drawPath(self._block_item)

        # content drawing is handled by qt since children are actual child widgets

        # if we are too far zoomed out, do not draw the text
        if self._objects_are_hidden != should_omit_text:
            for obj in self.objects:
                obj.setVisible(not should_omit_text)
                obj.setEnabled(not should_omit_text)
            self._objects_are_hidden = should_omit_text

        # extra content
        self.workspace.plugins.draw_block(self, painter)

    def on_selected(self):
        self.infodock.select_block(self.addr)

    def _boundingRect(self):
        bounding_rect = self.childrenBoundingRect().marginsAdded(self.margins)
        if self.qblock_annotations:
            # Hack to keep the arrows centered on the graph blocks.
            hack_right_margin = QMarginsF(0, 0, self.qblock_annotations.width, 0)
            return bounding_rect.marginsAdded(hack_right_margin)
        return bounding_rect


class QLinearBlock(QBlock):
    # TODO: hci: fix: Make the execution statistics work for the linear view as well
    ADDRESS_PADDING = 10

    @property
    def mode(self):
        return 'linear'

    def format_address(self, addr):
        return '{:08x}'.format(addr)

    def layout_widgets(self):
        y_offset = 0

        max_width = 0

        for obj in self.objects:
            y_offset += self.SPACING * self.currentDevicePixelRatioF()
            obj_start = 0
            obj.setPos(obj_start, y_offset)
            if obj_start + obj.width > max_width:
                max_width = obj_start + obj.boundingRect().width()
            y_offset += obj.boundingRect().height()

        self._height = y_offset
        self._width = max_width

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument
        painter.setFont(self._config.disasm_font)

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
