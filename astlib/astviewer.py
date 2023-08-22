import graphviz
from graphviz import Graph
import html
from pathlib import Path
from typing import Callable, Any

from .astvisitor import VisitAllChildrenByDefaultVisitor, ASTNode

_NODE_FMT = '''<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
<TR><TD><b>{:}</b></TD></TR>
<TR><TD>{:}</TD></TR>
</TABLE>>'''

class NodeAttrs:
    '''Struct to hold AST node attributes for graphviz rendering'''

    RED_COLOR = '#dd0000ff'
    GREEN_COLOR = '#00aa00ff'
    BLUE_COLOR = '#0000eecc'
    BLACK_COLOR = '#000000ff'

    def __init__(self, node_string:str, node_color:str='black',
                font_color:str='black') -> None:
        self.node_string = node_string
        self.node_color = node_color
        self.font_color = font_color

class ASTViewer(VisitAllChildrenByDefaultVisitor):
    def __init__(self, format_node:Callable[[ASTNode,NodeAttrs],Any]=None) -> None:
        super().__init__()
        self.g:Graph = None
        self.id_ctr = 0
        self._format_node = format_node

    def render_ast(self, node:ASTNode, format:str, outfolder:Path, ast_name:str='',
                   fontname:str='Cascadia Code'):
        if not ast_name:
            ast_name = f'{node.kind}_AST'
        self.id_ctr = 0     # reset

        self.g = Graph(ast_name, format=format)
        self.g.attr('graph', rankdir='BT')
        self.g.attr('node', shape='plaintext')
        self.g.attr('node', fontname=fontname)

        self.assign_ids(node)
        self.visit(node)

        self.g.render(directory=outfolder, view=False)
        return self.g

    def assign_ids(self, node:ASTNode):
        node._graph_id = str(self.id_ctr)
        self.id_ctr += 1
        for x in node.inner:
            self.assign_ids(x)

    def visit(self, node:ASTNode, parent:ASTNode=None):
        visit_method = getattr(self, node.visitor_method_name, None)
        node_attrs = visit_method(node) if visit_method else NodeAttrs(f'TODO: {node.kind}')
        if self._format_node:
            # give the callback a chance to modify the formatting
            self._format_node(node, node_attrs)
        self.create_graph_node(node, parent, node_attrs)
        for child in node.inner:
            self.visit(child, node)

    def create_graph_node(self, node:ASTNode, parent:ASTNode, attrs:NodeAttrs):
        label = _NODE_FMT.format(node.kind, html.escape(attrs.node_string))
        self.g.node(node._graph_id, label=label, color=attrs.node_color, fontcolor=attrs.font_color)
        if parent and '_graph_id' in parent.__dict__:
            self.g.edge(node._graph_id, parent._graph_id)

    def visit_BinaryOperator(self, node):
        return NodeAttrs(f'{node.opcode}')

    def visit_BuiltinType(self, bit:ASTNode):
        return NodeAttrs(bit.name)

    def visit_CallExpr(self, node):
        return NodeAttrs(f'caller @ 0x{node.instr_addr:x}')

    def visit_CompoundStmt(self, node):
        return NodeAttrs('')

    def visit_CStyleCastExpr(self, node):
        return NodeAttrs(node.dtype.dtype_str())

    def visit_DeclRefExpr(self, node):
        return NodeAttrs(f'{node.referencedDecl.name}')

    def visit_DeclStmt(self, stmt:ASTNode):
        return NodeAttrs('')

    def visit_ForStmt(self, fstmt):
        # return NodeAttrs(f'@ 0x{fstmt.instr_addr:x}')
        return NodeAttrs('')

    def visit_FunctionDecl(self, fdecl:ASTNode):
        return NodeAttrs(f'{fdecl.return_dtype.dtype_str()} {fdecl.name}')

    def visit_IfStmt(self, node):
        return NodeAttrs('')

    def visit_IntegerLiteral(self, node):
        return NodeAttrs(f'0x{node.value:x} @ 0x{node.instr_addr:x}')

    def visit_MemberExpr(self, memexpr):
        return NodeAttrs(f'0x{memexpr.offset:x}:{memexpr.name} @ 0x{memexpr.instr_addr:x}')

    def visit_ParenExpr(self, parenexpr):
        return NodeAttrs('')

    def visit_ParmVarDecl(self, pvdecl):
        return NodeAttrs(f'{pvdecl.dtype.dtype_str()} {pvdecl.name}')

    def visit_ReturnStmt(self, rs):
        return NodeAttrs('')

    def visit_TranslationUnitDecl(self, tudecl):
        return NodeAttrs('')

    def visit_TypedefDecl(self, tddecl):
        return NodeAttrs(f'{tddecl.name}')

    def visit_UnaryOperator(self, node):
        return NodeAttrs(f'{node.opcode}')

    def visit_VarDecl(self, vdecl):
        return NodeAttrs(f'{vdecl.dtype.dtype_str()} {vdecl.name}')