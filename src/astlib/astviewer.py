import graphviz
from graphviz import Graph
import html
from pathlib import Path
from typing import Callable, Any

from astlib.ast import ASTNode, Any, Callable

from .astvisitor import VisitAllChildrenByDefaultVisitor
from .ast import *

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
    def __init__(self, format_node:Callable[['ASTNode',NodeAttrs],Any]=None) -> None:
        super().__init__()
        self.g:Graph = None
        self.id_ctr = 0
        self._format_node = format_node

    def render_ast(self, node:'ASTNode', format:str, outfolder:Path=None, ast_name:str='',
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

        if outfolder is not None:
            self.g.render(directory=outfolder, view=False)

        return self.g

    def assign_ids(self, node:'ASTNode'):
        node._graph_id = str(self.id_ctr)
        self.id_ctr += 1
        for x in node.inner:
            self.assign_ids(x)

    def visit(self, node:'ASTNode', parent:'ASTNode'=None):
        visit_method = getattr(self, node.visitor_method_name, None)
        node_attrs = visit_method(node) if visit_method else NodeAttrs(f'TODO: {node.kind}')
        if self._format_node:
            # give the callback a chance to modify the formatting
            self._format_node(node, node_attrs)
        self.create_graph_node(node, parent, node_attrs)
        for child in node.inner:
            self.visit(child, node)

    def create_graph_node(self, node:'ASTNode', parent:'ASTNode', attrs:NodeAttrs):
        label = _NODE_FMT.format(node.kind, html.escape(attrs.node_string))
        self.g.node(node._graph_id, label=label, color=attrs.node_color, fontcolor=attrs.font_color)
        if parent and '_graph_id' in parent.__dict__:
            self.g.edge(node._graph_id, parent._graph_id)

    def visit_ArraySubscriptExpr(self, node):
        return NodeAttrs('')

    def visit_BinaryOperator(self, node):
        return NodeAttrs(f'{node.opcode}')

    def visit_BuiltinType(self, bit:'ASTNode'):
        return NodeAttrs(bit.name)

    def visit_CallExpr(self, node):
        return NodeAttrs(f'caller @ 0x{node.instr_addr:x}')

    def visit_CharacterLiteral(self, node:CharacterLiteral):
        return NodeAttrs(f"{node.value}")

    def visit_CompoundStmt(self, node):
        return NodeAttrs('')

    def visit_CStyleCastExpr(self, node):
        return NodeAttrs(str(node.dtype))

    def visit_DeclRefExpr(self, node):
        return NodeAttrs(f'{node.referencedDecl.name}')

    def visit_DeclStmt(self, stmt:'ASTNode'):
        return NodeAttrs('')

    def visit_FloatingLiteral(self, lit:'ASTNode'):
        return NodeAttrs(f'{lit.value}')

    def visit_ForStmt(self, fstmt):
        # return NodeAttrs(f'@ 0x{fstmt.instr_addr:x}')
        return NodeAttrs('')

    def visit_FunctionDecl(self, fdecl:'ASTNode'):
        return NodeAttrs(f'{fdecl.return_dtype} {fdecl.name}')

    def visit_IfStmt(self, node):
        return NodeAttrs('')

    def visit_IntegerLiteral(self, node):
        return NodeAttrs(f'0x{node.value:x} @ 0x{node.instr_addr:x}')

    def visit_MemberExpr(self, memexpr):
        return NodeAttrs(f'0x{memexpr.offset:x}:{memexpr.name} @ 0x{memexpr.instr_addr:x}')

    def visit_ParenExpr(self, parenexpr):
        return NodeAttrs('')

    def visit_ParmVarDecl(self, pvdecl):
        return NodeAttrs(f'{pvdecl.dtype} {pvdecl.name}')

    def visit_ReturnStmt(self, rs):
        return NodeAttrs('')

    def visit_TranslationUnitDecl(self, tudecl):
        return NodeAttrs('')

    def visit_TypedefDecl(self, tddecl):
        return NodeAttrs(f'{tddecl.name}')

    def visit_UnaryOperator(self, node):
        return NodeAttrs(f'{node.opcode}')

    def visit_VarDecl(self, vdecl):
        return NodeAttrs(f'{vdecl.dtype} {vdecl.name}')

class VariableGraphViewer(ASTViewer):
    def __init__(self, vgraph_nodes:List[ASTNode], render_khop:int=-1,
                format_node:Callable[[ASTNode,NodeAttrs],Any]=None) -> None:
        '''
        vgraph_nodes: List of nodes in the variable graph, with node[0] being the
                      DeclRefExpr node
        render_khop: If > -1, render the khop neighborhood even if it goes outside
                     the variable graph (useful for context if format_node highlights
                     only the vgraph)
        '''
        super().__init__(format_node)

        self.vgraph_nodes = vgraph_nodes
        self.render_khop = render_khop
        self.id_ctr = 0     # reset

        # add these extra edges that don't exist in AST
        self.needs_edge_to_declref = self._collect_neighbors_for_all_declrefs()

    def _collect_neighbors_for_all_declrefs(self) -> List[ASTNode]:
        '''
        We need dedicated logic for this since we aren't just finding AST neighbors.
        Instead, we need to find all nodes in our supplied variable graph which should
        be connected to our UNIFIED/MERGED DeclRefExpr node.

        In other words, we add edges from our one representative DeclRefExpr node
        to every node which is a parent of any of the (several) DeclRefExpr nodes
        in the variable graph.

        We should end up with a single DeclRefExpr node for the target variable that
        has one outgoing edge to every expression in which it is referenced.

        ...and this architecture allows our model to compute a node embedding for
        the target variable (DeclRefExpr) that includes information aggregated
        across all the references to this variable in our context (function or globally)
        '''
        needs_edge_to_declref = []

        for n in self.vgraph_nodes[1:]:
            for x in n.inner:
                if x.kind == 'DeclRefExpr' and x.referencedDecl.name == self.declref_varname:
                    needs_edge_to_declref.append(n)
                    break   # move on to next node in neighborhood

        return needs_edge_to_declref

    @property
    def declref(self) -> DeclRefExpr:
        return self.vgraph_nodes[0] if self.vgraph_nodes else None

    @property
    def declref_varname(self) -> str:
        return self.declref.referencedDecl.name if self.declref else ''

    # COPIED FROM PARENT:

    def render_vargraph(self, format:str='pdf', outfolder:Path=None, ast_name:str='',
                   fontname:str='Cascadia Code'):
        if not ast_name:
            ast_name = f'{self.declref_varname}_VarGraph'
        self.id_ctr = 0     # reset

        self.g = Graph(ast_name, format=format)
        self.g.attr('graph', rankdir='BT')
        self.g.attr('node', shape='plaintext')
        self.g.attr('node', fontname=fontname)

        render_nodes = self.assign_ids(self.declref)

        for v in render_nodes:
            node_attrs = self.visit(v)
            self.create_graph_node(v, v.parent, node_attrs)

        # ADD EXTRA EDGES

        for node in self.needs_edge_to_declref:
            node_attrs = self.visit(node)
            # TODO: color each outgoing edge from target node
            self.add_edge(self.declref, node)

        if outfolder is not None:
            self.g.render(directory=outfolder, view=False)

        return self.g

    # TODO: change the render_ast() implementation to
    # - assign ids for the khop neighborhood (or just the vgraph nodes otherwise)
    #       make khop simple:
    #           for i in range(khop):
    #               # reach out another hop
    #                   (collect new parent/child nodes that don't already exist in our list, for all nodes in our list)
    #                   assign ids to these new ones, add to list
    #
    # - render each node in the khop, STARTING FROM DeclRefExpr
    #

    def _get_khop_neighborhood(self, node:ASTNode, k:int):
        from itertools import chain
        node_list = [node]
        for i in range(k):
            new_nodes = []
            for n in node_list:
                for neighbor in chain([n.parent], n.inner):
                    if neighbor is not None and neighbor not in node_list:
                        new_nodes.append(neighbor)

            for nn in new_nodes:
                if nn not in node_list:
                    node_list.append(nn)

        return node_list

    def _assign_node_id(self, node:ASTNode):
        node._graph_id = str(self.id_ctr)
        self.id_ctr += 1

    def assign_ids(self, node:'ASTNode') -> List[ASTNode]:
        '''Assigns ids and returns the list of nodes to be rendered'''
        render_nodes = []

        if self.render_khop > -1:
            render_nodes = self._get_khop_neighborhood(node, self.render_khop)
        else:
            render_nodes = list(self.vgraph_nodes)

        for node in render_nodes:
            self._assign_node_id(node)

        return render_nodes

    def visit(self, node:'ASTNode'):
        visit_method = getattr(self, node.visitor_method_name, None)
        node_attrs = visit_method(node) if visit_method else NodeAttrs(f'TODO: {node.kind}')
        if self._format_node:
            # give the callback a chance to modify the formatting
            self._format_node(node, node_attrs)
        return node_attrs

    def create_graph_node(self, node:'ASTNode', parent:'ASTNode', attrs:NodeAttrs):
        label = _NODE_FMT.format(node.kind, html.escape(attrs.node_string))
        self.g.node(node._graph_id, label=label, color=attrs.node_color, fontcolor=attrs.font_color)
        self.add_edge(node, parent)

    def add_edge(self, node:ASTNode, parent:ASTNode):
        if parent and '_graph_id' in parent.__dict__:
            self.g.edge(node._graph_id, parent._graph_id)
