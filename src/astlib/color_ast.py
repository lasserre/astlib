# collection of built-in format_node callbacks for ast.render()

# from .ast import A
from .astvisitor import ASTNode
from typing import List

def highlight_var_refs(varname:str, font_color:str='red'):
    '''
    Returns a format_node callback function that highlights all references
    to the given variable
    '''
    def do_highlight(node, attrs):
        if node.kind == 'DeclRefExpr' and node.referencedDecl.name == varname:
            attrs.font_color = font_color
    return do_highlight

def _mark_khop_neighborhood(node:ASTNode, k:int):
    '''
    node: The node whose neighborhood should be marked
    k: The number of hops to mark
    '''
    # k == 0 -> only mark this node
    # k == 1 -> mark immediate neighbors
    # k > 1 -> mark neighbors up to k hops away
    neighborhood_nodes = [node]
    # node.in_neighborhood = True
    if k > 0:
        if node.parent:
            neighborhood_nodes.extend(_mark_khop_neighborhood(node.parent, k-1))
        for child in node.inner:
            neighborhood_nodes.extend(_mark_khop_neighborhood(child, k-1))
    return list(set(neighborhood_nodes))

def highlight_khop_neighborhood(nodes:List[ASTNode], k:int, font_color:str='red'):
    '''
    node: The node whose neighborhood should be marked
    k: The number of hops to mark
    font_color: The font color used for highlighting
    '''
    neighborhood = []
    for n in nodes:
        neighborhood.extend(_mark_khop_neighborhood(n, k))
    neighborhood = list(set(neighborhood))
    def do_highlight(n, attrs):
        # if hasattr(n, 'in_neighborhood'):
        if n in neighborhood:
            attrs.font_color = font_color
    return do_highlight
