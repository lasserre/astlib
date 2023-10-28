# collection of built-in format_node callbacks for ast.render()

def highlight_var_refs(varname:str, font_color:str='red'):
    '''
    Returns a format_node callback function that highlights all references
    to the given variable
    '''
    def do_highlight(node, attrs):
        if node.kind == 'DeclRefExpr' and node.referencedDecl.name == varname:
            attrs.font_color = font_color
    return do_highlight
