from typing import List, Any, Dict, Callable
from rich.console import Console

class ASTVisitor:
    '''
    Dynamically implements the visit() logic. Concrete visitors should do
    the following:
        1. Derive from ASTVisitor
        2. Implement visit_NODETYPE functions that accept an ASTNode instance
           for every node type they wish to support, e.g:

           def visit_VarDecl(vardecl:ASTNode):
               # do stuff here
               return True  # to prevent visiting child nodes
    '''
    def __init__(self, warn_missing_visits:bool, missing_visit_methods:List[str]=[], get_default_return_value:Callable[['ASTNode'],Any]='') -> None:
        '''
        warn_missing_visits: If true, log a warning when a node is encountered for which no visit method has been defined
        missing_visit_methods: A list of ASTNode types for which a missing visit method is expected (and no warning
        should be logged regardless of warn_missing_visits)
        '''
        self.warn_missing_visits = warn_missing_visits
        self.missing_visit_methods = missing_visit_methods
        self.get_default_return_value = get_default_return_value

    def missing_method_should_be_logged(self, node_kind:str):
        '''
        This logic is a bit weird to read when you combine with the "not visit_method"
        condition, so breaking it out into its own function for readability
        '''
        return self.warn_missing_visits and node_kind not in self.missing_visit_methods

    def visit(self, node):
        visit_method = getattr(self, node.visitor_method_name, None)

        if not visit_method and self.missing_method_should_be_logged(node.kind):
            console = Console()
            console.print(f'WARNING: No visit_method defined by {type(self).__name__} for node type {node.kind}', style='bright_yellow')

        return visit_method(node) if visit_method else self.get_default_return_value(node)

class VisitAllChildrenByDefaultVisitor(ASTVisitor):
    '''
    Visits all AST nodes in the tree by default, allowing specific node types to
    be visited by derived classes who implement visit_<NODE_KIND> methods.

    visit() will return a list of non-None return values gathered from node-specific
    visit methods, which may be used or ignored based on the concrete visitor
    '''
    def __init__(self) -> None:
        super().__init__(warn_missing_visits=False, missing_visit_methods=[])

    def visit(self, node):
        return_vals = []
        visit_method = getattr(self, node.visitor_method_name, None)

        if visit_method:
            res = visit_method(node)
            if res is not None:
                return_vals.append(res)

        for child in node.inner:
            return_vals.extend(self.visit(child))

        return return_vals

        # return self._visit_all_children(node)

    # def _visit_all_children(self, node):
    #     return self._aggregate_child_results([self.visit(child) for child in node.inner])

    # def _aggregate_child_results(self, child_return_vals:List[Any]) -> Any:
    #     # if you wish to access the return values of each child node's visit() function
    #     # then override this function
    #     return None

class StructTypeAndValueDeclLookup(VisitAllChildrenByDefaultVisitor):
    '''
    Generates a variable lookup dictionary that maps variable IDs -> corresponding
    ValueDecl nodes. The resulting dictionary is then used to set the
    DeclRefExpr.referencedDecl property for easy access (instead of just the ID we
    started with)

    I also added StructType ID lookups as well. This could be a separate class, but
    there's no reason to make multiple passes - we always want to do both. This
    logic sets the StructType._struct_def property to the StructDef node in the supplied
    structure library (struct_lib), which allows access to the structure attributes
    anywhere a StructType exists throughout the AST (these will all point to the same
    StructDef object, 1 per structure type).
    '''
    def __init__(self, struct_lib:Dict[int,'StructDef']) -> None:
        super().__init__()
        self.struct_lib = struct_lib

        # maps var id -> ASTNode
        self._var_lookup = {}
        # maps typedef name -> typedef decl
        self._typedef_lookup = {}

        # _save_mode == False:
        #   > 1x through, don't save bc lookup dict isn't complete yet
        #   > just map ids to ASTNodes in the dict
        # _save_mode == True:
        #   > 2x through, just set DeclRefExpr.referencedDecl = ASTNode via the lookup table
        self._save_mode = False

    def extract(self, node, save_result:bool) -> dict:
        '''
        node: The head node to start visiting
        save_result: If true, the resulting variable lookup dictionary
        will be saved to each DeclRefExpr node (this is used during initial
        load only, then it persists for easy access)
        '''
        self._var_lookup = {}
        self._save_mode = False
        self.visit(node)    # generate self._var_lookup
        if save_result:
            self._save_mode = True
            self.visit(node)    # save referencedDecl for each DeclRefExpr node
        return self._var_lookup

    def visit_CStyleCastExpr(self, castexpr):
        self.visit(castexpr.dtype)

    def visit_DeclRefExpr(self, refexpr):
        if self._save_mode:
            refexpr.referencedDecl = self._var_lookup[refexpr.referencedDecl_id]

    def visit_EnumConstantDecl(self, node):
        if not self._save_mode:
            self._var_lookup[node.id] = node

    def visit_FieldDecl(self, fdecl):
        self.visit(fdecl.dtype)

    def visit_FunctionDecl(self, node):
        if not self._save_mode:
            self._var_lookup[node.id] = node
        self.visit(node.return_dtype)

    def visit_FunctionType(self, ftype):
        self.visit(ftype.return_dtype)

    def visit_ParmVarDecl(self, node):
        if not self._save_mode:
            self._var_lookup[node.id] = node
        self.visit(node.dtype)

    def visit_RecordDecl(self, rd):
        rd._struct_def = self.struct_lib[rd.sid]

    def visit_StructType(self, node):
        if node._struct_def.sid == -1:
            # only visit this StructType if it hasn't yet been visited
            node._struct_def = self.struct_lib[node.sid]
            for f in node.fields:
                self.visit(f.dtype)

    def visit_TypedefDecl(self, tddecl):
        if not self._save_mode:
            self._typedef_lookup[tddecl.name] = tddecl

    def visit_TypedefType(self, tdtype):
        if self._save_mode:
            tdtype.decl = self._typedef_lookup[tdtype.name] if tdtype.name in self._typedef_lookup else None

    def visit_VarDecl(self, node):
        if not self._save_mode:
            self._var_lookup[node.id] = node
        self.visit(node.dtype)

class DatatypePrinter(ASTVisitor):
    def __init__(self) -> None:
        super().__init__(warn_missing_visits=False)

    def to_string(self, dtype):
        return self.visit(dtype)

    def isFuncptr(self, dtype):
        if dtype.kind == 'PointerType':
            while dtype.kind == 'PointerType':  # walk through pointer layers...
                dtype = dtype.inner[0]
            return dtype.kind == 'FunctionType'
        return False

    def visit(self, node):
        visit_method = getattr(self, node.visitor_method_name, None)
        return visit_method(node) if visit_method else f'TODO: visit method for {node.kind}'

    def visit_BuiltinType(self, bit):
        return bit.name

    def visit_FunctionType(self, ftype):
        is_fptr = ftype.parent.kind == 'PointerType'
        # fname = self._current_varname if self._current_varname else 'TODO_SET_CURRENT_VARNAME'
        fname = 'f'
        param_str = ','.join(self.visit(x) for x in ftype.inner)
        if is_fptr:
            if self.isFuncptr(ftype.return_dtype):
                # do this for now to avoid generating "spiral" syntax...
                return f'void* /*RETURNS FPTR*/ (*{fname})({param_str})'
            return f'{self.visit(ftype.return_dtype)} (*{fname})({param_str})'
        return f'{self.visit(ftype.return_dtype)} {fname}({param_str})'

    def visit_PointerType(self, pt):
        if pt.inner[0].kind == 'FunctionType':
            # don't add anything, FunctionType will handle the whole thing
            return self.visit(pt.inner[0])
        return f'{self.visit(pt.inner[0])}*'

    def visit_TypedefType(self, tdtype):
        return tdtype.name

    def visit_VoidType(self, vt):
        return "void"

class HasNodeTypesVisitor(ASTVisitor):
    def __init__(self, node_types:List[str], has_any:bool=True) -> None:
        '''
        node_types: The list of node types (kinds) to check for
        has_any: If set, return true if any of the node types exist. Otherwise,
                 return true only if ALL node types exist in the tree
        '''
        super().__init__(False)
        self.node_types = node_types
        self.has_any = has_any
        self._result = False
        self._types_found = set()

    def visit(self, node):
        if self._result:
            return self._result  # we've already figured it out, we're done

        if node.kind in self.node_types:
            if self.has_any:
                self._result = True
                return self._result
            else:
                self._types_found.add(node.kind)
                if len(self._types_found) == len(self.node_types):
                    # we found them all
                    self._result = True
                    return self._result

        for child in node.inner:
            self.visit(child)

        return self._result

class GetNodesAtAddr(ASTVisitor):
    def __init__(self, addr:int) -> None:
        super().__init__(False)
        self.addr = addr
        self.node_matches = []

    def visit(self, node):
        if 'instr_addr' in node.__dict__:
            if node.instr_addr == self.addr:
                self.node_matches.append(node)

        for child in node.inner:
            self.visit(child)

        return self.node_matches