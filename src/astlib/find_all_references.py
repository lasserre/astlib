from .astviewer import *

from typing import List
from .ast import *

class FindAllVarRefs(VisitAllChildrenByDefaultVisitor):
    def __init__(self, varname:str) -> None:
        super().__init__()
        self.varname = varname

    def visit_DeclRefExpr(self, refexpr:ASTNode):
        if refexpr.referencedDecl.name == self.varname:
            return refexpr

class Statement:
    def __init__(self, statement_node:ASTNode, refexprs:List[ASTNode]):
        self.statement_node = statement_node
        self.refexprs = refexprs

class FindAllStatementsContainingVar(VisitAllChildrenByDefaultVisitor):
    def __init__(self, varname:str) -> None:
        super().__init__()
        self.varname = varname

        # use a dict here to ensure we consolidate duplicate statements, which
        # could occur if a var is referenced multiple times in a single statement
        self._statements = {}

    def collect_statement_set(self, ast:ASTNode) -> List[Statement]:
        '''
        Returns a list of statements, with each statement being a tuple of
        (StatementNode, DeclRefExprNode)
        where the DeclRefExprNode is the reference
        '''
        self.visit(ast)
        return list(self._statements.values())

    def visit_DeclRefExpr(self, refexpr:ASTNode):
        if refexpr.referencedDecl.name == self.varname:
            # this is a reference, capture it's containing statement
            node = refexpr.parent

            while not node.is_statement:
                node = node.parent

            # make sure we haven't already saved this statement
            if node not in self._statements:
                self._statements[node] = Statement(node, [refexpr])
            else:
                self._statements[node].refexprs.append(refexpr)

def get_vartype(decl:ValueDecl) -> str:
    '''
    Returns the vartype string (as used in varid) for a local or parameter
    variable declaration
    '''
    return 'l' if decl.kind == 'VarDecl' else 'p'

def get_vartype_from_ref(ref:DeclRefExpr) -> str:
    '''
    Returns the vartype string (as used in varid) for a local or parameter
    variable reference.
    '''
    return get_vartype(ref.referencedDecl)

def binary_id(binary_name:str) -> int:
    '''
    Extracts the binary ID from the name of a binary file in Ghidra
    '''
    return int(binary_name.split('.')[0])

def original_binary_name(parent_folder_name:str) -> str:
    '''
    Extracts the original binary name from the name of the parent folder
    in Ghidra

    NOTE: this is a hacky workaround for an issue with .so files getting renamed
    to .debug and losing the .so extension. The current implementation
    that imports binaries into Ghidra preserves the original filename within the
    name of the parent folder, so I'm grabbing that to avoid having to re-generate
    the Ghidra databases
    '''
    # parent folder name format: "runX.X.<binary_name>."
    return '.'.join(parent_folder_name.split('.')[2:-1])

def run_id(binary_parent_folder:str) -> int:
    '''
    Extracts the run ID from the name of the parent folder of a binary file in Ghidra
    '''
    return int(binary_parent_folder.split('.')[0][3:])

def build_varid(bid:int, func_addr:int, var_signature:str, vartype:str) -> tuple:
    '''
    Builds the varid tuple (just a memory aid so I don't miss information)

    bid: Binary ID
    func_addr: Start address of function
    var_signature: Variable signature
    vartype: 'l' for local or 'p' for param
    '''
    return (bid, func_addr, var_signature, vartype)

def compute_var_ast_signature(var_refs:List[ASTNode], func_addr:int) -> str:
    '''
    Compute the DIRTY-style variable signature for the given variable, given all the
    references to the variable.

    The signature will be a string containing the sorted list of decimal instruction offsets
    (relative to the start of the function) in CSV format, and uniquely identifies a variable
    '''
    ref_instr_offsets = sorted(set([x.instr_addr - func_addr for x in var_refs]))
    return ','.join(map(str, ref_instr_offsets))

def build_var_ast_signature(fdecl:FunctionDecl, varname:str) -> str:
    '''
    Compute the variable signature for the given variable by first
    locating all references.
    '''
    var_refs = FindAllVarRefs(varname).visit(fdecl.func_body)
    return compute_var_ast_signature(var_refs, fdecl.address)

def find_root_vdecl(mexpr:MemberExpr) -> ValueDecl:
    if isinstance(mexpr.inner[0], MemberExpr):
        return find_root_vdecl(mexpr.inner[0])
    elif isinstance(mexpr.inner[0], DeclRefExpr):
        decl_ref = mexpr.inner[0]
        return decl_ref.referencedDecl
    elif isinstance(mexpr.inner[0], ArraySubscriptExpr):
        return find_root_vdecl(mexpr.inner[0])
    elif isinstance(mexpr.inner[0], ParenExpr):
        return find_root_vdecl(mexpr.inner[0])
    elif isinstance(mexpr.inner[0], UnaryOperator):# and mexpr.inner[0].opcode == '*':
        return find_root_vdecl(mexpr.inner[0])
    elif isinstance(mexpr.inner[0], CStyleCastExpr):
        return None     # we don't want to follow "non-variables" w/ a cast inside the member
                        # expression like: ((Struct1*)(var + 4))->field3
    else:
        msg = f'Unhandled MemberExpr.inner[0] type of {type(mexpr.inner[0])}'
        print(msg)
        mexpr.print()
        mexpr.parent.print()
        mexpr.parent.parent.print()
        raise Exception(msg)

class CollectAllMemberExprs(VisitAllChildrenByDefaultVisitor):
    def __init__(self, exclude_globals:bool=False):
        '''
        Collects all structure member references in the AST in the form
        of MemberExpr nodes.
        '''
        super().__init__()
        self.exclude_globals = exclude_globals

    def visit_MemberExpr(self, memexpr:MemberExpr):
        if self.exclude_globals:
            vdecl = find_root_vdecl(memexpr)
            return memexpr if vdecl and vdecl.location.loc_type != 'ram' else None
        return memexpr

class CollectStructMemberRefs(VisitAllChildrenByDefaultVisitor):
    def __init__(self, member_offset:int=-1, parent_sid:int=-1):
        '''
        Collects all structure member references in the AST in the form
        of MemberExpr nodes.

        If member_offset is specified, only members with this offset are returned
        If parent_sid is specified, only members with this parent_sid are returned

        These conditions can be combined to find only references to a single
        member in a specific structure
        '''
        super().__init__()
        self.member_offset = member_offset
        self.parent_sid = parent_sid
        # self.member_exprs:List[MemberExpr] = []

    def visit_MemberExpr(self, memexpr:'MemberExpr'):
        if self.member_offset > -1:
            if memexpr.offset != self.member_offset:
                return  # offset does not match
        if self.parent_sid > -1:
            if memexpr.sid != self.parent_sid:
                return  # parent sid does not match
        return memexpr

class CollectFakeStructMemberRefs(VisitAllChildrenByDefaultVisitor):
    def __init__(self):
        '''
        Collects all fake structure member references in the AST in the form
        of MemberExpr nodes. These are member references generated by Ghidra
        which do not actually exist in the parent structure from which they
        are referenced (e.g. svar._8_4_ or svar.field_0x10)
        '''
        super().__init__()

    def visit_MemberExpr(self, memexpr:'MemberExpr'):
        return memexpr if memexpr.is_fake_member else None
