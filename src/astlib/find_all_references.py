from .astviewer import *

from typing import List
from .ast import ASTNode, FunctionDecl, DeclRefExpr, ValueDecl

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
    ref_instr_offsets = sorted([x.instr_addr - func_addr for x in var_refs])
    return ','.join(map(str, ref_instr_offsets))

def build_var_ast_signature(fdecl:FunctionDecl, varname:str) -> str:
    '''
    Compute the variable signature for the given variable by first
    locating all references.
    '''
    var_refs = FindAllVarRefs(varname).visit(fdecl.func_body)
    return compute_var_ast_signature(var_refs, fdecl.address)
