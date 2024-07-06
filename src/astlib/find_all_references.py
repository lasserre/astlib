from .astviewer import *

from typing import List
from .ast import ASTNode, FunctionDecl

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
