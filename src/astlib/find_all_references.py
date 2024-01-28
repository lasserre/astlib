from .astviewer import *
from .ast import ASTNode

from typing import List

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
