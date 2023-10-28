from .astviewer import *

from typing import List

class FindAllVarRefs(VisitAllChildrenByDefaultVisitor):
    def __init__(self, varname:str) -> None:
        super().__init__()
        self.varname = varname

    def visit_DeclRefExpr(self, refexpr:ASTNode):
        if refexpr.referencedDecl.name == self.varname:
            return refexpr

class FindAllStatementsContainingVar(VisitAllChildrenByDefaultVisitor):
    def __init__(self, varname:str) -> None:
        super().__init__()
        self.varname = varname

        # use a list here to ensure we don't collect duplicate statements, which
        # could occur if a var is referenced multiple times in a single statement
        self._statements = []

    def collect_statement_set(self, ast:ASTNode) -> List[ASTNode]:
        self.visit(ast)
        return self._statements

    def visit_DeclRefExpr(self, refexpr:ASTNode):
        if refexpr.referencedDecl.name == self.varname:
            # this is a reference, capture it's containing statement
            node = refexpr.parent

            while not node.is_statement:
                node = node.parent

            # make sure we haven't already saved this statement
            if node not in self._statements:
                self._statements.append(node)
