class VisitAllNodes(ASTVisitor):
    def visit_node(self, node:ASTNode):
        raise NotImplementedError('visit_node not implemented!')

    def visit_BinaryOperator(self, node:ASTNode):
        return self.visit_node(node)
    def visit_BreakStmt(self, node:ASTNode):
        return self.visit_node(node)
    def visit_CallExpr(self, node:ASTNode):
        return self.visit_node(node)
    def visit_CaseStmt(self, node:ASTNode):
        return self.visit_node(node)
    def visit_CharacterLiteral(self, node:ASTNode):
        return self.visit_node(node)
    def visit_CompoundStmt(self, node:ASTNode):
        return self.visit_node(node)
    def visit_ConstantExpr(self, node:ASTNode):
        return self.visit_node(node)
    def visit_CStyleCastExpr(self, node:ASTNode):
        return self.visit_node(node)
    def visit_DeclRefExpr(self, node:ASTNode):
        return self.visit_node(node)
    def visit_DeclStmt(self, node:ASTNode):
        return self.visit_node(node)
    def visit_FunctionDecl(self, node:ASTNode):
        return self.visit_node(node)
    def visit_IfStmt(self, node:ASTNode):
        return self.visit_node(node)
    def visit_IntegerLiteral(self, node:ASTNode):
        return self.visit_node(node)
    def visit_LogMsg(self, node:ASTNode):
        return self.visit_node(node)
    def visit_ParenExpr(self, node:ASTNode):
        return self.visit_node(node)
    def visit_ParmVarDecl(self, node:ASTNode):
        return self.visit_node(node)
    def visit_SwitchStmt(self, node:ASTNode):
        return self.visit_node(node)
    def visit_TranslationUnitDecl(self, node:ASTNode):
        return self.visit_node(node)
    def visit_UnaryOperator(self, node:ASTNode):
        return self.visit_node(node)
    def visit_ValueDecl(self, node:ASTNode):
        return self.visit_node(node)
    def visit_VarDecl(self, node:ASTNode):
        return self.visit_node(node)