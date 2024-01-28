import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

import ghidra
from ghidra.app.decompiler import *
from ghidra.program.database import ProgramDB

from typing import List, Any
from rich.console import Console
import astlib
from varlib import datatype, location

# NOTE: While this seems like it should be a parser (inputs are tokens), it is
# not simply a linear stream of tokens - the base ClangToken class implements
# ClangNode which is a tree node.

# -- So it is more like a TREE of tokens...(tokens and token)
#    The comment for ClangTokenGroup says: "A node in a tree of C code tokens"
#    The comment for ClangToken says: "Class representing a C code language token"

# I also checked the "AST Graph" functionality in GraphASTScript.java, but from what
# I can tell this is just a data-flow graph from the basic blocks, not really an AST

# ...so (as I have demonstrated before), I may be wrong and this may not be the
# ideal place to get this information, but this is the best I can find right now lol

_syntax_token_types = {
    ClangSyntaxToken.COMMENT_COLOR: 'COMMENT',
    ClangSyntaxToken.CONST_COLOR: 'CONST',
    ClangSyntaxToken.DEFAULT_COLOR: 'DEFAULT',
    ClangSyntaxToken.ERROR_COLOR: 'ERROR',
    ClangSyntaxToken.FUNCTION_COLOR: 'FUNCTION',
    ClangSyntaxToken.GLOBAL_COLOR: 'GLOBAL',
    ClangSyntaxToken.KEYWORD_COLOR: 'KEYWORD',
    ClangSyntaxToken.MAX_COLOR: 'MAX',
    ClangSyntaxToken.PARAMETER_COLOR: 'PARAMETER',
    ClangSyntaxToken.SPECIAL_COLOR: 'SPECIAL',
    ClangSyntaxToken.TYPE_COLOR: 'TYPE',
    ClangSyntaxToken.VARIABLE_COLOR: 'VARIABLE',
}

def syntaxTokenTypeStr(self:ClangSyntaxToken) -> str:
    global _syntax_token_types
    stype = self.getSyntaxType()
    if stype not in _syntax_token_types:
        return f'Unrecognized token type {stype}'
    return _syntax_token_types[stype]

def getClangNodeName(node:ClangNode):
    # node class names are of the form ghidra.app.decompiler.NAME
    return node.__class__.__name__.split('.')[-1]

class AstBuilder:
    '''Build the astlib AST for Ghidra functions'''
    def __init__(self, func_decomp:DecompileResults) -> None:
        self.func_decomp = func_decomp
        self.tudecl = astlib.TranslationUnitDecl()
        # save here during construction, then add to tudecl at the end
        self.global_var_decls:List[astlib.VarDecl] = []         # global var decls
        self.other_func_decls:List[astlib.FunctionDecl] = []    # forward-declared functions
        self.main_func_decl:astlib.FunctionDecl = None
        self.main_func_body:astlib.CompoundStmt = None
        self._next_decl_id = 0
        self.console = Console()

    def _new_decl_id(self) -> int:
        '''Get the next decl available decl id to be used for a new/unique decl'''
        new_id = self._next_decl_id
        self._next_decl_id += 1
        return new_id

    def build_func_ast(self) -> astlib.TranslationUnitDecl:
        clang_func = self.func_decomp.getCCodeMarkup()

        # NOTE: visit children only to verify we never see ClangFunction nodes
        # within the main ClangFunction result (CCodeMarkup)
        # -> if I'm wrong, I'll get an unimplemented node type for ClangFunction
        # self._visit_children(clang_func)
        fbody_idx = 0

        # find and parse func proto
        for i in range(clang_func.numChildren()):
            node = clang_func.Child(i)

            if not self.main_func_decl:
                # parseFuncProto()
                if getClangNodeName(node) != 'ClangFuncProto':
                    continue    # skip all the initial comments

                self.main_func_decl = self._visit_node(node)  # parse func proto
                self.main_func_body = astlib.CompoundStmt()
                self.main_func_decl.add_child(self.main_func_body)
                fbody_idx = i+1

        # parse function body
        for astnode in self._visit_children(clang_func, start_idx=fbody_idx):
            self.main_func_body.add_child(astnode)

        # TEMP: try this, if it doesn't work we can go back to iterative
        # (push node) approach
        # --> but for parsing, once we know our context, it makes sense to "parse this thing"
        #     now instead of pushing current node and when we hit a SYNTAX TOKEN, how do
        #     we know what it means? it's simpler to express the logic in terms of
        #     "I'm parsing an if statement"
        # parseFuncProto()
        # parseFuncBody()

        # add in the main components as children of top-level translation unit
        for gvar in self.global_var_decls:
            self.tudecl.add_child(gvar)

        for func in self.other_func_decls:
            self.tudecl.add_child(func)

        self.tudecl.add_child(self.main_func_decl)

        return self.tudecl

    def _visit_node(self, node:ClangNode):
        node_name = getClangNodeName(node)
        visit_method = getattr(self, f'_visit_{node_name}', None)

        if not visit_method:
            msg = f'WARNING: No visit_method defined for {node_name}'
            self.console.print(msg, style='bright_yellow')
            return None    # FIXME: temp for testing
            # raise Exception(msg)

        return visit_method(node) if visit_method else None

    def _visit_children(self, node:ClangNode, start_idx:int=0) -> List[Any]:
        return_values = [self._visit_node(node.Child(i)) for i in range(start_idx, node.numChildren())]
        return [x for x  in return_values if x is not None]

    # def _visit_ClangFunction(self, node:ClangFunction):
        # self._visit_children(node)

    def _visit_ClangSyntaxToken(self, tok:ClangSyntaxToken):
        typestr = syntaxTokenTypeStr(tok)
        if str(tok.text) and not str(tok.text).isspace():
            print(f'SYNTAX TOKEN: {tok.text}, TYPE={typestr}, OPEN={tok.getOpen()}, CLOSE={tok.getClose()}, children={tok.numChildren()}')

    def _visit_ClangBreak(self, cbreak:ClangBreak):
        if cbreak.numChildren() > 0:
            print(f'ClangBreak has children')
            import IPython; IPython.embed()

    def _visit_ClangCommentToken(self, comment:ClangCommentToken):
        # don't care about comments
        pass

    def _visit_ClangFuncProto(self, fp:ClangFuncProto):
        # ASSUMPTION (I've validated this manually): there is 1 and only 1 ClangFuncProto,
        # and this is for the function whose AST we are generating
        # --> this corresponds to the main FunctionDecl in the TranslationUnitDecl

        print(f'Func proto (numChildren = {fp.numChildren()})')
        name = 'todo'
        address = fp.getClangFunction().getMinAddress().getOffset()
        return_dtype = datatype.DataType('TEMP')
        params = []

        self.console.print(f'TODO: handle func proto arguments', style='bright_yellow')

        fdecl = astlib.FunctionDecl(self._new_decl_id(), name, address, False, return_dtype, params)
        return fdecl

    def _visit_ClangVariableDecl(self, cvdecl:ClangVariableDecl):
        print('TODO: vdecl')

        # TODO: we can just return the VarDecl node here!
        #   --> (CompoundStmt collects all child return vals and adds them as children)

        # TODO: once I see what is needed to create DeclRefExpr nodes, probably also need to
        # save a mapping from (decl_id: VarDecl) so I can set referencedDecl in DeclRefExpr

        import IPython; IPython.embed()
        raise Exception('finish')

    def _visit_ClangVariableToken(self, vtok:ClangVariableToken):
        print(f'VAR TOKEN: {vtok.getText()}, numChildren={vtok.numChildren()}')
        # if vtok.getText() == '0x20002':
        #     import IPython; IPython.embed()

    def _visit_ClangTokenGroup(self, tg:ClangTokenGroup):
        print('ClangTokenGroup children...')
        # import IPython; IPython.embed()
        self._visit_children(tg)

    def _visit_ClangStatement(self, statement:ClangStatement):
        print(f'STATEMENT: {statement.getPcodeOp().toString()} (numChildren={statement.numChildren()})')
        print('visiting statement children...')
        self._visit_children(statement)
        print('...done')

    def _visit_ClangOpToken(self, optoken:ClangOpToken):
        print(f'OP TOKEN: {optoken.text} (numChildren={optoken.numChildren()})')
