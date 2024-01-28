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

from .datatypes import to_varlib_dtype

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

PAUSE_UNIMPLEMENTED = False

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

class CommaToken:
    '''
    Only setting this up because I know Ghidra uses the comma operator, and we're
    probably going to need to find this

    Best case scenario, Ghidra exposes this as a ClangOpToken and we don't have to
    parse it out :P
    '''
    def __init__(self, tok:ClangSyntaxToken):
        self.tok = tok

class GroupingToken:
    '''
    Represents a paren or bracket that can be opened or closed and has
    a matching inverse with the same id
    '''
    def __init__(self, tok:ClangSyntaxToken):
        self.tok = tok

    @property
    def id(self) -> int:
        return self.tok.open if self.is_open else self.tok.close

    @property
    def is_paren(self) -> bool:
        return self.tok.text in '()'

    @property
    def is_bracket(self) -> bool:
        return self.tok.text in '[]'

    @property
    def is_open(self) -> bool:
        return self.tok.open > -1

    @property
    def is_close(self) -> bool:
        return self.tok.close > -1

def getNodeName(node:ClangNode):
    # node class names are of the form ghidra.app.decompiler.NAME
    return node.__class__.__name__.split('.')[-1]

def getNodeChildren(node:ClangNode) -> List[ClangNode]:
    return [node.Child(i) for i in range(node.numChildren())]

def location_from_storage(storage:ghidra.program.model.listing.VariableStorage) -> location.Location:
    if not storage.valid:
        raise Exception(f'Invalid storage {storage}')
    if storage.varnodeCount != 1:
        raise Exception(f'Unhandled varnode count of {storage.varnodeCount}')

    address = storage.firstVarnode.getAddress()
    space_name = address.addressSpace.name

    if space_name == 'unique':
        return location.Location(location.LocationType.Unique, offset=address.offset)
    elif storage.registerStorage:
        return location.Location(location.LocationType.Register, storage.register.name)
    elif storage.stackOffset is not None:
        return location.Location(location.LocationType.Stack, offset=storage.stackOffset)

    print(f'Unhandled address space {space_name}')
    import IPython; IPython.embed()
    raise Exception(f'Unhandled address space {space_name}')

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
            out = self._visit_node(clang_func.Child(i))
            if isinstance(out, astlib.FunctionDecl):
                self.main_func_decl = out
                fbody_idx = i+1
                break

        # parse function body
        fbody = CompoundStmtParser(clang_func, self, start_idx=fbody_idx).parse()
        self.main_func_decl.add_child(fbody)

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
        node_name = getNodeName(node)
        visit_method = getattr(self, f'_visit_{node_name}', None)

        if not visit_method:
            msg = f'WARNING: No visit_method defined for {node_name}'
            self.console.print(msg, style='bright_yellow')
            return None    # FIXME: temp for testing
            # raise Exception(msg)

        return visit_method(node) if visit_method else None

    def _visit_children(self, node:ClangNode, start_idx:int=0) -> List[Any]:
        return_values = [self._visit_node(node.Child(i)) for i in range(start_idx, node.numChildren())]
        return [x for x in return_values if x is not None]

    # def _visit_ClangFunction(self, node:ClangFunction):
        # self._visit_children(node)

    def _visit_ClangSyntaxToken(self, tok:ClangSyntaxToken):
        typestr = syntaxTokenTypeStr(tok)
        if str(tok.text) and not str(tok.text).isspace():
            if tok.syntaxType == ClangToken.KEYWORD_COLOR:
                if tok.text == 'void':
                    return datatype.BuiltinType.create_void_type()
                msg = f'Unhandled keyword {tok.text}'
                self.console.print(msg, style='bright_yellow')
                if PAUSE_UNIMPLEMENTED:
                    import IPython; IPython.embed()
                    raise Exception('done')

            if tok.syntaxType == ClangToken.DEFAULT_COLOR:
                if tok.text == ',':
                    return CommaToken(tok)
                return GroupingToken(tok)

            print(f'SYNTAX TOKEN: {tok.text}, TYPE={typestr}, OPEN={tok.getOpen()}, CLOSE={tok.getClose()}, children={tok.numChildren()}')
            if PAUSE_UNIMPLEMENTED:
                import IPython; IPython.embed()
                raise Exception('done')

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
        return FuncprotoParser(fp, self).parse()

    ##--------------------------------------
    # For IfStmt, WhileStmt, CompoundStmt, etc...
    # - SyntaxToken is going to clue us in on state change ('if', 'while', etc)
    # - SyntaxToken needs to RETURN something to let us start parsing XYZ
    #   - IfParser(builder)
        # parseCond
        # parseIfBlock
        # parseElseBlock
    # - SyntaxToken needs to let us know when a scope is entered/exited ({ and } at least)
    #   --> because these are AT THE SAME LEVEL as "if"/etc, I think it will work properly
    #       since we will be ABLE to observe the scope changes without peeking
    #       into grandchildren nodes
    ##--------------------------------------

    def _visit_ClangVariableDecl(self, cvdecl:ClangVariableDecl):

        # TODO: once I see what is needed to create DeclRefExpr nodes, probably also need to
        # save a mapping from (decl_id: VarDecl) so I can set referencedDecl in DeclRefExpr

        sym = cvdecl.highSymbol
        return astlib.VarDecl(self._new_decl_id(), sym.name,
            to_varlib_dtype(sym.dataType),
            location_from_storage(sym.storage))

    def _visit_ClangVariableToken(self, vtok:ClangVariableToken):
        print(f'VAR TOKEN: {vtok.getText()}, numChildren={vtok.numChildren()}')
        # if vtok.getText() == '0x20002':
        #     import IPython; IPython.embed()
        if PAUSE_UNIMPLEMENTED:
            import IPython; IPython.embed()
            raise Exception('done')

    def _visit_ClangTokenGroup(self, tg:ClangTokenGroup):
        # NOTE: we may need to flatten nested CompundStmts when we are done
        return CompoundStmtParser(tg, self).parse()

    def _visit_ClangStatement(self, statement:ClangStatement):
        print(f'STATEMENT: {statement.getPcodeOp().toString()} (numChildren={statement.numChildren()})')
        import IPython; IPython.embed()
        print('visiting statement children...')
        if PAUSE_UNIMPLEMENTED:
            import IPython; IPython.embed()
            if hasattr(self, 'quit'):
                raise Exception('done')
        self._visit_children(statement)
        print('...done')

    def _visit_ClangOpToken(self, optoken:ClangOpToken):
        print(f'OP TOKEN: {optoken.text} (numChildren={optoken.numChildren()})')

        if optoken.text == 'if':
            import IPython; IPython.embed()

        if optoken.text == '*':
            import IPython; IPython.embed()

        if PAUSE_UNIMPLEMENTED:
            import IPython; IPython.embed()
            raise Exception('done')

    def _visit_ClangReturnType(self, rtype:ClangReturnType):
        if rtype.dataType is None:
            return datatype.BuiltinType.create_void_type()
        return to_varlib_dtype(rtype.dataType)

class FuncprotoParser:
    def __init__(self, clang_fp:ClangFuncProto, builder:AstBuilder):
        self.clang_fp = clang_fp
        self.builder = builder

    def parse(self) -> astlib.FunctionDecl:
        # node 0: rtype
        rtype = self.builder._visit_node(self.clang_fp.Child(0))
        if not isinstance(rtype, datatype.DataType):
            raise Exception(f'Expected return type to be first child of func proto')

        # node 2: func name
        fname_token:ClangFuncNameToken = self.clang_fp.Child(2)
        if not isinstance(fname_token, ClangFuncNameToken):
            raise Exception(f'Expected func name to be 3rd child of func proto')

        fname = fname_token.text
        address = self.clang_fp.clangFunction.minAddress.offset

        # parse params
        outputs = []
        for i in range(3, self.clang_fp.numChildren()):
            outputs.append(self.builder._visit_node(self.clang_fp.Child(i)))

        # we should get VarDecls for each param
        vdecl_params = [x for x in outputs if isinstance(x, astlib.VarDecl)]

        # convert to ParmVarDecl to satisfy AST
        params = [astlib.ParmVarDecl(vd.id, vd.name, vd.dtype, vd.location) for vd in vdecl_params]

        return astlib.FunctionDecl(self.builder._new_decl_id(), fname, address, False, rtype, params)

class CompoundStmtParser:
    def __init__(self, node:ClangNode, builder:AstBuilder, start_idx:int=0):
        '''
        node: The node whose children should be added to the compound statement
        builder: The builder to use for parsing
        start_idx: Child index to start with, defaults to 0
        '''
        self.node = node
        self.builder = builder
        self.start_idx = start_idx

    def parse(self) -> astlib.CompoundStmt:
        stmt = astlib.CompoundStmt()

        for out in self.builder._visit_children(self.node, self.start_idx):
            if isinstance(out, astlib.ASTNode):
                stmt.add_child(out)

        return stmt

class StatementParser:
    def __init__(self, stmt:ClangStatement, builder:AstBuilder):
        self.stmt = stmt
        self.builder = builder

    def parse(self) -> astlib.ASTNode:
        # TODO: somewhere we are going to have an ExprParser, which is the reusable part

        # things that a statement can start with:
        # - open paren: (xyz->x).gain = 3;
        # - var token: lvar1 = 5;
        # - function call: myFunc();  --> this is a ClangFuncNameToken
        # - KEYWORD?!? (confirm..) if, while, etc.
            # - if is an OP_TOKEN
            # - else is a SYNTAX TOKEN

        # THIS IS IT! use the statement pcode op to determine what we do!
        self.stmt.pcodeOp.mnemonic

        if isinstance(self.stmt.Child(0), ClangFuncNameToken):
            # this statement is a function call
            pass
        # TODO: check first child to see if it's a keyword statement (if/while/switch)
        # elif self.builder._visit_node(self.stmt.Child(0))

        # finally, assume it's a LHS = RHS; statement
        op_tokens = [(i, x) for i, x in enumerate(getNodeChildren(self.stmt)) if getNodeName(x) == 'ClangOpToken']


        # self.builder._visit_children(self.stmt)

class ExprParser:
    def __init__(self, node:ClangNode, builder:AstBuilder):
        self.node = node
        self.builder = builder

    def parse(self) -> astlib.ASTNode:
        # things that are NOT expressions
        # - statements/blocks (if, while, switch, etc)
        pass