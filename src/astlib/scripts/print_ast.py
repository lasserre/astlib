import argparse
from pathlib import Path
import json
from typing import Dict, List

# from ..ast import ASTNode, dict_to_ast
# from ..astvisitor import ASTVisitor
from astlib import *
from varlib.datatype import *

_var_lookup = {}

# TODO - after done validating I can switch back to the struct-style
# struct definitions instead of typedef-ing (which is fine to keep too).
# No big deal, but right now I'm kind of cheating and printing out the
# typedef style although my actual AST only has the struct XYZ {}; style
# definition (where you have to use struct XYZ everywhere).
# Reason I'm hacking around this issue is Ghidra code I'm validating against
# just refers to struct name directly
_VALIDATION_MODE = True

def get_next_indent(indent:str) -> str:
    return f'{indent}  '

def binary_operator_to_code(node:dict, indent='') -> str:
    lhs = node_to_code(node['inner'][0], indent)
    if len(node['inner']) > 1:
        rhs = node_to_code(node['inner'][1], indent)
    else:
        rhs = 'nullptr; /** <<< TODO: RHS!! **/'
    return f"{lhs} {node['opcode']} {rhs}"

def call_expr_to_code(node:dict, indent:str='') -> str:
    # lookup function being called
    # node_to_code arguments
    return '// ---> FIX CALL EXPR HERE <---'

def case_stmt_to_code(node:dict, indent:str='') -> str:
    val = node['inner'][0]['inner'][0]['value']
    cstr = f"case {val}:\n"
    next_indent = get_next_indent(indent)
    cstr += f"{next_indent}{node_to_code(node['inner'][1], next_indent)}"
    return cstr

block_types = [
    'CompoundStmt',
    'FunctionDecl',
    'IfStmt',
    'SwitchStmt',
]

def is_block(kind:str):
    return kind in block_types

def get_messages_recursive(node:dict, stop_at_kind='') -> List[str]:
    msgs = []
    if stop_at_kind and node['kind'] == stop_at_kind:
        # prevent including messages >1x e.g. for compound statement and
        # also a parent compound statement where it got rolled up again
        return msgs
    if 'messages' in node:
        msgs = node['messages']
    if 'inner' in node and node['inner']:
        for child in node['inner']:
            msgs.extend(get_messages_recursive(child))
    return msgs

def compound_stmt_to_code(node:dict, indent='') -> str:
    lines = []
    for c in node['inner']:
        lines.extend(f'{indent}/** {m} */' for m in get_messages_recursive(c, 'CompoundStmt'))
        semicolon = '' if is_block(c['kind']) else ';'
        lines.append(f'{indent}{node_to_code(c, indent)}{semicolon}')
    return f'\n'.join(lines)
    # return f'\n{indent}'.join([node_to_code(c, indent) for c in node['inner']])

def cstyle_cast_expr_to_code(node:dict, indent='') -> str:
    if len(node['inner']) != 1:
        raise Exception(f"CStyleCastExpr has >1 child: {node}")
    return f"({node['dtype']}){node_to_code(node['inner'][0], indent)}"

def decl_ref_expr_to_code(node:dict, indent='') -> str:
    global _var_lookup
    ref_node = _var_lookup[node['referencedDecl_id']]
    return f"{ref_node['name']}"

def integer_literal_to_code(node:dict, indent='') -> str:
    return f"0x{node['value']:x}"
    import IPython; IPython.embed()

def paren_expr_to_code(node:dict, indent='') -> str:
    if 'inner' not in node or not node['inner']:
        return '()'
    if len(node['inner'])>1:
        return f'/** unexpected ParenExpr with > 1 child! */'
    return f"({node_to_code(node['inner'][0], indent)})"

def switch_stmt_to_code(node:dict, indent='') -> str:
    sw_str = f"switch ({node_to_code(node['inner'][0],indent)}) {{\n"
    sw_str += node_to_code(node['inner'][1], indent)
    sw_str += f"\n{indent}}}"
    return sw_str

def unary_operator_to_code(node:dict, indent='') -> str:
    return f"{node['opcode']}{node_to_code(node['inner'][0],indent)}"

def node_to_code(node:dict, indent='') -> str:
    if node['kind'] == 'BinaryOperator':
        return binary_operator_to_code(node, indent)
    elif node['kind'] == 'BreakStmt':
        return f"  break"
    elif node['kind'] == 'CallExpr':
        return call_expr_to_code(node, indent)
    elif node['kind'] == 'CaseStmt':
        return case_stmt_to_code(node, indent)
    elif node['kind'] == 'CharacterLiteral':
        return repr(chr(node['value']))
    elif node['kind'] == 'CompoundStmt':
        return compound_stmt_to_code(node, indent)
    elif node['kind'] == 'CStyleCastExpr':
        return cstyle_cast_expr_to_code(node, indent)
    elif node['kind'] == 'DeclRefExpr':
        return decl_ref_expr_to_code(node, indent)
    elif node['kind'] == 'IfStmt':
        condition = node['inner'][0]
        then_block = node['inner'][1] if len(node['inner']) > 1 else {'kind': 'CompoundStmt', 'inner': []}
        stmt = f"if ({node_to_code(condition)}) {{"
        next_indent = get_next_indent(indent)
        stmt += f"\n{node_to_code(then_block, next_indent)}"
        stmt += f"\n{indent}}}"
        if len(node['inner']) > 2:
            else_block = node['inner'][2]
            stmt += f"\n{indent}else {{"
            stmt += f"\n{node_to_code(else_block, next_indent)}"
            stmt += f"\n{indent}}}"
        return stmt
    elif node['kind'] == 'IntegerLiteral':
        return integer_literal_to_code(node, indent)
    elif node['kind'] == 'ParenExpr':
        return paren_expr_to_code(node, indent)
    elif node['kind'] == 'SwitchStmt':
        return switch_stmt_to_code(node, indent)
    elif node['kind'] == 'UnaryOperator':
        return unary_operator_to_code(node, indent)
    else:
        return f'UNHANDLED KIND [{node["kind"]}]'

def map_var_ids(node:dict, var_lookup:Dict[int,dict]):
    if 'VarDecl' in node['kind']:
        var_lookup[node['id']] = node
    if 'inner' in node:
        for child in node['inner']:
            map_var_ids(child, var_lookup)

def ast_to_code(ast:dict) -> str:
    global _var_lookup
    if ast['kind'] != 'TranslationUnitDecl':
        print(f'Top-level element is not a Translation Unit ({ast["kind"]})')
        return
    map_var_ids(ast, _var_lookup)
    lines = []
    for n in ast['inner']:
        semicolon = '' if is_block(n['kind']) else ';'
        lines.append(f'{node_to_code(n)}{semicolon}')
    return f'\n'.join(lines)
    # return '\n'.join([node_to_code(n) for n in ast['inner']])

class PrintASTVisitor(ASTVisitor):
    def __init__(self, header_only:bool=False, indent_size:int=4,
                 validation_mode:bool=False) -> None:
        super().__init__(
            warn_missing_visits=True,
            missing_visit_methods=[
                # these methods are the ones we know we haven't implemented and are ok
                'TranslationUnitDecl'
                # 'CompoundStmt'
            ]
        )
        self.header_only = header_only
        self.validation_mode = validation_mode
        self.indent_size:int = indent_size
        self.current_indent:str = ''
        self._indent_stack = []

        # CLS: trying to refactor to return strings instead of storing them
        # in a _code state variable. This way, I can do things like ','.join(visit(x) for x in children)
        # because I don't have to make sure my commas get added in-between each call...

        # self._code:str = ''     # C code (or C++? lol)
        self._within_var_decl = False   # set during VarDecl processing
        # print arrays as pointers instead of arrays if they are return values
        # (e.g. int* func(); instead of int[3] func();)
        # just for validation...
        self._use_ptr_not_array = False
        self._num_vdecl_arr_elements = None
        self._current_varname = None
        self._statement_mode_stack:List[bool] = []
        self.push_statement_mode(False)

    def _indent(self):
        self._indent_stack.append(self.current_indent)
        self.current_indent += ' ' * self.indent_size

    def _unindent(self):
        self.current_indent = self._indent_stack.pop()

    def _suppress_indent(self):
        '''Temporarily stop indenting anything at all (for use within an expression)'''
        self._indent_stack.append(self.current_indent)
        self.current_indent = ''

    def _unsuppress_indent(self):
        # since we saved our old/current settings on the stack, just restore
        self.current_indent = self._indent_stack.pop()

    def _emit_line(self, line:str) -> str:
        '''Emits the given line, handling any necessary indentation and line endings'''
        return f'{self.current_indent}{line}\n'

    def _start_line(self, line_prefix:str='') -> str:
        return f'{self.current_indent}{line_prefix}'

    def _end_line(self, line_suffix:str='') -> str:
        return f'{line_suffix}\n'

    def convert_ast_to_code(self, node:ASTNode) -> str:
        # if node.kind != 'TranslationUnitDecl':
        # if not isinstance(node, TranslationUnitDecl):
        #     print(f'ERROR: Top-level element is not a translation unit ({node.kind})')
        #     return ''

        code = ''

        # if self.validation_mode:
            # add struct typedefs at top for validation
            # for child in node.inner:
                # if child.kind == 'RecordDecl':
                    # NOTE:
                    # - omitting typedef's here will cause clang errors...
                    # ...BUT, clang seems to be resilient to this kind of issue (it should
                    # only affect is with pointers to structs typically...we resolve struct
                    # deps pretty well for actual struct members)
                    # - when I include typedefs, validation will fail because it causes
                    # differences when clang omits the 2nd occurrence of the typedef
                    # (since I've already emitted it here). My AST has the 2nd occurence
                    # and we get a conflict
                    # code += self._emit_line(f'typedef struct {child.name} {child.name};')
                    # pass

            # emit this in validation mode unconditionally so our logic
            # to clean up typedefs works (these are just to facilitate clang compilation)
            # code += self._emit_line('typedef int REMOVE_EVERYTHING_ABOVE_THIS_IN_JSON;')

        code += self.visit(node)
        return code

    def push_statement_mode(self, new_mode:bool):
        self._statement_mode_stack.append(new_mode)

    def pop_statement_mode(self):
        self._statement_mode_stack.pop()

    @property
    def statement_mode(self):
        '''
        This is a state variable used during AST traversal to indicate
        whether sub-expressions should emit themselves as complete statements
        (with a trailing semicolon/newline) or just as expression snippets
        (with nothing extra). The containing types will set this value
        as appropriate when they are visited (before their children), and
        should restore the original value when done.
        '''
        return self._statement_mode_stack[-1]

    def visit_ArraySubscriptExpr(self, arrexpr:ASTNode):
        return f'{self.visit(arrexpr.inner[0])}[{self.visit(arrexpr.inner[1])}]'

    def visit_BinaryOperator(self, binop:ASTNode):
        code = ''
        if len(binop.inner) < 2:
            operand = self.visit(binop.inner[0]) if binop.inner else 'NO_OPERAND'
            line = f'/* TODO: only {len(binop.inner)} operands for {binop.kind} "{binop.opcode}" (operand={operand}) */'
            code += self._emit_line(line) if self.statement_mode else line
            return code

        if self.statement_mode:
            code += self._start_line()

        # do this unconditionally to allow restoring modes below
        self.push_statement_mode(False)
        # the raw expression part
        code += self.visit(binop.inner[0])
        code += f' {binop.opcode} '
        self._suppress_indent()     # we don't want the RHS indented like a line!
        code += self.visit(binop.inner[1])
        self._unsuppress_indent()
        # restore original mode
        self.pop_statement_mode()

        if self.statement_mode:
            code += self._end_line(';')

        return code

    def visit_BreakStmt(self, bstmt:ASTNode):
        return self._emit_line('break;')

    def visit_BuiltinType(self, bit:ASTNode):
        return bit.name

    def visit_CallExpr(self, expr:ASTNode):
        # fname = expr.inner[0].referencedDecl.name

        self.push_statement_mode(False)
        args = [self.visit(node) for node in expr.inner[1:]]
        self.pop_statement_mode()

        call_expr = f'{self.visit(expr.inner[0])}({", ".join(args)})'
        return self._emit_line(f'{call_expr};') if self.statement_mode else call_expr

    def visit_CaseStmt(self, cs:ASTNode):
        self.push_statement_mode(False)
        code = self._emit_line(f'case {self.visit(cs.inner[0])}:')
        self.pop_statement_mode()

        self.push_statement_mode(True)
        self._indent()
        code += ''.join(self.visit(node) for node in cs.inner[1:])
        self._unindent()
        self.pop_statement_mode()
        return code

    def visit_CharacterLiteral(self, lit:ASTNode):
        return repr(chr(lit.value))

    def visit_CompoundStmt(self, stmt:ASTNode):
        self.push_statement_mode(True)
        code = ''.join(self.visit(node) for node in stmt.inner)
        self.pop_statement_mode()
        return code

    def visit_ConstantArrayType(self, arrtype:ASTNode):
        if self._use_ptr_not_array:
            return f'{self.visit(arrtype.inner[0])}*'
        else:
            code = self.visit(arrtype.inner[0])
            if self._within_var_decl:
                # save this for printing AFTER the identifier
                self._num_vdecl_arr_elements = arrtype.num_elements
            else:
                code += f'[{arrtype.num_elements}]'
            return code

    def visit_ConstantExpr(self, cexpr:ASTNode):
        return self.visit(cexpr.inner[0])

    def visit_CStyleCastExpr(self, expr:ASTNode):
        # I think I should be able to call visit() here, but for now I don't have enough
        # types implemented on Ghidra side for this to work...
        return f'({expr.dtype}){self.visit(expr.inner[0])}'
        # return f'({expr.dtype_name}){self.visit(expr.inner[0])}'

    def visit_DeclRefExpr(self, refexpr:ASTNode):
        return f'{refexpr.referencedDecl.name}'

    def visit_DeclStmt(self, stmt:ASTNode):
        self.push_statement_mode(False)
        code = self._emit_line(f'{self.visit(stmt.inner[0])};')
        self.pop_statement_mode()
        return code

    def visit_DefaultStmt(self, ds:ASTNode):
        code = self._emit_line('default:')

        self.push_statement_mode(True)
        self._indent()
        code += ''.join(self.visit(node) for node in ds.inner)
        self._unindent()
        self.pop_statement_mode()
        return code

    def visit_DoStmt(self, dostmt:ASTNode):
        code = self._emit_line('do {')

        self.push_statement_mode(True)
        self._indent()
        code += self.visit(dostmt.inner[0])
        self._unindent()
        self.pop_statement_mode()

        self.push_statement_mode(False)
        code += self._emit_line(f'}} while ({self.visit(dostmt.inner[1])});')
        self.pop_statement_mode()
        return code

    def visit_EnumDecl(self, edecl:ASTNode):
        code = self._emit_line(f'enum {edecl.name} {{')
        self._indent()
        for enumconst in edecl.inner:
            code += self._emit_line(f'{self.visit(enumconst)} = {enumconst.value},')
        self._unindent()
        code += self._emit_line('};')
        return code

    def visit_EnumConstantDecl(self, ec:ASTNode):
        return ec.name

    def visit_EnumType(self, etype:ASTNode):
        return f'enum {etype.name}'

    def visit_FieldDecl(self, field:ASTNode):
        self._within_var_decl = True

        is_funcptr = self.isFuncptr(field.dtype)
        if is_funcptr or field.dtype.kind == 'FunctionType':
            # function pointer case - we need to tell FunctionType the name of
            # this variable and let it do the printing because of C "spiral" syntax
            self._current_varname = field.name
            code = self._start_line(f'{self.visit(field.dtype)}')
        else:
            code = self._start_line(self.visit(field.dtype))
            code += f' {field.name}'

        nelem = self._num_vdecl_arr_elements
        arr_size = f'[{nelem}]' if nelem is not None else ''
        code += self._end_line(f'{arr_size};')

        # return self._emit_line(f'{self.visit(field.dtype)} {field.name};')

        # reset state
        self._num_vdecl_arr_elements = None
        self._within_var_decl = False
        self._current_varname = None
        return code

    def visit_FloatingLiteral(self, lit:ASTNode):
        return lit.special_value if lit.special_value else f'{lit.value}'

    def visit_ForStmt(self, forstmt:ASTNode):
        init_stmt = forstmt.inner[0] if forstmt.inner[0].kind != 'NullNode' else None
        cond_stmt = forstmt.inner[1] if forstmt.inner[1].kind != 'NullNode' else None
        increment_stmt = forstmt.inner[2] if forstmt.inner[2].kind != 'NullNode' else None
        loop_body = forstmt.inner[3] if forstmt.inner[3].kind != 'NullNode' else None

        # emit "for () {" line with statement mode off
        self.push_statement_mode(False)
        init_str = self.visit(init_stmt) if init_stmt else ''
        cond_str = self.visit(cond_stmt) if cond_stmt else ''
        increment_str = self.visit(increment_stmt) if increment_stmt else ''
        code = self._emit_line(f'for ({init_str}; {cond_str}; {increment_str}) {{')
        self.pop_statement_mode()

        self._indent()
        code += self.visit(loop_body) if loop_body else ''
        self._unindent()
        code += self._emit_line('}')

        return code

    def visit_FunctionDecl(self, fdecl:ASTNode):
        params = [x for x in fdecl.inner if x.kind == 'ParmVarDecl']
        fbody = [x for x in fdecl.inner if x not in params]

        # this implementation skips emitting the prototype for the
        # function with a body. We can move this check down to change that if desired
        # (this is the code that generates the fwd-decls for Ghidra C code)
        if fbody and self.header_only:
            return ''

        # turn off arrays for parameter list
        # TODO: turn this back on if/when I want to print non-validation version
        # if self.validation_mode:
        self._use_ptr_not_array = True
        param_strlist = []
        for p in params:
            if self.isFuncptr(p.dtype):
                self._current_varname = p.name
                param_strlist.append(self.visit(p.dtype))
            else:
                param_strlist.append(f'{self.visit(p.dtype)} {p.name}')

        # if self.validation_mode:
        self._use_ptr_not_array = False

        param_str = ', '.join(param_strlist)
        if self.validation_mode and not fbody:
            # when exporting header for Ghidra C code we want to omit prototype in
            # fwd decls so clang doesn't error out because functions are called with
            # wrong #'s of arguments
            param_str = ''

        semicolon = ';' if self.header_only or not fbody else ''
        func_proto = f'{fdecl.return_dtype} {fdecl.name}({param_str}){semicolon}'

        code = self._emit_line(func_proto)

        if fbody:
            code += self._emit_line('{')
            self._indent()
            for node in fbody:
                code += self.visit(node)
            self._unindent()
            code += self._emit_line('}')
        return code

    def visit_FunctionType(self, ftype:ASTNode):
        is_fptr = ftype.parent.kind == 'PointerType'
        fname = self._current_varname if self._current_varname else 'TODO_SET_CURRENT_VARNAME'
        param_str = ','.join(self.visit(x) for x in ftype.inner)
        if is_fptr:
            if self.isFuncptr(ftype.return_dtype):
                # do this for now to avoid generating "spiral" syntax...
                return f'void* /*RETURNS FPTR*/ (*{fname})({param_str})'
            return f'{self.visit(ftype.return_dtype)} (*{fname})({param_str})'
        return f'{self.visit(ftype.return_dtype)} {fname}({param_str})'

    def visit_GotoStmt(self, gtstmt:ASTNode):
        return self._emit_line(f'goto {gtstmt.label_name};')

    def visit_IfStmt(self, stmt:ASTNode):
        self.push_statement_mode(False)
        code = self._emit_line(f'if ({self.visit(stmt.inner[0])}) {{')
        self.pop_statement_mode()

        self.push_statement_mode(True)
        self._indent()
        code += self.visit(stmt.inner[1])
        self._unindent()

        if len(stmt.inner) > 2:
            code += self._emit_line('} else {')
            self._indent()
            code += self.visit(stmt.inner[2])
            self._unindent()
            code += self._emit_line('}')
        else:
            code += self._emit_line('}')
        self.pop_statement_mode()

        return code

    def visit_IntegerLiteral(self, lit:ASTNode):
        return f'{lit.value}'

    def visit_LabelStmt(self, label:ASTNode):
        # don't indent this on purpose
        code = self._end_line(f'{label.name}:')
        if label.inner:
            code += self.visit(label.inner[0])
        return code

    def visit_MemberExpr(self, memexpr:MemberExpr):
        token = '->' if memexpr.is_arrow else '.'
        return f'{self.visit(memexpr.inner[0])}{token}{memexpr.name}'

    def visit_NullNode(self, node:ASTNode):
        return ''

    def visit_ParenExpr(self, expr:ASTNode):
        return f'({self.visit(expr.inner[0])})'

    def visit_PointerType(self, pt:ASTNode):
        if pt.inner[0].kind == 'FunctionType':
            # don't add anything, FunctionType will handle the whole thing
            return self.visit(pt.inner[0])
        return f'{self.visit(pt.inner[0])}*'

    def visit_RecordDecl(self, rd:ASTNode):
        if not rd.inner:
            if _VALIDATION_MODE:
                return self._emit_line(f'typedef struct {rd.name} {rd.name};')
            return self._emit_line(f'struct {rd.name} {rd.name};')
        struct_start = 'typedef ' if _VALIDATION_MODE else ''
        struct_end = f' {rd.name}' if _VALIDATION_MODE else ''
        code = self._emit_line(f'{struct_start}struct {rd.name}')
        code += self._emit_line('{')
        self._indent()
        code += ''.join(self.visit(field) for field in rd.inner)
        self._unindent()
        code += self._emit_line(f'}}{struct_end};')
        return code
        # import IPython; IPython.embed()

    def visit_ReturnStmt(self, rs:ASTNode):
        if rs.inner:
            return self._emit_line(f'return {self.visit(rs.inner[0])};')
        else:
            return self._emit_line(f'return;')

    def visit_StringLiteral(self, strlit:ASTNode):
        return strlit.value

    def visit_StructType(self, stype:ASTNode):
        return stype.name if _VALIDATION_MODE else f'struct {stype.name}'

    def visit_SwitchStmt(self, ss:ASTNode):
        self.push_statement_mode(False)
        code = self._emit_line(f'switch ({self.visit(ss.inner[0])}) {{')
        self.pop_statement_mode()

        self.push_statement_mode(True)
        self._indent()
        code += self.visit(ss.inner[1])
        self._unindent()
        self.pop_statement_mode()

        code += self._emit_line('}')
        return code

    def visit_TranslationUnitDecl(self, tudecl:TranslationUnitDecl):
        self.push_statement_mode(True)  # anything below this is a standalone statement or block
        return ''.join(self.visit(child) for child in tudecl.inner)

    def visit_Type(self, typenode:ASTNode):
        return typenode.name

    def visit_TypedefDecl(self, tddecl:ASTNode):
        return self._emit_line(f'typedef {tddecl.inner[0].name} {tddecl.name};')

    def visit_TypedefType(self, tdtype:ASTNode):
        return tdtype.name

    def visit_UnaryOperator(self, unop:ASTNode):
        return f'{unop.opcode}{self.visit(unop.inner[0])}'

    def isFuncptr(self, dtype:ASTNode):
        if dtype.kind == 'PointerType':
            while dtype.kind == 'PointerType':  # walk through pointer layers...
                dtype = dtype.inner[0]
            return dtype.kind == 'FunctionType'
        return False

    def visit_VarDecl(self, vdecl:ASTNode):
        self._within_var_decl = True
        line_end = ';\n' if self.statement_mode else ''
        code = ''

        if self.statement_mode:
            code += self._start_line()

        if isinstance(vdecl.dtype, PointerType) and isinstance(vdecl.dtype.pointed_to, FunctionType):
            code += f'{vdecl.dtype.pointed_to.str_with_varname(vdecl.name)}{line_end}'
        else:
            nelem = self._num_vdecl_arr_elements
            arr_size = f'[{nelem}]' if nelem is not None else ''
            code += f'{vdecl.dtype} {vdecl.name}{arr_size}{line_end}'

        # reset state
        self._current_varname = None
        self._num_vdecl_arr_elements = None
        self._within_var_decl = False
        return code

    def visit_VoidType(self, vt:ASTNode):
        return "void"

    def visit_WhileStmt(self, ws:ASTNode):
        self.push_statement_mode(False)
        code = self._emit_line(f'while ({self.visit(ws.inner[0])}) {{')

        self.push_statement_mode(True)
        self._indent()
        code += self.visit(ws.inner[1])
        self._unindent()
        self.pop_statement_mode()

        code += self._emit_line('}')
        self.pop_statement_mode()
        return code

def print_ast(ast:ASTNode, outfile:Path=None, header_only:bool=False, validation_mode:bool=False):
    # try printing out the C syntax...for where I am right now this might help
    # quickly identify what is missing/wrong
    c_code = PrintASTVisitor(header_only, validation_mode=validation_mode).convert_ast_to_code(ast)
    if outfile:
        with open(outfile, 'w') as f:
            f.write(c_code)
    else:
        print(c_code)
    # import IPython; IPython.embed()
    return 0

def main():
    p = argparse.ArgumentParser(description='Print AST JSON as C code')
    p.add_argument('json_file', help='JSON AST file to convert to code')
    p.add_argument('--header-only', action='store_true',
        help='Only print forward-declarations and typedefs, no function body code')
    p.add_argument('-o', '--outfile', help='Write to this output filename instead of printing to stdout')
    args = p.parse_args()
    ast = read_json(args.json_file)
    exit(print_ast(ast, args.outfile, args.header_only))

if __name__ == '__main__':
    main()
