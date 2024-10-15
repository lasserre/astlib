import argparse
from pathlib import Path
import json
from typing import Dict, List

# from ..ast import ASTNode, dict_to_ast
# from ..astvisitor import ASTVisitor
from astlib import *
from varlib.datatype import *

_var_lookup = {}

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

def print_ast(ast:ASTNode, outfile:Path=None, header_only:bool=False, validation_mode:bool=False):
    if outfile:
        with open(outfile, 'w') as f:
            f.write(ast.c_code_str(header_only, validation_mode))
    else:
        ast.print(header_only, validation_mode)
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
