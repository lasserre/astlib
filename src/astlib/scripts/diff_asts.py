import argparse
import json
import os
from pathlib import Path
import traceback
from typing import List
import subprocess

from astlib import ASTVisitor, ASTNode
from astlib.scripts.run_validation import KNOWN_LIB_FUNCS

TYPEDEFS_TO_DELETE = [
    '__int128_t',
    '__uint128_t',
    '__NSConstantString',
    '__builtin_ms_va_list',
    '__builtin_va_list',
    'size_t',
]

# :: (scope), . (object member), -> (pointer member), *, +, &, ^, |, ',' (comma), | (enum cat)
BAD_BINOP_TOKENS = [
    # these are included, I just want to wait and see if they cause a problem first
    '::', '.', '->',
    '*', '+', '&', '^', '|', ','
]

class GhidraASTTransformer:
    '''Mirror to ClangASTTransformer for constructs I had to handle in my AST'''
    def __init__(self, compound_only:bool=False, nullparens_only:bool=False) -> None:
        self.delete_current_node = False    # set this to short-circuit and delete current node
        self.compound_only = compound_only
        self.nullparens_only = nullparens_only

    def visit(self, node:dict):
        self.process_node_type(node)
        if self.delete_current_node:
            # can't do it here - return now and keep flag set to indicate this
            return

        children_to_delete = []

        if 'inner' in node:
            for child in node['inner']:
                self.visit(child)
                if self.delete_current_node:
                    children_to_delete.append(child)
                    self.delete_current_node = False    # reset flag

            # delete any children we requested to delete
            node['inner'] = [x for x in node['inner'] if x not in children_to_delete]

    def process_node_type(self, node:dict):
        if 'kind' not in node:
            node['kind'] = 'NullNode'

        if self.compound_only:
            if node['kind'] == 'CompoundStmt':
                self.visit_CompoundStmt(node)
        elif self.nullparens_only:
            if node['kind'] == 'ParenExpr':
                self.visit_ParenExpr(node)
        else:
            # general-purpose
            if node['kind'] == 'BinaryOperator':
                self.visit_BinaryOperator(node)
            elif node['kind'] == 'CompoundStmt':
                self.visit_CompoundStmt(node)
            # elif node['kind'] == 'MemberExpr':
            #     self.visit_MemberExpr(node)

    def visit_BinaryOperator(self, binop:dict):
        # this is the Ghidra AST (my AST export) version of the binary operator
        # problem described below
        # here, we are looking for either
        #       + parent -> + child
        # OR
        #       + parent -> PAREN child -> + child
        # since our code will insert PARENs in the a + (b + c) case

        # ALSO:
        # in general - replace all ParenExpr children by their child node
        # to get rid of parens within BinaryOperators (Ghidra and I just don't agree...lol)

        parent_op = binop['opcode']
        if parent_op in BAD_BINOP_TOKENS:
            for child in binop['inner']:
                # + parent -> + child case
                if child['kind'] == 'BinaryOperator' and child['opcode'] == parent_op:
                    # whack this subtree starting at parent
                    binop.clear()
                    binop['kind'] = 'NullNode'
                    return
                # + parent -> PAREN child -> + child case
                elif child['kind'] == 'ParenExpr':
                    grandchild = child['inner'][0]
                    if grandchild['kind'] == 'BinaryOperator' and grandchild['opcode'] == parent_op:
                        binop.clear()
                        binop['kind'] = 'NullNode'
                        return

        for child in binop['inner']:
            if child['kind'] == 'ParenExpr':
                paren_child = child['inner'][0] if child['inner'] else {'kind': 'NullNode'}
                child.clear()
                child.update(paren_child)

    def visit_CompoundStmt(self, cmpd:dict):
        # see comment in ClangASTTransformer
        # we have to take the same action here so that validation matches
        #
        # for validation, if we see a CompoundStmt with 1 child let's remove the
        # wrapping CompoundStmt
        if len(cmpd['inner']) == 1:
            child = cmpd['inner'][0]
            cmpd.clear()
            cmpd.update(child)  # put child up a level where CompoundStmt was

    def visit_ParenExpr(self, parenexpr:dict):
        if parenexpr['inner'] and parenexpr['inner'][0]['kind'] == 'NullNode':
            nullnode = parenexpr['inner'][0]
            parenexpr.clear()
            parenexpr.update(nullnode)

# map binary operators to precedence levels
# - HIGHEST precedence is the smallest number (1)
# - LOWEST precedence is the biggest number (17)
REAL_PRECEDENCE_RULES = {
    '==': 10,
    '!=': 10,
    '&&': 14,
    '||': 15,
}

class EnsureKindKeyPresent:
    def __init__(self) -> None:
        pass

    def visit(self, node:dict):
        if 'kind' not in node:
            node['kind'] = 'NullNode'

        if 'inner' in node:
            for child in node['inner']:
                self.visit(child)

class ClangASTTransformer:
    '''Artifacts specific to Clang's AST we wish to reduce/eliminate before diffing against our AST'''
    def __init__(self, compound_only:bool=False, recovery_only:bool=False) -> None:
        self.delete_current_node = False    # set this to short-circuit and delete current node
        self.visit_counts = {}  # map kind -> count
        self.compound_only = compound_only
        self.recovery_only = recovery_only
        # list of indices needed to address the current node starting from root node
        # and indexing into each node's inner array sequentially
        self.current_node_address = []
        self.recovery_node_addresses = []   # list of addresses

    def print_visit_counts(self):
        for kind, count in self.visit_counts.items():
            print(f'{kind}: {count} visits')

    def keep_transl_unit_child(self, node:dict):
        # filter out:
        # - RecordDecl's with the name _GUID (clang generates these)
        if node['kind'] == 'RecordDecl' and node['name'] == '_GUID':
            return False
        return True

    def visit(self, node:dict):
        kind = node['kind']
        if kind in self.visit_counts:
            self.visit_counts[kind] += 1
        else:
            self.visit_counts[kind] = 1

        self.process_node_type(node)
        if self.delete_current_node:
            # can't do it here - return now and keep flag set to indicate this
            return

        children_to_delete = []

        if 'inner' in node:
            for i, child in enumerate(node['inner']):
                self.current_node_address.append(i)
                self.visit(child)
                self.current_node_address.pop()
                if self.delete_current_node:
                    children_to_delete.append(child)
                    self.delete_current_node = False    # reset flag

            # delete any children we requested to delete
            node['inner'] = [x for x in node['inner'] if x not in children_to_delete]

    def process_node_type(self, node:dict):
        if self.compound_only:
            if node['kind'] == 'CompoundStmt':
                self.visit_CompoundStmt(node)
        elif self.recovery_only:
            if node['kind'] == 'RecoveryExpr':
                self.visit_RecoveryExpr(node)
            # yes this is not recovery, but need to handle similarly...
            elif node['kind'] == 'CXXDependentScopeMemberExpr':
                self.visit_CXXDependentScopeMemberExpr(node)
        else:
            # general-purpose
            if node['kind'] == 'BinaryOperator':
                self.visit_BinaryOperator(node)
            elif node['kind'] == 'BuiltinType':
                self.visit_BuiltinType(node)
            elif node['kind'] == 'CompoundStmt':
                self.visit_CompoundStmt(node)
            elif node['kind'] == 'EnumConstantDecl':
                self.visit_EnumConstantDecl(node)
            elif node['kind'] == 'ForStmt':
                self.visit_ForStmt(node)
            elif node['kind'] == 'MemberExpr':
                self.visit_MemberExpr(node)
            elif node['kind'] == 'SwitchStmt':
                self.visit_SwitchStmt(node)
            elif node['kind'] == 'TranslationUnitDecl':
                self.visit_TranslationUnitDecl(node)
            elif node['kind'] == 'TypedefDecl':
                self.visit_TypedefDecl(node)
            elif node['kind'] == 'WhileStmt':
                self.visit_WhileStmt(node)

    def visit_BinaryOperator(self, binop:dict):
        # Ok...this is going to reduce the amount of AST we are validating but
        # it's the only way to get around this Ghidra bug.
        # Ghidra's associativity is wrong for binary operators if you have
        # this construct in pcode: a + (b + c)
        #
        # Ghidra will generate: "a + b + c" which parses to: (a + b) + c
        # due to left-associativity, or:
        # +
        #   +
        #     a
        #     b
        #   c
        #
        # my code (correctly I believe) generates: a + (b + c) or:
        # +
        #   a
        #   ParenExpr
        #     +
        #       b
        #       c
        #
        # the logic in Ghidra that generates this bug is in bool PrintLanguage::parentheses(const OpToken *op2)
        # under OpToken::binary case, they have: if (topToken->associative && (topToken == op2)) return false;
        # which corresponds to the tokens:
        # :: (scope), . (object member), -> (pointer member), *, +, &, ^, |, ',' (comma), | (enum cat)
        #
        # so to avoid this headache and move on, I am going to remove the subtrees where this case
        # occurs (on both sides). If the actual code corresponds to (a + b) + c, we will both
        # correctly generate "a + b + c"...but if the actual code is a + (b + c), I will generate
        # that and Ghidra will generate the wrong version with no parens. Since I can't tell on
        # Ghidra's side I will simply remove both cases...whenever there is a nested binary operator
        # of the same kind (e.g. + parent -> + child)
        parent_op = binop['opcode']
        if parent_op in BAD_BINOP_TOKENS:
            for child in binop['inner']:
                if child['kind'] == 'BinaryOperator' and child['opcode'] == parent_op:
                    # whack this subtree starting at parent
                    binop.clear()
                    binop['kind'] = 'NullNode'
                    return

        # in general - replace all ParenExpr children by their child node
        # to get rid of parens within BinaryOperators (Ghidra and I just don't agree...lol)
        for child in binop['inner']:
            while child['kind'] == 'ParenExpr':
                paren_child = child['inner'][0] if child['inner'] else {'kind': 'NullNode'}
                child.clear()
                child.update(paren_child)

        # below this is OLD CODE I SHOULD NOT NEED because I now emit the unnecessary
        # parens and match Ghidra. If this continue to work then delete code below
        return

        # second check: || -> () -> ==
        # these parens are unneccessary as == is higher precedence
        if parent_op in REAL_PRECEDENCE_RULES:
            parent_precedence = REAL_PRECEDENCE_RULES[parent_op]
            for child in binop['inner']:
                if child['kind'] == 'ParenExpr':
                    grandchild = child['inner'][0]
                    if grandchild['kind'] == 'BinaryOperator':
                        grand_op = grandchild['opcode']
                        if grand_op in REAL_PRECEDENCE_RULES:
                            grand_precedence = REAL_PRECEDENCE_RULES[grand_op]
                            # if child is a HIGHER precedence (smaller magnitude) remove parens
                            if grand_precedence < parent_precedence:
                                # remove parens node
                                child.clear()   # clear parens dict
                                child.update(grandchild)    # put BinaryOperator up a level where parens dict was

    def visit_BuiltinType(self, bit:dict):
        # move this string to bit.name so it compares properly
        bit['name'] = bit['type']['qualType']

    def visit_CompoundStmt(self, cmpd:dict):
        # this may or may not be a problem in general, but at least for IfStmt's
        # I've noticed clang apparently behaves inconsistently about if it wraps
        # a single statement in a CompoundStmt or not.
        # for validation, if we see a CompoundStmt with 1 child let's remove the
        # wrapping CompoundStmt
        if 'inner' in cmpd and len(cmpd['inner']) == 1:
            child = cmpd['inner'][0]
            cmpd.clear()
            cmpd.update(child)  # put child up a level where CompoundStmt was

    def visit_EnumConstantDecl(self, ecdecl:dict):
        if 'inner' in ecdecl:
            # having an expression (as clang does) is more robust/correct, but
            # Ghidra doesn't generate code with expressions like that - we just
            # have the values
            del ecdecl['inner']

    def visit_ForStmt(self, forstmt:dict):
        # CLANG inner corresponds to: { INIT, CONDVAR, COND, INC, BODY, END_EXPR };
        #   - I think CONDVAR is if you have for (int i = 0; i <...) then i is a
        #     NEWLY-DECLARED condition variable.
        # my version is: INIT, COND, INC, BODY
        #   - so let's remove the CONDVAR from CLANG for validation
        # del forstmt['inner'][1]     # delete CONDVAR entry
        # forstmt['inner'].pop(1)     # delete CONDVAR entry
        new_inner = []
        for i, child in enumerate(forstmt['inner']):
            if i == 1:
                continue
            if child['kind'] == 'ParenExpr':
                paren_child = child['inner'][0] if child['inner'] else {'kind': 'NullNode'}
                new_inner.append(paren_child)
            else:
                new_inner.append(child)
        forstmt['inner'] = new_inner

    def visit_MemberExpr(self, member:dict):
        if member['inner'] and member['inner'][0]['kind'] == 'ParenExpr':
            parenexpr = member['inner'][0]
            paren_child = parenexpr['inner'][0]
            member['inner'] = [paren_child]     # remove ParenExpr

    def visit_CXXDependentScopeMemberExpr(self, cxx:dict):
        if 'inner' in cxx:
            cxx['inner'].clear()
        # piggyback off RecoveryExpr processing...
        cxx['kind'] = 'RecoveryExpr'
        self.recovery_node_addresses.append(self.current_node_address.copy())

    def visit_RecoveryExpr(self, recov:dict):
        # zero out this node's inner member
        if 'inner' in recov:
            recov['inner'].clear()

        # save off the "node address" of this node so GhidraAST can
        # make it a RecoveryExpr and zero out its node
        #
        # node address: [0,2,2,1,3,1,5]
        #
        # corresponds to the inner index for each level beginning from top
        # translation unit!
        # (have to maintain this for each node as we go...current_node_address)
        #
        # then we return recovery_addrs list and we really don't even need
        # to use a visitor to fix those (just go through the list and fix them)
        self.recovery_node_addresses.append(self.current_node_address.copy())

    def visit_SwitchStmt(self, ss:dict):
        cmpd_stmt = ss['inner'][1]
        if cmpd_stmt['kind'] != 'CompoundStmt':
            return

        case_idxs = []
        for i, node in enumerate(cmpd_stmt['inner']):
            if node['kind'] == 'CaseStmt' or node['kind'] == 'DefaultStmt':
                case_idxs.append(i)

        # everything between CaseStmts should be moved underneath its parent case
        if case_idxs and len(case_idxs) < 2:
            i = case_idxs[0]
            if cmpd_stmt['inner'][i+1:]:
                # there are children to be put underneath here
                case_stmt = cmpd_stmt['inner'][i]
                # move tail underneath case statement
                tail = cmpd_stmt['inner'][i+1:]
                case_stmt['inner'].extend(tail)
                cmpd_stmt['inner'] = cmpd_stmt['inner'][:i+1]
        elif case_idxs:
            # general case >= 2

            # list of (case idx, stop idx)
            # for each entry, we want to move code from [case idx+1, stop idx+1] underneath
            # the case idx node
            code_moves = []

            for i in range(0,len(case_idxs)-1):
                idx = case_idxs[i]
                next_idx = case_idxs[i+1]
                if next_idx > (idx + 1):
                    code_moves.append((idx, next_idx))

            # handle final case
            if case_idxs[-1] < (len(cmpd_stmt['inner']) - 1):
                code_moves.append((case_idxs[-1], len(cmpd_stmt['inner'])))

            # go in reverse so idxs still work as the list shrinks
            code_moves.reverse()
            for case_i, stop_i in code_moves:
                node_range = cmpd_stmt['inner'][case_i+1:stop_i]
                first_part = cmpd_stmt['inner'][:case_i+1]
                last_part = cmpd_stmt['inner'][stop_i:]
                cmpd_stmt['inner'] = [*first_part, *last_part]
                cmpd_stmt['inner'][case_i]['inner'].extend(node_range)

    def visit_TranslationUnitDecl(self, tudecl:dict):
        tudecl['inner'] = [n for n in tudecl['inner'] if self.keep_transl_unit_child(n)]

    def visit_TypedefDecl(self, tddecl:dict):
        pass
        # HACK: trying to disable this first...
        # if tddecl['name'] in TYPEDEFS_TO_DELETE:
        #     self.delete_current_node = True

    def visit_WhileStmt(self, ws:dict):
        if ws['inner'] and ws['inner'][0]['kind'] == 'ParenExpr':
            paren = ws['inner'][0]
            paren_child = paren['inner'][0] if paren['inner'] else {'kind': 'NullNode'}
            ws['inner'] = [paren_child, *ws['inner'][1:]]

def get_node_at_address(address:List[int], root_node:dict):
    node = root_node
    for idx in address:
        node = node['inner'][idx]
    return node

def diff_asts(args):
    # 1. reduce the dictionaries to keys/values we want to compare
    # 2. write them out to files
    # 3. directly diff the output files

    ghidra_ast = {}
    clang_ast = {}

    with open(args.ghidra_ast) as ghidra_file:
        ghidra_ast = json.load(ghidra_file)
    with open(args.clang_ast) as clang_file:
        clang_ast = json.load(clang_file)

    def reduce_dict(d:dict, keep_keys:List[str], remove_kinds:List[str]=None,
                    collapse_kinds:List[str]=None) -> dict:
        newdict = {k: v for k, v in d.items() if k in keep_keys}
        if 'inner' in d and len(d['inner']):
            if remove_kinds:
                keep_nodes = [n for n in d['inner'] if n['kind'] not in remove_kinds]
            else:
                keep_nodes = d['inner']
                # [reduce_dict(node, keep_keys, remove_kinds) for node in d['inner'] if node['kind'] not in remove_kinds]

            replacements = {}   # int -> node
            if collapse_kinds:
                for i, n in enumerate(keep_nodes):
                    if n['kind'] in collapse_kinds:
                        # want to put n.inner in n's place
                        replacements[i] = n     # seed loop w/ initial node
                        while replacements[i]['kind'] in collapse_kinds:
                            nn = replacements[i]
                            if 'inner' in nn:
                                if len(nn['inner']) == 1:
                                    replacements[i] = nn['inner'][0]
                                elif len(nn['inner']) == 0:
                                    continue
                                else:
                                    print(f'>1 child inside {nn["kind"]} node! not collapsing...')
                            else:
                                replacements[i] = None
                                break

            for k, v in replacements.items():
                keep_nodes[k] = v

            newdict['inner'] = [reduce_dict(n, keep_keys, remove_kinds, collapse_kinds) for n in keep_nodes]
            if not newdict['inner']:
                newdict.pop('inner', None)  # remove empty inner lists
        return newdict

    # ----------- FIRST PASS: reduce to "kind" only to compare structure
    keep_keys = ['kind', 'name', 'opcode']

    EnsureKindKeyPresent().visit(clang_ast)
    EnsureKindKeyPresent().visit(ghidra_ast)

    # if we don't collapse ImplicitCastExpr's first, it breaks the logic I have
    # for a few special cases by getting in-between parents and children nodes
    clang_reduced = reduce_dict(clang_ast, keep_keys,
        collapse_kinds=[
            'ImplicitCastExpr'
        ])

    # the transformation we apply to CompoundStatements (where we replace
    # CompoundStatments with only 1 child with their child node) causes some
    # nodes to NOT be visited if it is all done in 1 pass.
    # so do CompoundStmt first, then do everything
    ClangASTTransformer(compound_only=True).visit(clang_ast)

    clangTx2 = ClangASTTransformer()
    clangTx2.visit(clang_ast)  # transform clang-specific constructs
    # clangTx2.print_visit_counts()

    # do the same with GhidraASTTransformer for consistency
    GhidraASTTransformer(compound_only=True).visit(ghidra_ast)
    GhidraASTTransformer().visit(ghidra_ast)    # transform ghidra-specific constructs

    clang_reduced = reduce_dict(clang_ast, keep_keys,
        remove_kinds=[
            'FullComment',
            # 'TypedefDecl',
            'CXXRecordDecl',    # don't include for now
        ])
    ghidra_reduced = reduce_dict(ghidra_ast, keep_keys)

    # ----------- SECOND PASS: EXTRA GHIDRA (AST) STEPS
    # extra ghidra (my AST) reduction steps
    for child in ghidra_reduced['inner']:
        if child['kind'] == 'FunctionDecl':
            # reduce_dict() removes empty inner lists (to simplify comparison) so
            # have to check for presence of 'inner' here too...normally it's always present
            # even if empty
            has_body = [x for x in child['inner'] if x['kind'] != 'ParmVarDecl'] if 'inner' in child else False
            if not has_body and 'inner' in child:
                # this is a forward-decl function - erase all the params
                # to get an empty prototype
                child.pop('inner')

            if child['name'] in KNOWN_LIB_FUNCS:
                # match what we did on Ghidra side in rename_known_library_funcs
                child['name'] += '_SUFFIX'

    # remove initial typedefs for validation
    # (had issues with these exactly matching due to clang parse...it does not
    # matter for validation purposes)
    remove_idx = None
    for i, child in enumerate(ghidra_reduced['inner']):
        if child['name'] == 'REMOVE_EVERYTHING_ABOVE_THIS_IN_JSON':
            remove_idx = i
            break
    ghidra_reduced['inner'] = ghidra_reduced['inner'][remove_idx+1:]

    # ----------- SECOND PASS: EXTRA CLANG (GHIDRA C CODE) STEPS
    # remove initial typedefs for validation
    # (had issues with these exactly matching due to clang parse...it does not
    # matter for validation purposes)
    remove_idx = None
    for i, child in enumerate(clang_reduced['inner']):
        if child['name'] == 'REMOVE_EVERYTHING_ABOVE_THIS_IN_JSON':
            remove_idx = i
            break
    clang_reduced['inner'] = clang_reduced['inner'][remove_idx+1:]

    child_idxs_to_del = []

    for i, child in enumerate(clang_reduced['inner']):
        if child['kind'] == 'TypedefDecl':
            tdchild = child['inner'][0]
            if tdchild['kind'] == 'ElaboratedType':
                if tdchild['inner'][0]['kind'] == 'RecordType':
                    # remove child
                    child_idxs_to_del.append(i)
                    continue
    # go in reverse order since deleting later idx's doesn't affect
    # the previous idx's we still have to delete
    child_idxs_to_del.reverse()
    for idx in child_idxs_to_del:
        del clang_reduced['inner'][idx]

    # recovery node processing
    clangTx3 = ClangASTTransformer(recovery_only=True)
    clangTx3.visit(clang_reduced)
    recov_nodes = clangTx3.recovery_node_addresses

    for addr in recov_nodes:
        try:
            node = get_node_at_address(addr, ghidra_reduced)
        except:
            # have to skip this one, something doesn't line up
            continue
        node.clear()
        node['kind'] = 'RecoveryExpr'
        node['inner'] = []

    # null parens
    # GhidraASTTransformer(nullparens_only=True).visit(ghidra_ast)

    clang_filepath = Path(args.clang_ast)
    ghidra_filepath = Path(args.ghidra_ast)

    validation_folder = ghidra_filepath.parent/'validation'
    if not validation_folder.exists():
        os.mkdir(validation_folder)

    clang_reduced_filename = validation_folder/(clang_filepath.name + '.CLANG_REDUCED.json')
    ghidra_reduced_filename = validation_folder/(ghidra_filepath.name + '.GHIDRA_REDUCED.json')

    with open(clang_reduced_filename, 'w') as clang_out:
        json.dump(clang_reduced, clang_out, indent=2)
    with open(ghidra_reduced_filename, 'w') as ghidra_out:
        json.dump(ghidra_reduced, ghidra_out, indent=2)

    if args.bc:
        subprocess.run(['bcompare.exe', ghidra_reduced_filename, clang_reduced_filename])
        return 0

    return subprocess.call(['BComp.com', '/qc', ghidra_reduced_filename, clang_reduced_filename])

    # import IPython; IPython.embed()

def main():
    p = argparse.ArgumentParser(description='Diff Ghidra-exported AST against Clang AST')
    p.add_argument('ghidra_ast', help='Ghidra direct AST export (json file)')
    p.add_argument('clang_ast', help='Clang AST dump (json file)')
    p.add_argument('--bc', action='store_true', help='Run beyond compare (dont use this if you just need to refresh the BC window)')
    args = p.parse_args()
    try:
        rcode = diff_asts(args)
    except:
        # return 13 to match bcompare fail code and ensure exceptions
        # don't look like passes!
        print(traceback.format_exc())
        exit(13)
    exit(rcode)

if __name__ == '__main__':
    main()
