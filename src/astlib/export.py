import pandas as pd
from . import TranslationUnitDecl, FindAllVarRefs, compute_var_ast_signature, build_varid, get_vartype

def export_func_vars(tudecl:TranslationUnitDecl, bid:int=-1, skip_unique_vars:bool=False) -> pd.DataFrame:
    '''
    Exports a table describing the AST variables and their data types for the
    locals and parameters of the given function.
    '''
    columns = [
        'BinaryId','FunctionStart','Signature','Vartype','Name','Location','Type','TypeJson',
    ]

    if not tudecl:
        # failed to decompile - return empty dataframe
        return pd.DataFrame.from_records([], columns=columns)

    fdecl = tudecl.fdecl
    func_vars = fdecl.params + fdecl.local_vars

    if skip_unique_vars:
        func_vars = remove_unique_vars(func_vars)

    # find all refs & compute signatures
    var_refs = [FindAllVarRefs(v.name).visit(fdecl.func_body) for v in func_vars]
    var_sigs = [compute_var_ast_signature(refs, fdecl.address) for refs in var_refs]
    varids = [build_varid(bid, fdecl.address, var_sigs[i], get_vartype(func_vars[i])) for i in range(len(func_vars))]

    # save data in table form and return
    rows = [[*varids[i], v.name, v.location, v.dtype, v.dtype.to_json()] for i, v in enumerate(func_vars)]

    return pd.DataFrame.from_records(rows, columns=columns)