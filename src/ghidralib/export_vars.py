import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

# CLS: this should only be imported if pyhidra has been started

import pandas as pd
from typing import List
from tqdm import tqdm

import ghidra
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.database import ProgramDB
from ghidra.program.model.listing import FunctionManager, Function, Program
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.pcode import HighSymbol

from .projects import *
from .decompiler import AstDecompiler
from astlib.find_all_references import *

def export_func_vars(decompiler:AstDecompiler, func:Function, bid:int=-1, skip_unique_vars:bool=False) -> pd.DataFrame:
    '''
    Exports a table describing the AST variables and their data types for the
    locals and parameters of the given function.
    '''
    columns = [
        'BinaryId','FunctionStart','Signature','Vartype','Name','Location','Type','TypeJson',
    ]

    fdecomp = decompiler.decompile(func)
    tudecl = fdecomp.ast

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

def export_vars(decompiler:AstDecompiler, func_list:List[Function], bid:int=-1, skip_unique_vars:bool=False,
                status_msg:str='') -> pd.DataFrame:
    '''
    Exports a combined table for all the function vars in the
    specified function list
    '''
    return pd.concat(
            [export_func_vars(decompiler, f, bid, skip_unique_vars) for f in tqdm(func_list, desc=status_msg if status_msg else decompiler.program.name)]
        ).reset_index(drop=True)

class ProgramExport:
    def __init__(self, vars_df:pd.DataFrame, sdb:StructDatabase):
        self.vars_df = vars_df
        self.sdb = sdb

def export_program(proj:GhidraProject, bin_file:DomainFile, limit_funcs:int=None,
                        skip_unique_vars:bool=False) -> ProgramExport:
    # force-fitting this in here a little bit for now, but I don't want to go change the existing
    # dragon-oriented api of export_program_vars at the moment
    sdbs, vars_df = export_program_vars(proj, [bin_file], limit_funcs, skip_unique_vars, return_sdbs=True)
    return ProgramExport(vars_df, sdbs[0])

def export_program_vars(proj:GhidraProject, bin_files:List[DomainFile], limit_funcs:int=None,
                        skip_unique_vars:bool=False, return_sdbs:bool=False) -> pd.DataFrame:
    '''
    Exports the debug variable types to a combined data frame for the given binaries
    '''
    # the reason to make this debug-specific is because we only care about
    # the data types - we don't need to export the ASTs themselves
    bin_vdfs = []
    sdbs = []

    # remap BinaryId to ensure uniqueness across runs (OrigBinaryId/RunId maps new id to original)
    base_gid = 1000

    for i, bin_file in enumerate(bin_files):
        binary_name = original_binary_name(bin_file.parent.name)
        orig_bid = binary_id(bin_file.name)
        rid = run_id(bin_file.parent.name)
        bid = base_gid + i      # unique id

        with GhidraCheckoutProgram(proj, bin_file, bid=bid) as co:
            nonthunks = co.decompiler.nonthunk_functions[:limit_funcs]
            vdf = export_vars(co.decompiler, nonthunks, bid, skip_unique_vars)
            sdbs.append(co.decompiler.export_program_struct_db())
            # save mapping to original runid/bid
            vdf['Binary'] = binary_name
            vdf['OrigBinaryId'] = orig_bid
            vdf['RunId'] = rid
            bin_vdfs.append(vdf)

    var_df = pd.concat(bin_vdfs).reset_index(drop=True)
    return (sdbs, var_df) if return_sdbs else var_df
