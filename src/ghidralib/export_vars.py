import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

# CLS: this should only be imported if pyhidra has been started

import pandas as pd
from typing import List, Dict, Set
from tqdm import tqdm

import ghidra
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.database import ProgramDB
from ghidra.program.model.listing import FunctionManager, Function, Program
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.pcode import HighSymbol

from .projects import *
from .decompiler import AstDecompiler, DecompiledFunction, ProgramDecompilation
from astlib.find_all_references import *
from astlib import CollectAllMemberExprs
from varlib.datatype import StructField

def export_func_vars(fdecomp:DecompiledFunction, bid:int=-1, skip_unique_vars:bool=False) -> pd.DataFrame:
    '''
    Exports a table describing the AST variables and their data types for the
    locals and parameters of the given function.
    '''
    columns = [
        'BinaryId','FunctionStart','Signature','Vartype','Name','Location','Type','TypeJson',
    ]

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
            [export_func_vars(decompiler.decompile(f), bid, skip_unique_vars)
                for f in tqdm(
                    func_list,
                    desc=status_msg if status_msg else decompiler.program.name
                )
            ]
        ).reset_index(drop=True)

class ProgramExport:
    def __init__(self, vars_df:pd.DataFrame, sdb:StructDatabase, accessed_sdb:StructDatabase=None,
                func_local_accessed_sdbs:Dict[int,StructDatabase]=None):
        self.vars_df = vars_df
        self.sdb = sdb
        self.accessed_sdb = accessed_sdb
        self.func_local_accessed_sdbs = func_local_accessed_sdbs

def build_accessed_sdb(pdecomp:ProgramDecompilation) -> StructDatabase:
    accessed_offsets_by_sid:Dict[int,Set[int]] = {}     # map sid -> set(offsets)

    # gather all member references across entire program
    member_refs = [x for fd in pdecomp.decompiled_functions for x in CollectAllMemberExprs().visit(fd.ast)]

    for mref in member_refs:
        if mref.parent_struct:
            sid = mref.parent_struct.sid
            if sid not in accessed_offsets_by_sid:
                accessed_offsets_by_sid[sid] = set()
            accessed_offsets_by_sid[sid].add(mref.offset)

    accessed_sdb = StructDatabase()

    for sid, offsets in accessed_offsets_by_sid.items():
        full_sdef = pdecomp.sdb.structs_by_id[sid]
        access_sdef = StructDefinition(
            full_sdef.name,
            # check if off actually is a real structure offset before indexing, since
            # Ghidra generates "fake" member accesses sometimes
            {off: full_sdef.layout[off] for off in offsets if off in full_sdef.layout},
            ghidra_uid=full_sdef.ghidra_uid
        )
        accessed_sdb.map_struct_type('', access_sdef, is_union=False, force_sid=sid)

    # map ALL union types so any structs referring to a union don't break our postprocessing later
    for uid, udef in pdecomp.sdb.unions_by_id.items():
        accessed_sdb.map_struct_type('', udef, is_union=True, force_sid=uid)

    return accessed_sdb

def build_function_local_accessed_sdbs(pdecomp:ProgramDecompilation) -> Dict[int,StructDatabase]:
    '''
    Build a separate sdb for each function, where the structure definitions include only the members
    accessed within that function.
    '''
    accessed_offsets_by_func_sid:Dict[Tuple[int,int],Set[int]] = {}     # map (func_addr,sid) -> set(offsets)

    # gather all member references across entire program
    refs_by_func = {fd.address: CollectAllMemberExprs().visit(fd.ast) for fd in pdecomp.decompiled_functions}

    for func_addr, member_refs in refs_by_func.items():
        for mref in member_refs:
            mref:MemberExpr
            if mref.parent_struct:
                sid = mref.parent_struct.sid
                skey = (func_addr, sid)
                if skey not in accessed_offsets_by_func_sid:
                    accessed_offsets_by_func_sid[skey] = set()
                accessed_offsets_by_func_sid[skey].add(mref.offset)

    accessed_sdbs = {}  # map func_addr -> sdb

    for skey, offsets in accessed_offsets_by_func_sid.items():
        func_addr, sid = skey
        full_sdef = pdecomp.sdb.structs_by_id[sid]
        access_sdef = StructDefinition(
            f'{full_sdef.name}__{func_addr:#x}',
            {off: full_sdef.layout[off] for off in offsets if off in full_sdef.layout},
            ghidra_uid=full_sdef.ghidra_uid
        )
        if func_addr not in accessed_sdbs:
            accessed_sdbs[func_addr] = StructDatabase()
        accessed_sdbs[func_addr].map_struct_type('', access_sdef, is_union=False, force_sid=sid)

    # map ALL union types so any structs referring to a union don't break our postprocessing later
    for fsdb in accessed_sdbs.values():
        for uid, udef in pdecomp.sdb.unions_by_id.items():
            fsdb.map_struct_type('', udef, is_union=True, force_sid=uid)

    return accessed_sdbs

def export_program(proj:GhidraProject, bin_file:DomainFile,
                    limit_funcs:int=None,
                    skip_unique_vars:bool=False, status_msg:str='Exporting program data',
                    bid:int=-1, terminate_existing_checkouts:bool=False) -> ProgramExport:

    with GhidraCheckoutProgram(proj, bin_file, bid=bid, terminate_existing_checkouts=terminate_existing_checkouts) as co:
        nonthunks = co.decompiler.nonthunk_functions[:limit_funcs]
        pdecomp = co.decompiler.export_program_decompilation(status_msg, nonthunks)
        vars_df = pd.concat([
            export_func_vars(fd, bid, skip_unique_vars) for fd in pdecomp.decompiled_functions
        ]).reset_index(drop=True)
        accessed_sdb = build_accessed_sdb(pdecomp)
        func_local_sdbs = build_function_local_accessed_sdbs(pdecomp)

    return ProgramExport(vars_df, pdecomp.sdb, accessed_sdb, func_local_sdbs)

def export_program_vars(proj:GhidraProject, bin_files:List[DomainFile], limit_funcs:int=None,
                        skip_unique_vars:bool=False) -> pd.DataFrame:
    '''
    Exports the debug variable types to a combined data frame for the given binaries
    '''
    # the reason to make this debug-specific is because we only care about
    # the data types - we don't need to export the ASTs themselves
    bin_vdfs = []

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
            # save mapping to original runid/bid
            vdf['Binary'] = binary_name
            vdf['OrigBinaryId'] = orig_bid
            vdf['RunId'] = rid
            bin_vdfs.append(vdf)

    return pd.concat(bin_vdfs).reset_index(drop=True)
