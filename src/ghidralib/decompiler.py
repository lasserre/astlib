import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

# CLS: this should only be imported if pyhidra has been started

from typing import List, Dict, Tuple
import pandas as pd
from tqdm import tqdm

import ghidra
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.database import ProgramDB
from ghidra.program.model.listing import FunctionManager, Function, Program
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.pcode import HighSymbol, HighFunctionDBUtil
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SourceType

from astlib import TranslationUnitDecl, read_json_str, build_var_ast_signature, VarDecl, JsonRecursionError
from varlib import StructDatabase
from .export_types import export_ghidra_types_to_sdb

def get_decompiler_interface(program:ProgramDB, options:DecompileOptions=None) -> DecompInterface:
    if not options:
        options = DecompileOptions()

    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(program)
    return ifc

class DecompiledFunction:
    '''
    Contains decompiled function outputs all in one place
    for convenience
    '''
    def __init__(self, ast:TranslationUnitDecl, error_msg:str, results:DecompileResults):
        self.ast = ast
        self.error_msg = error_msg
        self.results = results

    @property
    def ast_log(self) -> str:
        return self.ast.logfile

    @property
    def local_sym_dict(self) -> Dict[str, HighSymbol]:
        '''
        Get dictionary of localSymbolMap from decompile results
        '''
        return dict(self.results.highFunction.localSymbolMap.nameToSymbolMap)

class AstDecompiler:
    AST_DELIM = '#$#$# BEGIN AST #@#@#'

    def __init__(self, program:Program, bid:int=-1, timeout_sec:int=240, options:DecompileOptions=None) -> None:
        '''
        program: The program to be decompiled
        bid: The binary id associated with this program (if any) to use when generating varids
        timeout_sec: Decompiler timeout in seconds
        options: Decompiler options
        '''
        self.program = program
        self.bid = bid
        self.timeout_sec = timeout_sec
        self.options = DecompileOptions() if options is None else options

        self.ifc = DecompInterface()
        self.ifc.setOptions(self.options)

    def __enter__(self) -> 'AstDecompiler':
        self.ifc.openProgram(self.program)
        return self

    def __exit__(self, etype, value, traceback):
        # CLS: I think this just ends the decompiler process, I don't think it
        # does anything to the program domain_file (which should still be open)
        self.ifc.closeProgram()

    @property
    def func_mgr(self) -> FunctionManager:
        return self.program.functionManager

    @property
    def datatype_mgr(self) -> DataTypeManager:
        return self.program.dataTypeManager

    @property
    def functions(self) -> List[Function]:
        return list(self.func_mgr.getFunctions(True))

    def get_address_from_offset(self, offset:int) -> Address:
        return self.program.addressFactory.getAddress(f'0x{offset:x}')

    def get_function(self, offset:int) -> Function:
        return self.func_mgr.getFunctionAt(self.get_address_from_offset(offset))

    @property
    def nonthunk_functions(self) -> List[Function]:
        return [f for f in self.func_mgr.getFunctions(True) if not f.isThunk()]

    def export_program_struct_db(self) -> StructDatabase:
        '''
        Export the structure database defining the composite types for this program
        '''
        return export_ghidra_types_to_sdb(self.datatype_mgr)

    @staticmethod
    def extract_ast_json_from_decomp_results(res:DecompileResults) -> Tuple[str, str]:
        '''
        Separates the error message and AST JSON from the DecompileResults and returns
        them as a tuple: (error_msg, ast_json)
        '''
        if AstDecompiler.AST_DELIM in res.errorMessage:
            error_msg, ast_json = res.errorMessage.split(AstDecompiler.AST_DELIM)
        else:
            error_msg = res.errorMessage
            ast_json = ''
        return (error_msg, ast_json)

    def decompile(self, func:Function, sdb:StructDatabase=None) -> DecompiledFunction:
        '''
        Decompiles the given function
        '''
        res = self.ifc.decompileFunction(func, self.timeout_sec, None)
        error_msg, ast_json = AstDecompiler.extract_ast_json_from_decomp_results(res)

        if not res.decompileCompleted():
            ast_json = ''   # don't return something if the decompiler didn't properly complete

        if not ast_json:
            return DecompiledFunction(ast=None, error_msg=error_msg, results=res)

        try:
            tudecl = read_json_str(ast_json, sdb=sdb)
            ast = None if tudecl.logfile else tudecl    # if we had AST errors (logfile present in JSON) return None to indicate failure
            return DecompiledFunction(ast, error_msg, res)
        except JsonRecursionError:
            # allow us to recover from a massive function that triggers the JsonRecursionError
            return DecompiledFunction(ast=None, error_msg='JsonRecursionError in AstDecompiler (read_json_str)', results=res)

    def decompile_and_extract_signatures(self, func:Function, sdb:StructDatabase=None) -> Tuple[TranslationUnitDecl, Dict[str, VarDecl]]:
        '''
        Decompiles the function and builds variable signatures for each parameter and local in the function

        Returns a tuple of (decompiled AST, var_signatures) where var_signatures is a dictionary mapping
        variable signature to the corresponding VarDecl
        '''
        ast = self.decompile(func, sdb).ast
        func_vars = ast.fdecl.params + ast.fdecl.local_vars
        vars_by_sig = {build_var_ast_signature(ast.fdecl, v.name): v for v in func_vars}
        return (ast, vars_by_sig)

    def commit_function_prototype(self, fdecomp:DecompiledFunction, use_data_types:bool=True, return_commit:bool=True):
        '''
        Commits the function prototype to the database
        '''
        hf = fdecomp.results.highFunction
        HighFunctionDBUtil.commitParamsToDatabase(hf, use_data_types, SourceType.USER_DEFINED)
        if return_commit:
            HighFunctionDBUtil.commitReturnToDatabase(hf, SourceType.USER_DEFINED)

        # CLS: we don't want to commit local names - we will individually rename the variables
        # we retype, and Ghidra can recover variables differently if appropriate
        # HighFunctionDBUtil.commitLocalNamesToDatabase
