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
from ghidra.program.model.pcode import HighSymbol

from astlib import TranslationUnitDecl, read_json_str, build_var_ast_signature, VarDecl
from varlib import StructDatabase
from .export_types import export_ghidra_types_to_sdb

def get_decompiler_interface(program:ProgramDB, options:DecompileOptions=None) -> DecompInterface:
    if not options:
        options = DecompileOptions()

    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(program)
    return ifc

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

        self.last_res:DecompileResults = None   # cache last decompile result
        self.last_error_msg:str = ''
        self.last_ast_log:str = ''      # filled out in case of AST errors (content in logfile)

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

    @property
    def nonthunk_functions(self) -> List[Function]:
        return [f for f in self.func_mgr.getFunctions(True) if not f.isThunk()]

    def get_local_sym_dict(self, res:DecompileResults) -> Dict[str, HighSymbol]:
        '''
        Get dictionary of localSymbolMap from decompile results
        '''
        return dict(res.highFunction.localSymbolMap.nameToSymbolMap)

    @property
    def local_sym_dict(self) -> Dict[str, HighSymbol]:
        '''
        Return the local symbol dictionary from the last function decompiled
        '''
        return self.get_local_sym_dict(self.last_res)

    def export_program_struct_db(self) -> StructDatabase:
        '''
        Export the structure database defining the composite types for this program
        '''
        return export_ghidra_types_to_sdb(self.datatype_mgr)

    def _decompile_ast_json(self, func:Function) -> str:
        '''
        Decompiles the given function AST and returns the result as a JSON string
        '''
        self.last_res = None
        self.last_error_msg = ''
        self.last_ast_log = ''

        res = self.ifc.decompileFunction(func, self.timeout_sec, None)

        if AstDecompiler.AST_DELIM in res.errorMessage:
            error_msg, ast_json = res.errorMessage.split(AstDecompiler.AST_DELIM)
        else:
            error_msg = res.errorMessage
            ast_json = ''

        self.last_res = res
        self.last_error_msg = error_msg

        return '' if not res.decompileCompleted() else ast_json

    def decompile_ast(self, func:Function, sdb:StructDatabase=None) -> TranslationUnitDecl:
        '''
        Decompiles the given function AST
        '''
        ast_json = self._decompile_ast_json(func)
        if not ast_json:
            return None     # last_error_msg should be filled out

        tudecl = read_json_str(ast_json, sdb=sdb)
        self.last_ast_log = tudecl.logfile
        return tudecl if not self.last_ast_log else None

    def decompile_and_extract_signatures(self, func:Function, sdb:StructDatabase=None) -> Tuple[TranslationUnitDecl, Dict[str, VarDecl]]:
        '''
        Decompiles the function and builds variable signatures for each parameter and local in the function

        Returns a tuple of (decompiled AST, var_signatures) where var_signatures is a dictionary mapping
        variable signature to the corresponding VarDecl
        '''
        ast = self.decompile_ast(func, sdb)
        func_vars = ast.fdecl.params + ast.fdecl.local_vars
        vars_by_sig = {build_var_ast_signature(ast.fdecl, v.name): v for v in func_vars}
        return (ast, vars_by_sig)
