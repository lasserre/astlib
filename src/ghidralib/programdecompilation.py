import typing
if typing.TYPE_CHECKING:
    from ghidra.program.model.pcode import HighSymbol
    from ghidra.app.decompiler import DecompileResults

from pathlib import Path
import json
from rich.console import Console
from tqdm import tqdm
from typing import Dict, List

from astlib import TranslationUnitDecl, astnode_from_dict, read_json_nothrow
from varlib import StructDatabase

# From Ghidra decompiler mods, ast.cc:5 in getValidCLanguageName()
#
# /**
#  * Ghidra displays invalid C variable names in the decompiler window (like "file-local"),
#  * but when I convert it to C using the flat API (DecompiledFunction.getC())
#  * Ghidra first converts invalid names like this to valid C names (like "file_local")
# */
#
# --> now I'm seeing the local_sym_dict has names like "file-local" while our exported names
#     match Ghidra's getC() names (corrected). So make the local_sym_dict names valid C names
#     to allow our lookups to work properly
def to_valid_C_name(sym_name:str) -> str:
    return ''.join([c if c.isalnum() else '_' for c in sym_name])

class DecompiledFunction:
    '''
    Contains decompiled function outputs all in one place
    for convenience
    '''
    def __init__(self, ast:TranslationUnitDecl, error_msg:str, results:'DecompileResults', ast_json:str=''):
        self.ast = ast
        self.error_msg = error_msg
        self.results = results
        self.ast_json = ast_json

    @property
    def ast_log(self) -> str:
        return self.ast.logfile

    @property
    def local_sym_dict(self) -> Dict[str, 'HighSymbol']:
        '''
        Get dictionary of localSymbolMap from decompile results
        '''
        return dict(self.results.highFunction.localSymbolMap.nameToSymbolMap)

    @property
    def local_sym_dict_with_valid_varnames(self) -> Dict[str, 'HighSymbol']:
        return {to_valid_C_name(k): v for k, v in self.local_sym_dict.items()}

    @property
    def address(self) -> int:
        '''
        Returns the function address
        '''
        return self.ast.fdecl.address

    def to_dict(self) -> dict:
        return {
            'ast': self.ast.to_dict(),
            'error_msg': self.error_msg,
            # don't save results or ast_json str
        }

    @staticmethod
    def from_dict(d:dict, sdb:StructDatabase) -> 'DecompiledFunction':
        return DecompiledFunction(astnode_from_dict(d['ast'], sdb), d['error_msg'], results=None)

class ProgramDecompilation:
    '''
    Container for a set of decompiled functions and the corresponding
    StructureDatabase from a program
    '''
    def __init__(self, decompiled_funcs:List[DecompiledFunction], sdb:StructDatabase):
        self.decompiled_functions = decompiled_funcs
        self.failed_decompilations = []
        self.sdb = sdb

        self._filter_failed_decomps()

    def _filter_failed_decomps(self):
        '''
        Separates failed decompilations into self.failed_decompilations, removing them
        from the decompiled_functions list
        '''
        self.failed_decompilations = [fd for fd in self.decompiled_functions if not fd.ast]
        if self.failed_decompilations:
            console = Console()
            console.print(f'[yellow]{len(self.failed_decompilations):,} functions failed to decompile')
            self.decompiled_functions = [fd for fd in self.decompiled_functions if fd.ast]      # filter down to only good ones

    @staticmethod
    def from_json(filepath:Path) -> 'ProgramDecompilation':
        with open(filepath, 'r') as f:
            data = json.load(f)
        return ProgramDecompilation.from_dict(data)

    @staticmethod
    def from_dict(d:dict) -> 'ProgramDecompilation':
        sdb = StructDatabase.from_dict(d['sdb'])
        return ProgramDecompilation([DecompiledFunction.from_dict(x, sdb) for x in d['decompiled_functions']], sdb)

    @staticmethod
    def from_bin_folder(bin_folder:Path, debug:bool, show_pbar:bool=True) -> 'ProgramDecompilation':
        '''
        bin_folder: Binary folder within a wdb run folder (e.g. run1/0.my_binary)
        debug: Collects ProgramDecompilation for debug binary if true, otherwise collects stripped binary
        '''
        ast_dump_folder = bin_folder/'ast_dumps'
        ast_dump_folder /= 'debug' if debug else 'stripped'
        sdb_file = bin_folder/f'{bin_folder.name}.debug.sdb' if debug else bin_folder/f'{bin_folder.name}.sdb'
        sdb = StructDatabase.from_json(sdb_file) if sdb_file.exists() else None

        ast_file_list = list(ast_dump_folder.glob('*.json'))
        get_ast_files = tqdm(ast_file_list, desc=f'Reading decompiled functions from {bin_folder.name}') if show_pbar else ast_file_list
        ast_list = [read_json_nothrow(f, sdb) for f in get_ast_files]   # any failures (JsonRecursionErrors) where ast is None get handled by ProgramDecomp
        return ProgramDecompilation([
                DecompiledFunction(ast, error_msg='', results=None) for ast in ast_list
            ], sdb)

    def to_dict(self) -> dict:
        return {
            'decompiled_functions': [x.to_dict() for x in self.decompiled_functions],
            'sdb': self.sdb.to_dict(),
        }

    def to_json(self, filepath:Path):
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
