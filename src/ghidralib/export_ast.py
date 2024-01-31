
import argparse
import json
from pathlib import Path
import subprocess
import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *
from typing import Dict, Any

from wildebeest import RunStep
from wildebeest.run import Run
from wildebeest.postprocessing import FlatLayoutBinary, get_ghidra_folder_for_run, get_binary_symlink_name
from wildebeest.utils import env
from wildebeest.ghidrautil import GhidraKeys

def decompile_all(export_folder:Path, host:str, repo:str, folder:str, binaryName:str, timeout_sec:int, max_funcs:int=-1,
                port:int=13100, ast_only:bool=False):

    # start pyhidra so ghidra things work :)
    import pyhidra
    pyhidra.start()

    import ghidra
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.program.database import ProgramDB

    from .opensharedghidraproject import OpenSharedGhidraProject
    from .decompiler import get_decompiler_interface

    failed_decompilations = []

    with OpenSharedGhidraProject(host, repo, port) as proj:
        print(f'Opening shared project @ {host}:{port}: repo={repo}, folder={folder}, binary={binaryName}')
        prog = proj.openProgram(folder, binaryName, True)
        fm = prog.getFunctionManager()
        ifc = get_decompiler_interface(prog)
        if ast_only:
            ifc.toggleCCode(False)

        nonthunks = (x for x in fm.getFunctions(True) if not x.isThunk())

        for i, func in enumerate(nonthunks):
            if max_funcs > -1 and i >= max_funcs:
                break

            address = func.getEntryPoint().offset
            res = ifc.decompileFunction(func, timeout_sec, None)
            if not res.decompileCompleted():
                print('Decompilation failed:')
                print(res.getErrorMessage())
                failed_decompilations.append(address)
                continue

            if (i+1) % 500 == 0:
                print(f'Exported {i+1:,} functions...')

    # log addresses of failed decompilations
    if failed_decompilations:
        with open(export_folder/f'{binaryName}_failed_decompilations.txt', 'w') as faildecomps_file:
            faildecomps_file.write('\n'.join(f'{addr:x}' for addr in failed_decompilations))

    return 0

# TODO: make this an entry point, call it!
def decompile_all_main():
    p = argparse.ArgumentParser(description='Decompile all functions in a binary')
    p.add_argument('export_folder', help='Folder where outputs will be written (failed decomps)')
    p.add_argument('server', help='Ghidra server to connect to')
    p.add_argument('repo', help='Name of shared repository in Ghidra')
    p.add_argument('folder', help='Folder path in shared project')
    p.add_argument('binary', help='Name of binary file')
    p.add_argument('--timeout_sec', default=240, type=int, help='Decompiler timeout in seconds')
    p.add_argument('--max-funcs', default=-1, type=int, help='Max number of functions to decompile (default is no maximum)')
    p.add_argument('--port', default=13100, type=int, help='Port to connect to server')
    p.add_argument('--ast-only', action='store_true', help="Don't decompile C code, only AST export")
    args = p.parse_args()

    return decompile_all(Path(args.export_folder), args.server, args.repo, args.folder, args.binary,
        args.timeout_sec, args.max_funcs, args.port, args.ast_only)

def do_export_asts(run:Run, params:Dict[str,Any], outputs:Dict[str,Any]):

    debug_binaries = params['debug_binaries']
    ghidra_folder = get_ghidra_folder_for_run(run)
    repo = params[GhidraKeys.GHIDRA_REPO]

    DECOMPILE_TIMEOUT = 240     # 4 minutes

    for bid, fb in outputs['flatten_binaries'].items():
        fb:FlatLayoutBinary
        binary = fb.debug_binary_file if debug_binaries else fb.stripped_binary_file
        bin_symlink = get_binary_symlink_name(fb, binary)

        # NOTE: bin_symlink.name is the program to analyze

        debug_suffix = '.debug' if binary.name.endswith('.debug') else ''
        if debug_suffix:
            ast_config = fb.data_folder/'ghidra_ast.debug.json'
            ast_folder = fb.data_folder/'ast_dumps'/'debug'
            fb.data['debug_asts'] = ast_folder
        else:
            ast_config = fb.data_folder/'ghidra_ast.json'
            ast_folder = fb.data_folder/'ast_dumps'/'stripped'
            fb.data['stripped_asts'] = ast_folder
        ast_folder.mkdir(exist_ok=True, parents=True)     # folder has to exist or we don't get output!

        # write AST config file, process the imported binary
        with open(ast_config, 'w') as f:
            f.write(json.dumps({'output_folder': str(ast_folder)}))

        with env({'GHIDRA_AST_CONFIG_FILE': str(ast_config)}):
            rcode = subprocess.call([
                'ghidra_decompile_all', ast_folder,
                'localhost', repo, ghidra_folder, bin_symlink.name,
                '--timeout_sec', str(DECOMPILE_TIMEOUT), '--ast-only'
            ])
            if rcode != 0:
                raise Exception(f'Ghidra postscript processing failed with return code {rcode}')

def export_asts(debug:bool):
    params = {
        'debug_binaries': debug
    }
    return RunStep(f'export_asts_{"debug" if debug else "strip"}', do_export_asts, params)
