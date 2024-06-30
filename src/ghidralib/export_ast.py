
import argparse
import json
from pathlib import Path
import subprocess
import shutil
import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *
from typing import Dict, Any

from wildebeest import RunStep
from wildebeest.run import Run
from wildebeest.postprocessing import FlatLayoutBinary, get_ghidra_folder_for_run, get_binary_symlink_name
from wildebeest.utils import env, show_progress
from wildebeest.ghidrautil import GhidraKeys

def decompile_all(export_folder:Path, host:str, repo:str, folder:str, binaryName:str, timeout_sec:int, max_funcs:int=-1,
                port:int=13100, ast_only:bool=False):

    # start pyhidra so ghidra things work :)
    import pyhidra
    pyhidra.start()

    import ghidra
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.program.database import ProgramDB

    from ghidralib.projects import OpenSharedGhidraProject
    from ghidralib.decompiler import get_decompiler_interface
    from ghidralib.export_types import export_ghidra_types_to_sdb

    failed_decompilations = []

    with OpenSharedGhidraProject(host, repo, port) as proj:
        print(f'Opening shared project @ {host}:{port}: repo={repo}, folder={folder}, binary={binaryName}')
        prog = proj.openProgram(folder, binaryName, True)
        fm = prog.getFunctionManager()
        ifc = get_decompiler_interface(prog)

        sdb_file = export_folder/f'{binaryName}.sdb'
        print(f'Exporting all Ghidra data types to {sdb_file.name}...')
        sdb = export_ghidra_types_to_sdb(prog.getDataTypeManager())
        sdb.to_json(sdb_file)

        if ast_only:
            ifc.toggleCCode(False)

        def get_nonthunks(fm:ghidra.program.model.listing.FunctionManager):
            return (x for x in fm.getFunctions(True) if not x.isThunk())

        nonthunks = get_nonthunks(fm)
        total_funcs = len(list(get_nonthunks(fm)))

        print(f'Exporting function asts...')
        for i, func in show_progress(enumerate(nonthunks), total=total_funcs):
            if max_funcs > -1 and i >= max_funcs:
                break

            address = func.getEntryPoint().offset
            res = ifc.decompileFunction(func, timeout_sec, None)
            if not res.decompileCompleted():
                print('Decompilation failed:')
                print(res.getErrorMessage())
                failed_decompilations.append(address)
                continue

    # log addresses of failed decompilations
    if failed_decompilations:
        with open(export_folder/f'{binaryName}_failed_decompilations.txt', 'w') as faildecomps_file:
            faildecomps_file.write('\n'.join(f'{addr:x}' for addr in failed_decompilations))

    return 0

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

        # clear existing ast folder if it exists (like reset_data for this ast export folder)
        if ast_folder.exists():
            shutil.rmtree(ast_folder)
        ast_folder.mkdir(exist_ok=True, parents=True)     # folder has to exist or we don't get output!

        # write AST config file, process the imported binary
        with open(ast_config, 'w') as f:
            f.write(json.dumps({'output_folder': str(ast_folder)}))

        decompile_cmdline = [
            'ghidra_decompile_all', ast_folder,
            'localhost', repo, ghidra_folder, bin_symlink.name,
            '--timeout_sec', str(DECOMPILE_TIMEOUT), '--ast-only'
        ]

        with env({'GHIDRA_AST_CONFIG_FILE': str(ast_config)}):
            # print(f'Running command: {" ".join(str(x) for x in decompile_cmdline)}')
            rcode = subprocess.call(decompile_cmdline)
            if rcode != 0:
                raise Exception(f'Ghidra postscript processing failed with return code {rcode}')

            # move sdb files up to the data folder
            for sdb_file in ast_folder.glob('*.sdb'):
                shutil.move(sdb_file, fb.data_folder/sdb_file.name)

# TODO:
# - move this to ghidralib.wildebeest.export_asts -> RunStep
# - leave export_ast.export_asts as a python interface we can call from dragon-ryder

def export_asts(debug:bool):
    params = {
        'debug_binaries': debug
    }
    return RunStep(f'export_asts_{"debug" if debug else "strip"}', do_export_asts, params)

if __name__ == '__main__':
    exit(decompile_all_main())
