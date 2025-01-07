
import argparse
import json
from pathlib import Path
from rich.console import Console
import subprocess
import shutil
import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *
from typing import Dict, Any

from astlib import binary_id

from wildebeest import RunStep
from wildebeest.run import Run
from wildebeest.postprocessing import FlatLayoutBinary, get_ghidra_folder_for_run, get_binary_symlink_name
from wildebeest.utils import env, show_progress
from wildebeest.ghidrautil import GhidraKeys

def decompile_all(export_folder:Path, host:str, repo:str, folder:str, binaryName:str, timeout_sec:int, max_funcs:int=-1,
                port:int=13100, ast_only:bool=False):

    console = Console()

    # start pyhidra so ghidra things work :)
    import pyhidra
    pyhidra.start()

    from ghidralib.projects import verify_ghidra_revision, GhidraCheckoutProgram, get_project_manager_headless, OpenSharedGhidraProject
    from ghidralib.decompiler import AstDecompiler
    from ghidralib.export_types import export_ghidra_types_to_sdb

    with OpenSharedGhidraProject(host, repo, port) as proj:

        bin_file = proj.projectData.getFile(f'{folder}/{binaryName}')
        bid = binary_id(bin_file.name)
        verify_ghidra_revision(bin_file, expected_revision=1, rollback_delete=True)

        failed_decompilations = []
        failed_ast_exports = []
        failed_ast_log = []

        with GhidraCheckoutProgram(proj, bin_file) as co:
            sdb_file = export_folder/f'{binaryName}.sdb'
            print(f'Exporting all Ghidra data types to {sdb_file.name}...')
            sdb = export_ghidra_types_to_sdb(co.program.dataTypeManager)
            sdb.to_json(sdb_file)

            with AstDecompiler(co.program, bid, timeout_sec=timeout_sec) as decompiler:
                nonthunks = co.decompiler.nonthunk_functions

                print(f'Exporting function asts...')

                for i, func in show_progress(enumerate(nonthunks), desc=bin_file.name, total=len(nonthunks)):
                    if max_funcs > -1 and i >= max_funcs:
                        break

                    fdecomp = decompiler.decompile(func)

                    if fdecomp.ast is None:
                        addr_str = f'{func.entryPoint.offset:x}'
                        if fdecomp.error_msg:
                            failed_decompilations.append(addr_str)
                        else:
                            failed_ast_exports.append(addr_str)
                            failed_ast_log.extend([addr_str, fdecomp.ast_log])
                        continue

                    # save ast to json
                    filename = f'Func{func.entryPoint.offset:x}-{func.name}'[:175]  # limit to first 175 characters to avoid "filename too long" exception
                    for ch in "<>:\"/\\|?*":    # sanitize possible bad file chars in function name
                        filename = filename.replace(ch, '_')
                    filename += '.json'

                    with open(export_folder/filename, 'w') as f:
                        json.dump(fdecomp.ast.to_dict(), f)

        # log addresses of failed decompilations
        if failed_decompilations:
            with open(export_folder/f'{binaryName}_failed_decompilations.txt', 'w') as faildecomps_file:
                faildecomps_file.write('\n'.join(failed_decompilations))

        if failed_ast_exports:
            with open(export_folder/f'{binaryName}_failed_ast_exports.txt', 'w') as f:
                f.write('\n'.join(failed_ast_exports))
            with open(export_folder/f'{binaryName}_failed_ast_export_logs.txt', 'w') as f:
                f.write('\n'.join(failed_ast_log))

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

        decompile_all(ast_folder, 'localhost', repo, ghidra_folder, bin_symlink.name,
                        DECOMPILE_TIMEOUT, ast_only=True)

        # move sdb files up to the data folder
        for sdb_file in ast_folder.glob('*.sdb'):
            shutil.move(sdb_file, fb.data_folder/sdb_file.name)

def export_asts(debug:bool):
    params = {
        'debug_binaries': debug
    }
    return RunStep(f'export_asts_{"debug" if debug else "strip"}', do_export_asts, params)

if __name__ == '__main__':
    exit(decompile_all_main())
