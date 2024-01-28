import pyhidra

# FYI: this "initializes the application" (per Ghidra docs)
launcher = pyhidra.start()

import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

import ghidra
from ghidra.base.project import GhidraProject
from ghidra.program.model.pcode import PcodeBlockBasic
from ghidra.app.decompiler import *
# from ghidra.app.decompiler import DecompInterface, DecompileOptions

from ghidralib import OpenSharedGhidraProject, get_decompiler_interface, AstBuilder
from astlib.scripts.print_ast import print_ast

DECOMPILE_TIMEOUT_SEC = 180

# ghidra://localhost/binutils/run1.gcc-O0.binutils-2_36
# repo.fileExists('/run1.gcc-O0.binutils-2_36', '0.gdb.debug')

host = 'localhost'
port = 13100
repoName = 'astera'
folderPath = '/run1.gcc.astera'
binaryName = '0.fighter.debug'

def remove_comments_and_blank_lines(ghidra_c:str) -> str:
    '''
    Remove comment lines and blank lines from Ghidra C code to help our AST diff match
    '''
    return '\n'.join([l for l in ghidra_c.split('\n') if l.strip() and l.strip()[:2] != '/*'])

with OpenSharedGhidraProject(host, repoName, port) as proj:
    prog = proj.openProgram(folderPath, binaryName, True)
    fm = prog.getFunctionManager()
    nonthunks = (x for x in fm.getFunctions(True) if not x.isThunk())
    test_func = [x for x in nonthunks if x.name == 'main'][0]
    # print(test_func.name)

    ifc = get_decompiler_interface(prog)
    res = ifc.decompileFunction(test_func, DECOMPILE_TIMEOUT_SEC, None)

    # write C code for validation
    with open(f'{test_func.name}.ghidra.c', 'w') as f:
        f.write(remove_comments_and_blank_lines(res.getDecompiledFunction().getC()))

    tudecl = AstBuilder(res).build_func_ast()
    print_ast(tudecl, f'{test_func.name}.ast.c')
