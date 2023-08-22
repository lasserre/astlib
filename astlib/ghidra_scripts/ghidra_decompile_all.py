#Decompile all functions
#@author Caleb Stewart
#@category phd
#@keybinding
#@menupath
#@toolbar

# 4 min timeout = 240 sec
DECOMPILE_TIMEOUT_SEC = 240

# this try/except construction makes intellisense nice with ghidra type stubs
# installed :)
# https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator

import json
import os

import ghidra
try:
    from ghidra.ghidra_builtins import *
except:
    pass

from ghidra.program.database import ProgramDB
from ghidra.program.database.data import TypedefDB, StructureDB
from ghidra.program.model.data import DataType, PointerDataType
from ghidra.app.decompiler import DecompInterface, DecompileOptions

# This is what I'm doing in the decompiler/C++:
# string ensureValidFilename(string filename)
# {
    # string invalidChars = "<>:\"/\\|?*";
    # for (int i = 0; i < invalidChars.size(); i++) {
    #     auto charpos = filename.find(invalidChars[i]);
    #     if (charpos != string::npos) {
    #         // invalid character - replace it
    #         filename[charpos] = '_';
    #         i--;    // check this character again to make sure we catch all occurrences
    #     }
    # }
    # return filename;
# }

# replicate above snippet in python to match filenames for functions
def ensureValidFilename(filename):
    invalidChars = '<>:"/\\|?*'
    for c in invalidChars:
        filename = filename.replace(c, '_')
    return filename

# decompiler init
def get_decompiler_interface(options=DecompileOptions(), program=currentProgram):
    # type: (DecompileOptions, ProgramDB) -> DecompInterface
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(program)
    return ifc

fm = currentProgram.getFunctionManager()
ifc = get_decompiler_interface()

# parse args
usage = 'Usage: ghidra_decompile_all.py [VALIDATE [<subset_file> [<exclude_file>]]]'
args = getScriptArgs()
validation_mode = 'VALIDATE' in args
subset_file = args[1] if len(args) == 2 else None
exclude_file = args[2] if len(args) == 3 else None

if validation_mode:
    print('RUNNING VALIDATION')
    if 'GHIDRA_AST_CONFIG_FILE' not in os.environ:
        print('Error: GHIDRA_AST_CONFIG_FILE environment variable not set!')
        exit(1)

    configfile = os.environ['GHIDRA_AST_CONFIG_FILE']
    with open(configfile, 'r') as f:
        config = json.load(f)

    exportfolder = config['output_folder']
    ghidra_outfolder = os.path.join(exportfolder, 'GhidraCode')
    if not os.path.exists(ghidra_outfolder):
        os.mkdir(ghidra_outfolder)

    if exclude_file:
        print('Using exclude file: {}'.format(exclude_file))
        with open(exclude_file, 'r') as f:
            exclude_funcs = [l.strip() for l in f.readlines()]
            exclude_funcs = [f for f in exclude_funcs if f[0] != '#']     # allow comment lines beginning with a '#'
            for func in exclude_funcs:
                print('EXCLUDE FUNC: "{}"'.format(func))
    elif subset_file:
        print('Using subset file: {}'.format(subset_file))
        with open(subset_file, 'r') as f:
            subset_funcs = [l.strip() for l in f.readlines()]
            subset_funcs = [f for f in subset_funcs if f and f[0] != '#']     # allow comment lines beginning with a '#'
            for func in subset_funcs:
                print('SUBSET FUNC: "{}"'.format(func))

# don't take forever right now so I can speed up getting this working
# validate skip=0, temp=300 to make sure we didn't regress!
MAX_FUNCS = 10000000
# MAX_FUNCS = 200
SKIP_COUNT = 0
print('ONLY RUNNING ON UP TO THE FIRST {} FUNCTIONS'.format(MAX_FUNCS))
if SKIP_COUNT:
    print('SKIPPING FIRST {} FUNCTIONS'.format(SKIP_COUNT))

max_counter = 0
skip_counter = 0

nonthunks = (x for x in fm.getFunctions(True) if not x.isThunk())
funcs_to_decompile = nonthunks

if subset_file:
    funcs_to_decompile = (x for x in nonthunks if x.getName() in subset_funcs)
if exclude_file:
    funcs_to_decompile = (x for x in nonthunks if x.getName() not in exclude_funcs)

for f in funcs_to_decompile:
    # don't skip if we have been given a specific subset
    if not subset_file and skip_counter < SKIP_COUNT:
        skip_counter += 1
        continue

    address = f.getEntryPoint().offset
    res = ifc.decompileFunction(f, DECOMPILE_TIMEOUT_SEC, monitor)
    if not res.decompileCompleted():
        print('Decompilation failed:')
        print(res.getErrorMessage())
        continue

    if validation_mode:
        print('Exporting C code for {}'.format(f.getName()))
        decompiled_c_filename = os.path.join(ghidra_outfolder, ensureValidFilename(f.getName()) + '.c')
        with open(decompiled_c_filename, 'w') as dcf:
            dcf.write(res.getDecompiledFunction().getC())

    max_counter += 1
    if max_counter >= MAX_FUNCS:
        break

    if max_counter % 500 == 0:
        print('Exported {} functions...'.format(max_counter))
