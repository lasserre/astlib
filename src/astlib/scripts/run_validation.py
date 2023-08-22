import argparse
import json
import os
import pandas as pd
from pathlib import Path
import subprocess
import re
from rich.console import Console
from rich.table import Table
import sys
from typing import Dict, List

import astlib
from astlib.rich_utils import df_to_richtable
from astlib import config
from astlib.scripts.print_ast import convert_astfile_to_code

# run validation of AST export

# -------------------------------------------------------
# HACK to get around Ghidra-exported C code not compiling
# we just paste a predetermined set of typedefs at the top
# of both files. This does 2 things:
# 1) satisfies typedef needs for Ghidra C code
# 2) ensures both files' ASTs still match (since we include
#    it at top of both files)

# this is what I'm doing within Ghidra code:
# on my x86_64 laptop:
# char - 1B
# short - 2B
# int - 4B
# long - 8B
# long long - 8B

# from ghidra_arch.cc:
# types->setCoreType("void",1,TYPE_VOID,false);
# types->setCoreType("bool",1,TYPE_BOOL,false);
# types->setCoreType("byte",1,TYPE_UINT,false);
# types->setCoreType("word",2,TYPE_UINT,false);
# types->setCoreType("dword",4,TYPE_UINT,false);
# types->setCoreType("qword",8,TYPE_UINT,false);
# types->setCoreType("char",1,TYPE_INT,true);
# types->setCoreType("sbyte",1,TYPE_INT,false);
# types->setCoreType("sword",2,TYPE_INT,false);
# types->setCoreType("sdword",4,TYPE_INT,false);
# types->setCoreType("sqword",8,TYPE_INT,false);
# types->setCoreType("float",4,TYPE_FLOAT,false);
# types->setCoreType("float8",8,TYPE_FLOAT,false);
# types->setCoreType("float16",16,TYPE_FLOAT,false);
# types->setCoreType("undefined",1,TYPE_UNKNOWN,false);
# types->setCoreType("undefined2",2,TYPE_UNKNOWN,false);
# types->setCoreType("undefined4",4,TYPE_UNKNOWN,false);
# types->setCoreType("undefined8",8,TYPE_UNKNOWN,false);
# types->setCoreType("code",1,TYPE_CODE,false);
# types->setCoreType("wchar",2,TYPE_INT,true);

## OLD VALIDATION TYPEDEFS:
# typedef unsigned char uchar;
# typedef unsigned short ushort;
# typedef unsigned int uint;
# typedef unsigned long ulong;

# typedef unsigned char uint8_t;
# typedef unsigned int uint32_t;
# typedef unsigned long uint64_t;

# // these are not real...but I don't care, just getting it to compile
# typedef unsigned long uint128_t;
# typedef unsigned long uint256_t;
# typedef unsigned long uint512_t;

# typedef unsigned int uint3;
# typedef unsigned long uint5;
# typedef unsigned long uint6;
# typedef unsigned long uint7;
# typedef uint32_t uint32;

# typedef unsigned char byte;
# typedef char sbyte;

# typedef char int8_t;
# typedef int int32_t;
# typedef long int64_t;
# // these are not real...but I don't care, just getting it to compile
# typedef unsigned long int128_t;
# typedef unsigned long int256_t;
# typedef unsigned long int512_t;

GHIDRA_VALIDATION_TYPEDEF_STR = '''
typedef _Bool bool;
#define true 1
#define false 0

#define processEntry volatile

//typedef void* code;
typedef int (*code)(void);

// core types
typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned long qword;
typedef char sbyte;
typedef short sword;
typedef int sdword;
typedef long sqword;
typedef double float8;
typedef double float16;
typedef unsigned char undefined;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long undefined8;
typedef short wchar;

// abbreviations
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

// __uintN_t
typedef unsigned char __uint8_t;
typedef unsigned short __uint16_t;
typedef unsigned int __uint32_t;
typedef unsigned long __uint64_t;

// __intN_t
typedef char __int8_t;
typedef short __int16_t;
typedef int __int32_t;
typedef long __int64_t;

// misc
typedef long long __ssize_t;

// --- end of hardcoded typedefs ---
'''
# NOTE: bring these back if needed...
# // misc
# // typedef unsigned long long size_t;
# typedef long ssize_t;
# typedef long time_t;
# typedef long __time_t;
# typedef long __fd_mask;
# typedef long __suseconds_t;
# typedef void* __timezone_ptr_t;
# typedef void* __destr_function;
# typedef long mode_t;
# typedef int GLFWbool;
# typedef float* vec2;

KNOWN_LIB_FUNCS = [
    'fseek', 'fclose', 'ftell', 'malloc', 'fopen', 'calloc', 'free', 'fread',
    'memcpy', 'memset', 'sqrtf', 'printf', 'snprintf', 'fwrite', 'strlen',
    'strcmp', 'sin', 'cos', 'realloc', 'fmod', 'strchr', 'pow', 'strncmp',
    'memcmp', 'ldexp', 'log', 'floor', 'exp', 'fprintf', 'fmax', 'fmin',
    'vfprintf', 'sprintf', 'cosf', 'sinf', 'fmodf', 'expf',
]

def get_analyze_headless_path_dev(ghidra_root:Path, windows=True):
    return ghidra_root/'Ghidra'/'RuntimeScripts'/'Windows'/'support'/'analyzeHeadless.bat'

def clang_dump_ast(clang_exe:Path, cfile:Path, out_json:Path):
    # clang -Xclang -ast-dump=json -fsyntax-only C_FILE > out.json
    return subprocess.call([clang_exe, '-Xclang', '-ast-dump=json', '-fsyntax-only',
        '-Wno-pointer-to-int-cast', '-Wno-int-to-pointer-cast',
        '-Wno-int-conversion',
        '-Wno-return-stack-address',
        '-Wno-return-type',
        '-Wno-shift-count-overflow',
        '-Wno-constant-conversion',
        '-Wno-shift-op-parentheses',
        '-Wno-qualified-void-return-type',
        '-Wno-incompatible-pointer-types',
        '-Wno-fortify-source',
        '-Wno-compare-distinct-pointer-types',
        '-Wno-pointer-sign',
        cfile, '>', out_json], shell=True)

def diff_ast_sets(clang_ast_files:List[Path], exportfolder:Path, clang_rcodes:Dict) -> List:
    '''
    Diff each clang AST file (from Ghidra decompiled C -> clang -ast-dump=json -> AST.json)
    with its corresponding Ghidra AST file (as exported by my mods to Ghidra)
    using the diff_asts.py script I already created
    '''
    # CLS: now this is "installed" - just call it
    # DIFF_AST_SCRIPT = Path.home()/'dev'/'phd'/'research'/'ast-models'/'diff_asts.py'

    validation_results = []

    for clang_ast in clang_ast_files:
        # find match
        ghidra_ast = exportfolder/clang_ast.name
        if not ghidra_ast.exists():
            print(f'Error: No matching Ghidra AST found for {clang_ast}')
            continue

        clang_rcode = clang_rcodes[clang_ast.stem] if clang_ast.stem in clang_rcodes else -1
        rcode = subprocess.call(['diff_asts', ghidra_ast, clang_ast])
        # if clang_rcode == 0:
        #     rcode = subprocess.call(['diff_asts', ghidra_ast, clang_ast])
        # else:
        #     rcode = 13  # use bcompare fail...right now its showing up as "Pass" when clang failed
        validation_results.append((clang_ast.stem, clang_rcode, rcode))

    return validation_results

def print_nonempty_folder_warning(exportfolder:Path, console:Console):
    msg = f'\nExport folder {exportfolder} is nonempty!'
    msg += '\n\nANY "EXTRA" JSON FILES THAT ALREADY EXIST WILL BE INCLUDED IN VALIDATION RESULTS'
    msg += '\n\n'
    console.print(msg, style='bold gold1')
    import time
    time.sleep(1.5)

def rename_known_library_funcs(cfile:Path, lib_funcs:List[str]=KNOWN_LIB_FUNCS):
    '''
    Renames each builtin library function contained in the lib_funcs to
    <original_name>_SUFFIX to make them not collide with builtin library functions
    when running through "clang -ast-dump"
    '''
    regex = re.compile('|'.join(rf'\b{re.escape(w)}\b' for w in lib_funcs))
    def do_replace(match):
        return f'{match.group(0)}_SUFFIX'

    f_renamed = ''
    with open(cfile, 'r') as f:
        f_renamed = regex.sub(do_replace, f.read())
    with open(cfile, 'w') as f:
        f.write(f_renamed)

def run_validation(args):
    analyze_headless_path = get_analyze_headless_path_dev(Path.home()/'dev'/'ghidra')
    proj_location = Path.home()/'ghidra_projects'
    proj_name = 'default'

    ghidra_decompile_script = astlib.decompile_all_script()
    clang_exe = Path.home()/'software'/'LLVM'/'bin'/'clang.exe'

    exportfolder = config.get_ast_exportfolder()
    ghidracode_folder = exportfolder/'GhidraCode'

    warn_nonempty_folder = list(exportfolder.glob('*.json'))

    clang_rcodes = {}
    console = Console()

    if not args.only_diff:
        if warn_nonempty_folder:
            print_nonempty_folder_warning(exportfolder, console)

        # perform full export and validation from scratch if --only-diff
        # was not specified
        script_args = ['VALIDATE']
        if args.subset_file:
            ssf = Path(args.subset_file)
            if not ssf.exists():
                print(f'Subset file {ssf} does not exist')
                exit(1)
            script_args.append(ssf)
        elif args.exclude_file:
            ef = Path(args.exclude_file)
            if not ef.exists():
                print(f'Exclude file {ef} does not exist')
                exit(1)
            script_args.extend(['X', ef])

        rcode = subprocess.call([
            analyze_headless_path, proj_location, proj_name,
            '-scriptPath', ghidra_decompile_script.parent,
            '-postScript', ghidra_decompile_script.name, *script_args,
            '-process', args.program_name, '-noanalysis'
        ])

        if rcode != 0:
            print(f'Ghidra analyzeHeadless returned {rcode}')
            exit(rcode)

        # ---------------------------------------------------------------
        # rename known library functions by adding an arbitrary suffix
        # - for validation only, avoids bad Ghidra prototype for a known function
        #   which was causing compiler warnings/errors
        # - names still match because mod is consistent
        for ast_json in list(exportfolder.glob('*.json')):
            pass

        # ---------------------------------------------------------------
        # "paste" headers into Ghidra .c files at top
        ghidra_c_files = list(ghidracode_folder.glob('*.c'))
        for ghidra_c in ghidra_c_files:
            ast_export = (exportfolder/ghidra_c.name).with_suffix('.json')
            header_code = convert_astfile_to_code(ast_export, header_only=True, validation_mode=True)
            with open(ghidra_c, 'r') as f:
                body_code = f.read()
            with open(ghidra_c, 'w') as f:
                f.write(GHIDRA_VALIDATION_TYPEDEF_STR)
                f.write(f'{header_code}\n// ---------------- END OF AST HEADER\n\n')
                f.write(body_code)

            rename_known_library_funcs(ghidra_c)

            # raise Exception('Update func pointer fwd decls')
            # TODO: look for the fptr pattern and update the fwd decl for that variable
            # * CallExpr
            # *  - ParenExpr
            # *      - UnaryOperator *
            # *          - DeclRefExpr DAT_CORRECT

        # from ghidra_arch.cc:
        # TODO: hardcode a "boilerplate" typedef set that we use??
        # well, if I do that I need to have the JSON-equivalent boilerplate ready to go
        # to stick it inside the Ghidra AST export
        # - only need "weird Ghidra types", not ones actually valid in C
        # NOTE: if there is any automated way to walk the final AST and
        #       generate typedefs for all referenced data types that aren't "built-in"
        #       then I can spit that out BOTH in the AST json and in the forward decls
        #       .h file
        #       >> this would also produce AST exports from my tool that actually compile,
        #          which is a nice side-effect (although possibly not required?)
        #       >> if/when structures are ALREADY used in the code, my model might
        #          require their definitions...just a thought
        # ----
        # types->setCoreType("void",1,TYPE_VOID,false);
        # types->setCoreType("bool",1,TYPE_BOOL,false);
        # types->setCoreType("byte",1,TYPE_UINT,false);
        # types->setCoreType("word",2,TYPE_UINT,false);
        # types->setCoreType("dword",4,TYPE_UINT,false);
        # types->setCoreType("qword",8,TYPE_UINT,false);
        # types->setCoreType("char",1,TYPE_INT,true);
        # types->setCoreType("sbyte",1,TYPE_INT,false);
        # types->setCoreType("sword",2,TYPE_INT,false);
        # types->setCoreType("sdword",4,TYPE_INT,false);
        # types->setCoreType("sqword",8,TYPE_INT,false);
        # types->setCoreType("float",4,TYPE_FLOAT,false);
        # types->setCoreType("float8",8,TYPE_FLOAT,false);
        # types->setCoreType("float16",16,TYPE_FLOAT,false);
        # types->setCoreType("undefined",1,TYPE_UNKNOWN,false);
        # types->setCoreType("undefined2",2,TYPE_UNKNOWN,false);
        # types->setCoreType("undefined4",4,TYPE_UNKNOWN,false);
        # types->setCoreType("undefined8",8,TYPE_UNKNOWN,false);
        # types->setCoreType("code",1,TYPE_CODE,false);
        # types->setCoreType("wchar",2,TYPE_INT,true);

        # call clang on each Ghidra .c file to dump ast JSON
        for cfile in ghidra_c_files:
            outfile = cfile.with_suffix('.json')
            rcode = clang_dump_ast(clang_exe, cfile, outfile)
            clang_rcodes[outfile.stem] = rcode
            if rcode != 0:
                print(f'Clang dump failed with code {rcode} on file {cfile.name}')

    # call validation script
    clang_ast_files = list(ghidracode_folder.glob('*.json'))
    validation_results = diff_ast_sets(clang_ast_files, exportfolder, clang_rcodes)

    # important bcompare codes:
    # -------------------------
    # 0 - success (haven't seen this yet)
    # 1 - binary same << this is a PASS
    # 2 - rule-based same
    # 13 - rule-based difference

    bcomp_rcodes = {
        0: "Pass",
        1: "Pass",
        2: "Rule-based pass",
        13: "Fail"
    }

    # generate a report and pretty-print using rich
    df = pd.DataFrame(validation_results, columns=['Function', 'Clang AST Dump', 'Result'])
    df['Result'] = df.Result.map(bcomp_rcodes).fillna(df.Result)
    df['Clang AST Dump'] = df['Clang AST Dump'].map({
            -1: 'N/A',
            0: 'Compiles',
            1: 'Fails'
        }).fillna(df['Clang AST Dump'])

    # TODO: add a --filter-compile-fails flag (or something) and if it's set, right here
    # we can filter out rows where Clang AST Dump == Fails (filter out rows failing to "compile" through clang)

    # show totals
    totals_df = df.groupby('Result').count().reset_index().drop(columns=['Clang AST Dump'])
    totals_df.columns = ['Result','Functions']
    totals_df.sort_values('Functions',ascending=False)
    totals_df.loc[totals_df.index.max()+1] = ['Total', len(df)]
    totals_df['Percent'] = totals_df.Functions/len(df)*100

    fail_row_idx = totals_df.index[totals_df.Result=='Fail'][0] if 'Fail' in totals_df.Result.values else 1000
    pass_row_idx = totals_df.index[totals_df.Result=='Pass'][0] if 'Pass' in totals_df.Result.values else 1000

    table = df_to_richtable(totals_df, f'AST Validation Results',
        # title_style='yellow',
        # header_style='yellow',
        row_idx_to_style={
            fail_row_idx: 'red',
            pass_row_idx: 'green'
        })
    table.columns[1].justify = 'right'
    table.columns[2].justify = 'right'

    print()
    console.print(table)

    # show first N failures
    NUM_FAILS = 50
    first_fails = df[df.Result=='Fail'][:NUM_FAILS]
    first_fails.sort_values('Function')

    # dodger_blue1 is a good color for something else...
    table = df_to_richtable(first_fails, f'First {len(first_fails)} Failures',
        # rowstyle='bright_black', header_style='orange_red1'
        rowstyle='orange_red1'
    )

    if len(first_fails):
        print()
        console.print(table)

    if not args.only_diff:
        if warn_nonempty_folder:
            print_nonempty_folder_warning(exportfolder, console)

    # import IPython; IPython.embed()

def main():
    p = argparse.ArgumentParser(description='''Run validation of Ghidra AST export.
    This is done by:

        1) auto-decompiling all non-thunk functions in the program
        2) exporting their AST json files
        3) running clang --ast-dump=json on the (fixed) C output of Ghidra and
        4) comparing the two json files for a basic structural match

    The file formats are significantly different, so the files are minified to a bare structural representation
    before they are compared. Thus not every field is validated, just the basic AST structure''')

    p.add_argument('program_name', help='Name of the binary program to use for validation (pre-imported in Ghidra project ~/ghidra_projects/default)')
    p.add_argument('--subset-file', action='store',
        help='File that specifies a subset of functions to validate by supplying a single function name per line')
    p.add_argument('--exclude-file', action='store',
        help='File that specifies a subset of functions to exclude. If --subset-file is used, this option is ignored')
    p.add_argument('--only-diff', action='store_true',
        help="Don't re-export from Ghidra, just diff existing files and report totals")
    args = p.parse_args()
    exit(run_validation(args))

if __name__ == '__main__':
    main()
