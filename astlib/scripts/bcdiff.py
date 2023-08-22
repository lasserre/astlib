import argparse
import subprocess

from .. import config

# CLS: this is just a convenience script for me to manually check failures
# very quickly...I don't expect this has much long-term use

def bcdiff(args):
    validation_folder = config.get_ast_exportfolder()/'validation'
    ghidra_reduced_filename = validation_folder/f'{args.function_name}.json.GHIDRA_REDUCED.json'
    clang_reduced_filename = validation_folder/f'{args.function_name}.json.CLANG_REDUCED.json'

    if not ghidra_reduced_filename.exists():
        print(f'Exported AST file (reduced) does not exist: {ghidra_reduced_filename}')
    if not clang_reduced_filename.exists():
        print(f'Exported Ghidra code -> Clang JSON file (reduced) does not exist: {clang_reduced_filename}')

    subprocess.run(['bcompare.exe', ghidra_reduced_filename, clang_reduced_filename])

def main():
    p = argparse.ArgumentParser(description='Helper script to quickly diff a function in export folder')
    p.add_argument('function_name', help='Name of the function. Will be converted to proper files in the export folder')
    args = p.parse_args()
    exit(bcdiff(args))

if __name__ == '__main__':
    main()