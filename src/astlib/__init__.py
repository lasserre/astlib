from .ast import *
from .astvisitor import *
from .ghidra_scripts import *
from . import color_ast
from .find_all_references import *

from pathlib import Path

def ghidra_script_folder() -> Path:
    return (Path(__file__).parent/'ghidra_scripts').resolve()

def decompile_all_script() -> Path:
    return ghidra_script_folder()/'ghidra_decompile_all.py'
