import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

import ghidra
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.database import ProgramDB

def get_decompiler_interface(program:ProgramDB, options:DecompileOptions=None) -> DecompInterface:
    if not options:
        options = DecompileOptions()

    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(program)
    return ifc
