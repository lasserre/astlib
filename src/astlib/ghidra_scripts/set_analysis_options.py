#Set analysis options
#@author Caleb Stewart
#@category phd
#@keybinding
#@menupath
#@toolbar

# this try/except construction makes intellisense nice with ghidra type stubs
# installed :)
# https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator

import ghidra
try:
    from ghidra.ghidra_builtins import *
except:
    pass

dwarf_debug_item_limit = int(1e9)   # 1 billion - effectively no limit :)

setAnalysisOption(currentProgram, 'DWARF.Debug Item Limit', str(dwarf_debug_item_limit))
print('Set DWARF.Debug Item Limit to {:,}'.format(dwarf_debug_item_limit))
